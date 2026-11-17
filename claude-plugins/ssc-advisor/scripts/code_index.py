"""A structural index of a project's Python code, built with the standard library's ast module (the code is parsed,
never run or imported). It answers one question for the relevance check: can anything that starts the program reach
a call of the function an advisory names, and along which path?

What it records, per project:
  - every function, method and class (module.func, module.Class.method), with its file and lines;
  - edges between them: a call, a reference (a function passed as a callback, a class named in a URL table), an
    import of a project module (importing runs the module's top-level code), a dotted name in a string
    ("clinic.urls", "app.tasks:run": settings and config name code this way), and a nested function its parent defines;
  - calls of code outside the project (yaml.load, requests.get), with the code of the call;
  - entry points: what starts the program. Modules a run command names (Dockerfile CMD, Procfile, fly.toml, compose,
    pyproject scripts), modules with `if __name__ == "__main__"`, the usual start files (manage.py, wsgi.py, app.py,
    main.py, ...), and functions a framework calls through a decorator (@app.post, @router.get, @shared_task, ...);
  - places the code calls things by a name it computes (getattr, importlib, eval), where a path may be missed.

When a call's receiver is unknown (obj.save()), it is linked to every project method of that name: the index rather
says "reachable" by mistake than "not reachable". Tests are never entry points (they don't ship).
"""

import ast
import re
from collections import deque
from pathlib import Path

import ssc_scope

LIMIT = 400_000
ENTRY_FILES = {"manage.py", "wsgi.py", "asgi.py", "app.py", "main.py", "server.py", "__main__.py", "run.py", "cli.py"}
# decorators through which a framework calls a function: routes, tasks, CLI commands, event handlers
FRAMEWORK_DECORATOR = re.compile(
    r"(^|\.)(route|get|post|put|patch|delete|head|options|websocket|api_route|api_view|action|task|shared_task|"
    r"periodic_task|command|group|callback|on_event|middleware|exception_handler|receiver|job|handler|subscribe|"
    r"listener|endpoint|before_request|after_request|errorhandler|on_message|hookimpl|scheduled_job)$"
)
RUN_FILES = ("Dockerfile", "Procfile", "fly.toml", "docker-compose", "compose", "pyproject.toml", "setup.cfg")
RUN_COMMANDS = [
    re.compile(r"\bpython[\d.]*\s+(?:-[A-Za-z]+\s+)*-m\s+([\w.]+)"),
    re.compile(r"\bpython[\d.]*\s+(?:-[A-Za-z]+\s+)*([\w./-]+\.py)\b"),
    re.compile(r"\b(?:gunicorn|uvicorn|hypercorn|daphne|waitress-serve|granian)\b[^\n]*?\b([\w.]+):[\w()]+"),
    re.compile(r"\bcelery\s+(?:-A|--app)[ =]([\w.]+)"),
    re.compile(r"""^\s*[\w.-]+\s*=\s*["']([\w.]+):[\w.]+["']""", re.M),  # pyproject [project.scripts]
]
WEB_DECORATOR = re.compile(
    r"(^|\.)(route|get|post|put|patch|delete|head|options|websocket|api_route|api_view|action|endpoint|"
    r"before_request|after_request|errorhandler|exception_handler|middleware)$"
)
JOB_DECORATOR = re.compile(r"(^|\.)(task|shared_task|periodic_task|job|scheduled_job|subscribe|on_message|receiver|"
                           r"listener|handler|on_event|callback|hookimpl)$")  # fmt: skip
RUN_KINDS = ["program", "program", "web server", "background worker", "command line"]  # one per RUN_COMMANDS entry
# login, permission and token checks a framework applies to a function, a class or a whole app
AUTH = re.compile(
    r"login_required|permission_required|user_passes_test|staff_member_required|requires?_(auth|login|user|role|"
    r"permission|scope)|jwt_required|auth_required|token_required|is_authenticated|IsAuthenticated|IsAdmin|"
    r"permission_classes|authentication_classes|Security\(|Depends\([^)]*(auth|user|token|current|verify|"
    r"permission|api_key|session)|HTTPBearer|OAuth2|APIKey|LoginRequiredMiddleware|DEFAULT_PERMISSION_CLASSES|"
    r"DEFAULT_AUTHENTICATION_CLASSES|basic_auth|verify_token|check_auth",
    re.I,
)
DOTTED = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+(?::[A-Za-z_]\w*)?$")
MAX_CALLS = 8


def _module_name(rel):
    parts = rel[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or "__init__"


def _decorator_name(d):
    d = d.func if isinstance(d, ast.Call) else d
    try:
        return ast.unparse(d)
    except Exception:
        return ""


def _chain(node):
    """['a', 'b', 'c'] for a.b.c; None when the base isn't a plain name (f().x, x[0].y)."""
    out = []
    while isinstance(node, ast.Attribute):
        out.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        return [node.id, *reversed(out)]
    return None


class Index:
    def __init__(self, project, files, is_test=lambda rel: False):
        self.project = Path(project)
        self.is_test = is_test
        self.fns = {}  # qualname -> {file, line, end, kind}
        self.edges = {}  # qualname -> {qualname: (line, how)}
        self.external = []  # {caller, name, file, line, code}
        self.entries = {}  # qualname -> why it is an entry point
        self.dynamic = []  # file:line of getattr/importlib/eval calls
        self.modules = {}  # module name -> rel path
        self.imports = {}  # module -> {local name: dotted target}
        self.top = {}  # module -> {top-level name: qualname}
        self.by_name = {}  # method name -> [qualnames]
        self.instances = {}  # module -> top-level names bound to an outside object (app = Flask(__name__))
        self.nodes = {}  # qualname -> its ast node (functions and classes)
        self.entry_kind = {}  # qualname -> web route, background job, command line, web server, program, ...
        self.trees = {}
        self.errors = []
        for f in files:
            rel = f.relative_to(self.project).as_posix() if f.is_absolute() else f.as_posix()
            if not rel.endswith(".py"):
                continue
            try:
                self.trees[rel] = ast.parse(ssc_scope.read_text(f, LIMIT), filename=rel)
            except (SyntaxError, ValueError):
                self.errors.append(rel)
                continue
            self.modules[_module_name(rel)] = rel
        # a module is also known by the end of its dotted name (src/app/x.py is imported as app.x), but a single
        # name only for a package or a module at the top: app/utils/json.py must not hide the json library
        self._suffix = {}
        for mod in sorted(self.modules, key=len):
            parts = mod.split(".")
            is_pkg = self.modules[mod].endswith("__init__.py")
            for i in range(len(parts)):
                if i < len(parts) - 1 or is_pkg or len(parts) == 1 or parts[0] == "src":
                    self._suffix.setdefault(".".join(parts[i:]), mod)
        for rel, tree in self.trees.items():
            self._declare(_module_name(rel), rel, tree)
        for rel, tree in self.trees.items():
            self._link(_module_name(rel), rel, tree)
        self._entry_points(files)

    # ------------------------------------------------------------ pass 1: what exists
    def _add_fn(self, qual, rel, node, kind):
        self.fns[qual] = {"file": rel, "line": getattr(node, "lineno", 1), "end": getattr(node, "end_lineno", 1),
                          "kind": kind}  # fmt: skip

    def _declare(self, mod, rel, tree):
        self._add_fn(mod, rel, tree, "module")
        imports, top = {}, {}
        self.imports[mod], self.top[mod] = imports, top
        is_pkg = rel.endswith("__init__.py")
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        imports[a.asname] = a.name
                    else:
                        imports[a.name.split(".")[0]] = a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    pkg = mod.split(".") if is_pkg else mod.split(".")[:-1]
                    pkg = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
                    base = ".".join([*pkg, *([node.module] if node.module else [])])
                for a in node.names:
                    if a.name != "*":
                        imports[a.asname or a.name] = f"{base}.{a.name}" if base else a.name

        def walk(body, owner, cls):
            for node in body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    qual = f"{owner}.{node.name}"
                    is_class = isinstance(node, ast.ClassDef)
                    self._add_fn(qual, rel, node, "class" if is_class else "method" if cls else "function")
                    self.nodes[qual] = node
                    if owner == mod:
                        top[node.name] = qual
                    if cls and not is_class:
                        self.by_name.setdefault(node.name, []).append(qual)
                    if not is_class and not self.is_test(rel):
                        for d in node.decorator_list:
                            name = _decorator_name(d)
                            if FRAMEWORK_DECORATOR.search(name):
                                self.entries.setdefault(qual, f"@{ast.unparse(d)[:80]}")
                                self.entry_kind.setdefault(qual, "web route" if WEB_DECORATOR.search(name)
                                                           else "background job or event" if JOB_DECORATOR.search(name)
                                                           else "command line")  # fmt: skip
                    walk(node.body, qual, qual if is_class else None)
                else:
                    for field in ("body", "orelse", "finalbody", "handlers"):
                        sub = getattr(node, field, None)
                        if isinstance(sub, list):
                            walk(sub, owner, cls)

        walk(tree.body, mod, None)
        outside = self.instances.setdefault(mod, set())
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
                chain = _chain(node.value.func)
                if chain and chain[0] in imports and not self._module(imports[chain[0]].split(".")[0]):
                    for t in node.targets if isinstance(node, ast.Assign) else [node.target]:
                        if isinstance(t, ast.Name):
                            outside.add(t.id)

    # ------------------------------------------------------------ resolving names
    def _module(self, dotted):
        return (self.modules.get(dotted) and dotted) or self._suffix.get(dotted)

    def internal(self, dotted, depth=0):
        """The project qualname a dotted name means (a module, function, class or method), or None."""
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            mod = self._module(".".join(parts[:i]))
            if not mod:
                continue
            rest = parts[i:]
            if not rest:
                return mod
            for j in range(len(rest), 0, -1):  # Upload.as_view: a method the class inherits -> the class
                qual = f"{mod}.{'.'.join(rest[:j])}"
                if qual in self.fns:
                    return qual
            if depth < 3 and rest[0] in self.imports.get(mod, {}):  # re-exported: from .views import upload
                return self.internal(".".join([self.imports[mod][rest[0]], *rest[1:]]), depth + 1)
            return None
        return None

    def _resolve(self, mod, cls, chain):
        """-> (project qualname or None, dotted name outside the project or None, method name to match by name)."""
        base, attrs = chain[0], chain[1:]
        if base in ("self", "cls") and cls and attrs:
            qual = f"{cls}.{attrs[0]}"
            return (qual if qual in self.fns else None), None, (None if qual in self.fns else attrs[0])
        if base in self.instances.get(mod, ()):
            return None, None, None  # a method of an outside object: app.post(...), router.get(...)
        if base in self.top.get(mod, {}):
            qual = self.internal(".".join([self.top[mod][base], *attrs]))
            return qual, None, (None if qual else attrs[-1] if attrs else None)
        if base not in self.imports.get(mod, {}):
            return None, None, (attrs[-1] if attrs else None)  # a local variable, a parameter, a builtin
        dotted = ".".join([self.imports[mod][base], *attrs])
        qual = self.internal(dotted)
        if qual:
            return qual, None, None
        if self._module(dotted.split(".")[0]):
            return None, None, (attrs[-1] if attrs else None)  # something of ours we can't pin down
        return None, dotted, None

    # ------------------------------------------------------------ pass 2: edges
    def _edge(self, src, dst, line, how):
        if dst and dst != src:
            self.edges.setdefault(src, {}).setdefault(dst, (line, how))

    def _link(self, mod, rel, tree):
        for node in ast.walk(tree):  # importing a project module runs its top-level code
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                targets = [a.name for a in node.names] if isinstance(node, ast.Import) else []
                if isinstance(node, ast.ImportFrom):
                    for local, dotted in self.imports[mod].items():
                        if any(a.name == local or a.asname == local for a in node.names):
                            targets.append(dotted)
                for t in targets:
                    q = self.internal(t)
                    target_mod = q and self.fns[q]["file"]
                    if target_mod:
                        self._edge(mod, _module_name(target_mod), node.lineno, "import")
        self._scan(mod, rel, tree.body, mod, None)

    def _scan(self, mod, rel, body, owner, cls):
        """Edges and outside calls from the code that runs as `owner` (nested defs are their own owners)."""
        stack = list(body)
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qual = f"{owner}.{node.name}"
                is_class = isinstance(node, ast.ClassDef)
                if is_class:
                    for d in node.bases + node.decorator_list:
                        stack.append(d)
                    for sub in node.body:
                        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self._edge(qual, f"{qual}.{sub.name}", sub.lineno, "method")
                    self._scan(mod, rel, node.body, qual, qual)
                else:
                    if owner != mod and not (cls and owner == cls):
                        self._edge(owner, qual, node.lineno, "defines")  # a nested function its parent uses
                    stack.extend(node.decorator_list)
                    stack.extend(d for d in node.args.defaults + node.args.kw_defaults if d is not None)
                    self._scan(mod, rel, node.body, qual, cls)
                continue
            if isinstance(node, ast.Call):
                self._call(mod, rel, node, owner, cls)
            elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(getattr(node, "ctx", None), ast.Load):
                chain = _chain(node)
                if chain:
                    qual, outside, _ = self._resolve(mod, cls, chain)
                    self._edge(owner, qual, node.lineno, "reference")
                    if outside:
                        self._outside(owner, rel, node, outside)
                    if isinstance(node, ast.Attribute):
                        continue  # its parts are covered by the chain
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and DOTTED.match(node.value):
                self._edge(owner, self.internal(node.value.replace(":", ".")), node.lineno, "named in a string")
            stack.extend(ast.iter_child_nodes(node))

    def _call(self, mod, rel, node, owner, cls):
        chain = _chain(node.func)
        name = chain and ".".join(chain)
        if name in ("getattr", "__import__", "eval", "exec", "importlib.import_module", "import_module"):
            self.dynamic.append(f"{rel}:{node.lineno}")
        if not chain:
            return
        qual, outside, method = self._resolve(mod, cls, chain)
        if qual:
            self._edge(owner, qual, node.lineno, "call")
            if self.fns[qual]["kind"] == "class" and f"{qual}.__init__" in self.fns:
                self._edge(owner, f"{qual}.__init__", node.lineno, "call")
        elif outside:
            self._outside(owner, rel, node, outside)
        elif method:
            for q in self.by_name.get(method, [])[:20]:
                self._edge(owner, q, node.lineno, "call by method name")

    def _outside(self, owner, rel, node, dotted):
        try:
            code = ast.unparse(node)
        except Exception:
            code = dotted
        self.external.append({"caller": owner, "name": dotted, "file": rel, "line": node.lineno,
                              "code": code[:160]})  # fmt: skip

    # ------------------------------------------------------------ entry points
    def _entry_points(self, files):
        for mod, rel in self.modules.items():
            if self.is_test(rel):
                continue
            tree = self.trees[rel]
            if Path(rel).name in ENTRY_FILES and rel.count("/") <= 2:
                self.entries.setdefault(mod, f"{rel} (a usual start file)")
                self.entry_kind.setdefault(mod, "start file")
            for node in tree.body:
                if (
                    isinstance(node, ast.If)
                    and "__name__" in ast.unparse(node.test)
                    and "__main__" in ast.unparse(node.test)
                ):
                    self.entries.setdefault(mod, f"{rel}:{node.lineno} (if __name__ == '__main__')")
                    self.entry_kind.setdefault(mod, "script")
        for f in files:
            if not f.name.startswith(RUN_FILES):
                continue
            rel = f.relative_to(self.project).as_posix() if f.is_absolute() else f.as_posix()
            text = ssc_scope.read_text(f, LIMIT)
            for rx, kind in zip(RUN_COMMANDS, RUN_KINDS):
                for m in rx.finditer(text):
                    target = m.group(1)
                    target = _module_name(target) if target.endswith(".py") else target
                    qual = self.internal(target.replace("/", "."))
                    if qual and not self.is_test(self.fns[qual]["file"]):
                        line = text.count("\n", 0, m.start()) + 1
                        self.entries.setdefault(qual, f"{rel}:{line} (run command)")
                        self.entry_kind[qual] = kind  # what the run command says beats a guess from the name

    # ------------------------------------------------------------ questions
    def where(self, qual):
        f = self.fns.get(qual)
        return f"{f['file']}:{f['line']}" if f else "?"

    def reach(self):
        """{qualname: parent qualname} for everything reachable from an entry point (entries map to None). Exact
        links are followed first; a call matched only by its method name is used only for what they don't reach."""
        parent = {q: None for q in self.entries}
        for loose in (False, True):
            todo = deque(parent)
            while todo:
                q = todo.popleft()
                for nxt, (_, how) in self.edges.get(q, {}).items():
                    if nxt not in parent and (loose or how != "call by method name"):
                        parent[nxt] = q
                        todo.append(nxt)
        return parent

    def path(self, parent, qual):
        out = []
        while qual is not None:
            out.append(qual)
            qual = parent.get(qual)
        return list(reversed(out))

    def uses(self, modules, symbols=()):
        """Calls of a package's code (its import names in `modules`), or only of the named functions in `symbols`,
        each with whether an entry point reaches it and along which path."""
        mods = {ssc_scope.norm(m) for m in modules}
        lasts = {s.split(".")[-1] for s in symbols}

        def matches(name):
            if ssc_scope.norm(name.split(".")[0]) not in mods:
                return False
            return not symbols or name.split(".")[-1] in lasts

        parent = self.reach()
        found, seen = [], set()
        for c in self.external:
            if not matches(c["name"]) or (c["file"], c["line"], c["name"]) in seen:
                continue
            seen.add((c["file"], c["line"], c["name"]))
            hops = self.path(parent, c["caller"]) if c["caller"] in parent else []
            where = f"{c['caller']} ({self.where(c['caller'])})"
            one = {"call": f"{c['file']}:{c['line']}", "code": c["code"], "in": where, "reachable": bool(hops)}
            if hops:
                one["entry"] = self.entries.get(hops[0])
                one["entry_kind"] = self.entry_kind.get(hops[0], "entry point")
                guards = [g for q in hops for g in self.guards(q)]
                one["checks_on_path"] = guards[:6] or "no login or permission check found on the path"
                one["path"] = [f"{q} ({self.where(q)})" + self._how(hops, i) for i, q in enumerate(hops)]
            elif self.is_test(c["file"]):
                one["note"] = "in a test file"
            found.append(one)
        found.sort(key=lambda x: not x["reachable"])
        return found[:MAX_CALLS]

    def guards(self, qual):
        """Login, permission or token checks on a function: its decorators and parameter defaults (FastAPI
        Depends), and for a method its class's decorators and class attributes (permission_classes)."""
        node = self.nodes.get(qual)
        if node is None:
            return []
        found = []
        parts = list(getattr(node, "decorator_list", []))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parts += [d for d in node.args.defaults + node.args.kw_defaults if d is not None]
        owner = self.nodes.get(qual.rsplit(".", 1)[0])
        if isinstance(owner, ast.ClassDef):
            parts += owner.decorator_list + [b for b in owner.body if isinstance(b, (ast.Assign, ast.AnnAssign))]
            parts += owner.bases
        for p in parts:
            text = ast.unparse(p)
            if AUTH.search(text):
                found.append(f"{self.fns[qual]['file']}:{p.lineno} {text[:80]}")
        return found

    def app_wide_checks(self):
        """Checks set for a whole app at module level: DEFAULT_PERMISSION_CLASSES, FastAPI(dependencies=[...]),
        auth middleware lists, before_request hooks that check a login."""
        out = []
        for rel, tree in self.trees.items():
            if self.is_test(rel):
                continue
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    deco = " ".join(_decorator_name(d) for d in node.decorator_list)
                    if ("before_request" in deco or "middleware" in deco) and AUTH.search(ast.unparse(node)):
                        out.append(f"{rel}:{node.lineno} {deco} {node.name}")
                elif not isinstance(node, (ast.ClassDef, ast.Import, ast.ImportFrom)):
                    text = ast.unparse(node)
                    m = AUTH.search(text)
                    if m:
                        out.append(f"{rel}:{node.lineno} {m.group(0)}")
        return out[:6]

    def _how(self, hops, i):
        if i == 0:
            return ""
        how = self.edges[hops[i - 1]][hops[i]][1]
        return "" if how == "call" else f" [{how}]"

    def confirm(self, hops):
        """Check a path someone claims, hop by hop: each must be a project function or module that the previous hop
        calls, references or imports; the last may be an outside name (yaml.load) the previous hop calls."""
        missing = []
        for a, b in zip(hops, hops[1:]):
            qa = self.internal(a) if a not in self.fns else a
            qb = self.internal(b) if b not in self.fns else b
            if qa is None:
                missing.append(f"{a}: not a function or module of this project")
            elif qb is not None:
                if qb not in self.edges.get(qa, {}):
                    missing.append(f"{a} -> {b}: {a} doesn't call, reference or import {b}")
            elif not any(c["caller"] == qa and (c["name"] == b or c["name"].endswith("." + b.split(".")[-1]))
                         for c in self.external):  # fmt: skip
                missing.append(f"{a} -> {b}: {a} doesn't call {b}")
        first = hops[0] if hops else None
        q0 = first if first in self.fns else (self.internal(first) if first else None)
        reached = q0 in self.reach() if q0 else False
        return {"ok": not missing, "missing": missing, "starts_at_entry_point": q0 in self.entries,
                "first_hop_reachable": reached}  # fmt: skip

    def summary(self):
        return {
            "python_files": len(self.trees),
            "entry_points": [f"{q} ({why})" for q, why in list(self.entries.items())[:12]],
            "app_wide_checks": self.app_wide_checks() or "none found",
            "computed_calls": sorted(self.dynamic, key=lambda w: (w.rsplit(":", 1)[0], int(w.rsplit(":", 1)[1])))[:5],
            **({"unparsable": self.errors[:5]} if self.errors else {}),
        }
