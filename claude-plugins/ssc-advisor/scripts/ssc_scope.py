"""Build a folder's scan request for the advisory API, without the ssc app: the same output as the app's
`ssc scope PATH` (scanner/src/scan.rs; tests/test_plugin_scope.py compares the two).

It reads files only: nothing in the projects is installed or run (git is asked, read-only, whether a file with a
secret is tracked). What it collects: packages with the file, line and line text they came from, vendors, Docker base
images, CA certificates, internal package names, and secrets as facts only (kind, file, line, whether it looks like an
example). Secret values are never kept, printed or sent. Standard library only.

The detection rules come from the server (`GET /v1/scanner-rules`), with a built-in copy (scanner_rules.json) as the
fallback.
"""

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILTIN_RULES = HERE / "scanner_rules.json"

# Lockfiles reported per project (the server flags a project without one).
LOCKFILES = {
    "uv.lock",
    "requirements.lock",
    "poetry.lock",
    "pdm.lock",
    "Pipfile.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
}
TYPES = ["platform", "ci", "developer_tool", "ai_provider", "saas", "package_registry", "other"]
MAX_SECRET_FILE = 2 * 1024 * 1024


# ---------------------------------------------------------------- files and text
def read_text(path, limit=None):
    """A regular file as text (invalid UTF-8 dropped, universal newlines), at most `limit` characters."""
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read(limit) if limit else f.read()
    except OSError:
        return ""


def lines(text):
    """Lines split at "\\n" or "\\r\\n" (Rust's str::lines)."""
    parts = text.split("\n")
    last = parts.pop()  # after the final "\n": "" when the text ends with one
    out = [p.removesuffix("\r") for p in parts]
    return [*out, last] if last else out


def walk(root, keep_dir):
    """Every file under root, top-down: a folder's files, then its subfolders (os.walk order; links to folders are
    not entered)."""
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if keep_dir(x)]
        out.extend(Path(d) / f for f in files)
    return out


def listdir(d):
    try:
        with os.scandir(d) as it:
            return [(e.name, e.is_dir()) for e in it]
    except OSError:
        return []


def relpath(path, base):
    try:
        return Path(path).relative_to(base).as_posix()
    except ValueError:
        return str(path)


def path_key(p):
    return Path(p).parts


def glob_any(root, pattern):
    """The few glob patterns the rules use ("railway.json", ".github/workflows/*.y*ml"): `*` never matches a name
    starting with "."."""
    *dirs, last = pattern.split("/")
    base = Path(root, *dirs)
    if "*" not in last:
        p = base / last
        return [p] if os.path.lexists(p) else []
    rx = re.compile("^" + re.escape(last).replace(r"\*", ".*") + r"\Z")
    return sorted(base / n for n, _ in listdir(base) if not n.startswith(".") and rx.match(n))


# ---------------------------------------------------------------- the rules
class Rules:
    def __init__(self, v):
        def anchored(p, ci):
            return re.compile(f"(?:{p})", re.I if ci else 0)

        self.skip_dirs = set(v.get("skip_dirs") or [])
        self.project_skip_dirs = set(v.get("project_skip_dirs") or [])
        self.file_signs = [
            (r.get("glob", ""), r.get("vendor", ""), r.get("type", "")) for r in v.get("file_signs") or []
        ]
        self.tf = dict(v.get("terraform_providers") or {})
        self.pkg = [(anchored(r["pattern"], True), r["vendor"], r["type"]) for r in v.get("package_vendors") or []]
        self.env = [(anchored(r["pattern"], False), r["vendor"], r["type"]) for r in v.get("env_prefixes") or []]
        self.secretish = re.compile(v.get("secretish", ""), re.I)
        self.not_secret = re.compile(v.get("not_secret", ""))
        self.registry = [(re.compile(r["pattern"]), r["vendor"]) for r in v.get("registry_hosts") or []]
        self.secret_patterns = [
            (r["kind"], r["severity"], re.compile(r["pattern"])) for r in v.get("secret_patterns") or []
        ]
        self.placeholder = re.compile(v.get("secret_placeholder") or "(?i)example|dummy|fake|placeholder|xxxx")
        self.secret_skip = set(v.get("secret_skip_dirs") or [])
        aliases = v.get("import_aliases") or {}
        self.import_aliases = {k.lower(): x for k, x in aliases.items() if not k.startswith("$") and isinstance(x, str)}


def _rules_version(v):
    return v.get("version") if isinstance(v, dict) and isinstance(v.get("version"), int) else 0


def load_rules(fetched=None, cache=None):
    """The server's rules when given (and cached), else the cached copy unless the built-in one is newer (a copy cached
    by an older version must not hide newer rules), else the built-in one."""
    if fetched is not None:
        try:
            rules = Rules(fetched)
            if cache:
                Path(cache).parent.mkdir(parents=True, exist_ok=True)
                Path(cache).write_text(json.dumps(fetched, indent=2) + "\n", encoding="utf-8")
            return rules
        except (KeyError, TypeError, re.error, OSError):
            pass
    copies = []
    for f in (cache, BUILTIN_RULES):
        try:
            v = json.loads(Path(f).read_text(encoding="utf-8"))
            copies.append((v, Rules(v)))
        except (TypeError, OSError, ValueError, KeyError, re.error):
            continue
    if not copies:
        raise RuntimeError("no usable scanner rules")
    newest = max(_rules_version(v) for v, _ in copies)
    return next(r for v, r in copies if _rules_version(v) == newest)  # the cache first when it is as new


# ---------------------------------------------------------------- manifests
REQ_FILE = re.compile(r"^requirements[^/]*\.txt\Z")
DIGIT = re.compile(r"^\d")
VERSION_PREFIX = re.compile(r"^[\^~>=<\s]+")


def is_requirements(name):
    return bool(REQ_FILE.match(name))


def is_manifest(name):
    return name in ("package.json", "pyproject.toml") or is_requirements(name)


def py_str(v):
    """str() of a package.json version value, as the app spells it."""
    if isinstance(v, str):
        return v
    if v is None:
        return "None"
    if isinstance(v, bool):
        return "True" if v else "False"
    return json.dumps(v, separators=(",", ":"))


def dep(ecosystem, name, version, spec, line, text, pinned, section):
    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "spec": spec,
        "line": line,
        "text": text,
        "pinned": pinned,
        "section": section,
    }


REQ_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:==\s*([^\s;,]+)|([<>=!~].*?))?\s*(?:;.*)?\Z")


def req_lines(text):
    out = []
    for i, raw in enumerate(lines(text)):
        line = raw.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = REQ_LINE.match(line)
        if m:
            out.append(dep("PyPI", m[1].lower(), m[2], line, i + 1, raw, m[2] is not None, None))
    return out


PJ_SKIP = re.compile(r"^(workspace|file|link|portal|git\+|https?|catalog):")


def package_json_lines(text):
    try:
        pj = json.loads(text)
    except ValueError:
        return []
    if not isinstance(pj, dict):
        return []
    ls, out = lines(text), []
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        obj = pj.get(sect)
        if not isinstance(obj, dict):
            continue
        for name, spec in obj.items():
            spec = py_str(spec)
            if PJ_SKIP.match(spec):
                continue  # a local/monorepo or URL reference, not a registry package
            key = re.compile(r'"' + re.escape(name) + r'"\s*:')
            ln = next((i + 1 for i, x in enumerate(ls) if key.search(x)), None)
            ver = VERSION_PREFIX.sub("", spec)
            version = ver if ver and DIGIT.match(ver) else None
            out.append(dep("npm", name, version, spec, ln, ls[ln - 1] if ln else None, bool(DIGIT.match(spec)), sect))
    return out


def pep508(spec):
    m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==\s*([^\s,]+))?", spec.split(";")[0].strip())
    return (m[1].lower(), m[3]) if m else None


ASSIGN = re.compile(r'^[\w\-\."]+\s*=\s*\[')
QUOTED = re.compile(r"""["']([^"']+)["']""")
STRIP_QUOTED = re.compile(r""""[^"]*"|'[^']*'""")
POETRY_SECTION = re.compile(r"^(?:tool\.poetry\.(dev-)?dependencies|tool\.poetry\.group\.[\w\-]+\.dependencies)\Z")
POETRY_VERSION = re.compile(r"""["']\s*(?:==)?\s*([0-9][^"',]*)["']""")
EXACT = re.compile(r"^[0-9][\w.]*\Z")


def parse_pyproject_text(text):
    """[project] dependencies / optional-dependencies / dependency-groups and [tool.poetry.*dependencies]."""
    return [(n, v) for n, v, _ in parse_pyproject(text)]


def parse_pyproject(text):
    """The same, with the section each dependency is declared in: "dependencies" (the project's own),
    "optional:<extra>" or "group:<group>" (a dependency group: [dependency-groups], Poetry's groups and
    dev-dependencies)."""

    def unclosed(t):
        u = STRIP_QUOTED.sub("", t)
        return u.count("[") > u.count("]")

    ls = lines(text)
    deps, section, i = [], "", 0
    while i < len(ls):
        st = ls[i].split("#")[0].rstrip().strip()
        if st.startswith("["):
            section = st.strip("[]").strip()
        elif section in ("project", "project.optional-dependencies", "dependency-groups") and ASSIGN.match(st):
            buf = st.split("=", 1)[1] if "=" in st else ""
            while unclosed(buf) and i + 1 < len(ls):
                i += 1
                buf += "\n" + ls[i].split("#")[0]
            if section != "project" or st.startswith("dependencies"):
                key = st.split("=", 1)[0].strip().strip('"')
                label = {"project": "dependencies", "project.optional-dependencies": f"optional:{key}"}.get(
                    section, f"group:{key}"
                )
                for q in QUOTED.finditer(buf):
                    d = pep508(q[1])
                    if d:
                        deps.append((*d, label))
        elif POETRY_SECTION.match(section) and "=" in st:
            name, val = (x.strip() for x in st.split("=", 1))
            if name.lower() != "python":
                m = POETRY_VERSION.search(val)
                exact = m[1] if m and EXACT.match(m[1]) else None
                label = {"tool.poetry.dependencies": "dependencies", "tool.poetry.dev-dependencies": "group:dev"}.get(
                    section, "group:" + section.removeprefix("tool.poetry.group.").removesuffix(".dependencies")
                )
                deps.append((name.strip("\"'").lower(), exact, label))
        i += 1
    return deps


def pyproject_lines(text):
    ls, out = lines(text), []
    for name, version, section in parse_pyproject(text):
        # "name==1.0" in a [project] list, else `name = "1.0"` in a [tool.poetry] table
        key = re.compile(r"""["']""" + re.escape(name) + r"""(\[|[<>=!~ ;"'])""", re.I)
        poetry = re.compile(r"""^\s*["']?""" + re.escape(name) + r"""["']?\s*=""", re.I)
        ln = next((i + 1 for i, x in enumerate(ls) if key.search(x)), None)
        if ln is None:
            ln = next((i + 1 for i, x in enumerate(ls) if poetry.search(x)), None)
        spec = ls[ln - 1].strip().strip(",") if ln else name
        out.append(dep("PyPI", name, version, spec, ln, ls[ln - 1] if ln else None, version is not None, section))
    return out


def manifest_deps(path):
    base, text = Path(path).name, read_text(path)
    if base == "package.json":
        return package_json_lines(text)
    if base == "pyproject.toml":
        return pyproject_lines(text)
    if is_requirements(base):
        return req_lines(text)
    return []


GK_SKIP = re.compile(r"^(workspace|file|link|portal|git\+|https?):")


def requirements_names(text):
    out = []
    for raw in lines(text):
        line = raw.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([^\s;]+)", line)
        if m:
            out.append(re.sub(r"\[.*\]", "", m[1], count=1).lower())
        else:
            out.append(re.split(r"[<>=!~ \[;]", line)[0].lower())
    return out


def gatekeeper_names(repo, manifests):
    """Dependency names for the package -> vendor rules, in order, de-duplicated."""
    out, seen = [], set()
    for rel in manifests:
        p = Path(repo) / rel
        if not p.is_file():
            continue
        text, base = read_text(p), p.name
        found = []
        if base == "package.json":
            try:
                pj = json.loads(text or "{}")
            except ValueError:
                pj = None
            for sect in ("dependencies", "devDependencies", "optionalDependencies"):
                obj = pj.get(sect) if isinstance(pj, dict) else None
                for n, val in (obj or {}).items() if isinstance(obj, dict) else ():
                    s = py_str(val)
                    if GK_SKIP.match(s):
                        continue
                    ver = VERSION_PREFIX.sub("", s)
                    found.append(("npm", n, ver or None))
        elif base == "pyproject.toml":
            found = [("PyPI", n, v) for n, v in parse_pyproject_text(text)]
        elif is_requirements(base):
            found = [("PyPI", n, None) for n in requirements_names(text)]
        for eco, name, ver in found:
            k = (eco, name.lower(), ver)
            if k not in seen:
                seen.add(k)
                out.append(name)
    return out


# ---------------------------------------------------------------- lockfiles
UV_DIRECT = re.compile(r'\[\[package\]\]\s*\nname = "([^"]+)"\s*\nversion = "([^"]+)"')
BUN_DIRECT = re.compile(r'"(@?[^"@\s]+(?:/[^"@\s]+)?)": \[\s*"(@?[^"@\s]+(?:/[^"@\s]+)?)@([^"]+)"')
BUN_ANY = re.compile(r'"[^"]+": \[\s*"(@?[^"@\s]+(?:/[^"@\s]+)?)@([^"]+)"')
UV_NAME = re.compile(r'(?m)^name = "([^"]+)"')
UV_VERSION = re.compile(r'(?m)^version = "([^"]+)"')
UV_SOURCE = re.compile(r"(?m)^source = \{ (\w+)")
REQ_LOCK = re.compile(r"(?m)^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def parse_json(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


def lock_versions(files):
    """{(ecosystem, name lowercased): version} of direct dependencies, from uv.lock, bun.lock and package-lock.json
    (the first file wins)."""
    out = {}
    for f in files:
        base = Path(f).name
        if base not in ("uv.lock", "bun.lock", "package-lock.json"):
            continue
        text = read_text(f)
        if base == "uv.lock":
            for m in UV_DIRECT.finditer(text):
                out.setdefault(("PyPI", m[1].lower()), m[2])
        elif base == "bun.lock":
            for m in BUN_DIRECT.finditer(text):
                if m[1] == m[2]:
                    out.setdefault(("npm", m[1].lower()), m[3])
        else:
            v = parse_json(text)
            pk = v.get("packages") if isinstance(v, dict) else None
            for k, val in (pk or {}).items() if isinstance(pk, dict) else ():
                ver = val.get("version") if isinstance(val, dict) else None
                if k.startswith("node_modules/") and isinstance(ver, str) and ver:
                    rest = k[len("node_modules/") :]
                    if "/node_modules/" not in rest:
                        out.setdefault(("npm", rest.lower()), ver)
    return out


def lock_entries(files):
    """Every registry package version a lockfile records, direct and transitive: (ecosystem, name, version, file)."""
    out = []
    for f in files:
        base = Path(f).name
        if base == "package-lock.json":
            v = parse_json(read_text(f))
            pk = v.get("packages") if isinstance(v, dict) else None
            for k, val in (pk or {}).items() if isinstance(pk, dict) else ():
                val = val if isinstance(val, dict) else {}
                ver = val.get("version") if isinstance(val.get("version"), str) else ""
                link = val.get("link") is True
                if "node_modules/" in k and ver and not link:
                    out.append(("npm", k.rsplit("node_modules/", 1)[1], ver, f))
        elif base == "bun.lock":
            for m in BUN_ANY.finditer(read_text(f)):
                if ":" not in m[2]:
                    out.append(("npm", m[1], m[2], f))
        elif base == "uv.lock":
            for block in read_text(f).split("\n[[package]]\n")[1:]:
                n, v, src = (r.search(block) for r in (UV_NAME, UV_VERSION, UV_SOURCE))
                if n and v and src and src[1] == "registry":
                    out.append(("PyPI", n[1], v[1], f))
        elif base == "requirements.lock":
            for m in REQ_LOCK.finditer(read_text(f)):
                out.append(("PyPI", m[1], m[2], f))
    return out


# ---------------------------------------------------------------- vendors
TF_PROVIDER = re.compile(r'provider\s+"([a-z0-9_]+)"')
K8S = re.compile(r"(?m)^kind:\s*(Deployment|StatefulSet|DaemonSet|CronJob)\b")
COMPOSE_SECTION = re.compile(r"(?m)^\s*(services|environment):")
COMPOSE_VAR = re.compile(r"(?m)^\s*-?\s*([A-Z][A-Z0-9_]{2,})\s*[:=]")
FROM_IMAGE = re.compile(r"(?mi)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)")
GH_SECRET = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")
CI_VAR = re.compile(r"\$\{?([A-Z][A-Z0-9_]{3,})\}?")
ENV_LINE = re.compile(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=")
CODE_ENV = re.compile(
    r"""(?:os\.environ(?:\.get)?\s*[\[(]\s*|os\.getenv\(\s*|process\.env\.|process\.env\[\s*|import\.meta\.env\."""
    r"""|Deno\.env\.get\(\s*)["']?([A-Z][A-Z0-9_]{2,})"""
)
CODE_EXT = (".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".go", ".rb")
OTHER_CI = {
    ".gitlab-ci.yml": "GitLab CI",
    ".circleci/config.yml": "CircleCI",
    "bitbucket-pipelines.yml": "Bitbucket Pipelines",
    "azure-pipelines.yml": "Azure Pipelines",
}


class _Found:
    """Third parties found so far, by lowercased name: the first detection sets the name and type; secrets collect."""

    def __init__(self):
        self.order, self.by = [], {}  # lowercased name -> [name, type, secrets]

    def add(self, name, typ):
        k = name.lower()
        if k not in self.by:
            self.order.append(k)
            self.by[k] = [name, typ, []]
        return self.by[k][2]

    def add_secret(self, name, typ, secret):
        found = self.add(name, typ)
        if secret not in found:
            found.append(secret)


def _file_signs(repo, rules, found):
    for pattern, vendor, typ in rules.file_signs:
        for hit in glob_any(repo, pattern):
            if hit.name == "app.json" and "heroku" not in read_text(hit, 3000).lower():
                continue
            found.add(vendor, typ)
            break


def _infrastructure(repo, files, rules, found, env_names):
    """Terraform providers, Kubernetes manifests, ECS task definitions; compose files' variable names."""
    for f in files:
        if f.endswith(".tf"):
            for m in TF_PROVIDER.finditer(read_text(repo / f, 400_000)):
                if m[1] in rules.tf:
                    found.add(rules.tf[m[1]], "platform")
        elif f.endswith((".yaml", ".yml")) and not f.startswith(".github/"):
            txt = read_text(repo / f, 60_000)
            if K8S.search(txt) and "apiVersion:" in txt:
                found.add("Kubernetes", "platform")
            if COMPOSE_SECTION.search(txt) and Path(f).name.startswith(("docker-compose", "compose")):
                for m in COMPOSE_VAR.finditer(txt):
                    env_names.setdefault(m[1], []).append(f)
        elif f.endswith(".json") and "containerDefinitions" in read_text(repo / f, 60_000):
            found.add("AWS ECS", "platform")


def _registries(repo, files, rules, found):
    """The container registry of each Dockerfile base image (Docker Hub when the image names no host)."""
    for f in files:
        if not Path(f).name.startswith("Dockerfile"):
            continue
        for m in FROM_IMAGE.finditer(read_text(repo / f, 400_000)):
            img = m[1]
            if img.lower() == "scratch" or img.startswith("$"):
                continue
            reg = next((n for r, n in rules.registry if r.search(img)), None)
            first = img.split("/")[0]
            if reg is None and "." in first and "/" in img:
                reg = first
            found.add(reg or "Docker Hub", "package_registry")


def _ci(repo, files, rules, found):
    """CI systems and the secret names their pipelines use."""
    for f in files:
        if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml")):
            secrets = found.add("GitHub Actions", "ci")
            for m in GH_SECRET.finditer(read_text(repo / f, 400_000)):
                if m[1] != "GITHUB_TOKEN" and m[1] not in secrets:
                    secrets.append(m[1])
        elif f in OTHER_CI:
            for m in CI_VAR.finditer(read_text(repo / f, 400_000)):
                if rules.secretish.search(m[1]):
                    found.add_secret(OTHER_CI[f], "ci", m[1])


def _env_names(repo, files, env_names):
    """Environment variable names in .env files and in code (never values)."""
    for f in files:
        if Path(f).name.startswith(".env"):
            for m in ENV_LINE.finditer(read_text(repo / f, 400_000)):
                env_names.setdefault(m[1], []).append(f)
        elif f.endswith(CODE_EXT):
            for m in CODE_ENV.finditer(read_text(repo / f, 400_000)):
                env_names.setdefault(m[1], []).append(f)


class _BadInventory(Exception):
    """An old inventory file the generator could not read: the project gets no vendors (as the Rust app does)."""


def _inventory(repo, files, found):
    """An old-format inventory file (infra/deployments.json)."""
    if "infra/deployments.json" not in files:
        return
    inv = parse_json(read_text(repo / "infra/deployments.json", 400_000))
    inv = {} if inv is None else inv
    if not isinstance(inv, dict):
        raise _BadInventory
    entries, seen = [], set()
    for key, typ, field in (("services", "platform", "platform"), ("developer_tools", "developer_tool", "name"),
                            ("ci", "ci", "name")):  # fmt: skip
        items = inv.get(key)
        for item in items if isinstance(items, list) else []:
            name = item.get(field) if isinstance(item, dict) else None
            if not isinstance(name, str):
                raise _BadInventory
            if name.lower() not in seen:
                seen.add(name.lower())
                entries.append((name, typ))
    for name, typ in entries:
        found.add(name, typ)


def _first_match(rules_list, name):
    return next(((v, t) for r, v, t in rules_list if r.match(name)), None)


def detect_vendors(repo, rules):
    """[(name, type)] of the third parties a project relies on, or None when an old inventory file is malformed.
    The steps and their order are the Rust app's (vendors.rs): the first detection of a vendor sets its type."""
    repo = Path(repo)
    files = [relpath(p, repo) for p in walk(repo, lambda d: d not in rules.skip_dirs)]
    found, env_names = _Found(), {}
    _file_signs(repo, rules, found)
    _infrastructure(repo, files, rules, found, env_names)
    _registries(repo, files, rules, found)
    _ci(repo, files, rules, found)
    _env_names(repo, files, env_names)
    secret_names = sorted(k for k in env_names if rules.secretish.search(k) and not rules.not_secret.search(k))
    try:
        _inventory(repo, files, found)
    except _BadInventory:
        return None
    manifests = sorted((f for f in files if is_manifest(Path(f).name)), key=path_key)
    for name in gatekeeper_names(repo, manifests):
        hit = _first_match(rules.pkg, name)
        if hit:
            found.add(*hit)
    for secret in secret_names:
        hit = _first_match(rules.env, secret)
        if hit:
            found.add_secret(*hit, secret)
    # CI secrets that belong to a vendor (e.g. FASTAPI_CLOUD_TOKEN)
    for ci_name, ci_secrets in [(found.by[k][0], list(found.by[k][2])) for k in found.order if found.by[k][1] == "ci"]:
        for secret in ci_secrets:
            hit = _first_match(rules.env, secret)
            if hit and hit[0] != ci_name:
                found.add(*hit)
    out = [(found.by[k][0], found.by[k][1]) for k in found.order]
    out.sort(key=lambda a: (TYPES.index(a[1]) if a[1] in TYPES else len(TYPES), a[0]))
    return out


# ---------------------------------------------------------------- secrets (facts only, never the value)
def _secret_text(p):
    try:
        if not os.path.isfile(p) or os.path.getsize(p) > MAX_SECRET_FILE:
            return None
        with open(p, "rb") as f:
            data = f.read(MAX_SECRET_FILE + 1)
    except OSError:
        return None
    if len(data) > MAX_SECRET_FILE or b"\0" in data[:8000]:
        return None  # binary, or it grew
    return data.decode("utf-8", errors="replace")


def _git(project, *args):
    try:
        r = subprocess.run(["git", "-C", str(project), *args], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False, ""
    return r.returncode == 0, r.stdout


def _git_status(project, rel):
    ok, out = _git(project, "rev-parse", "--is-inside-work-tree")
    if not ok or out.strip() != "true":
        return None
    tracked = bool(_git(project, "ls-files", "--", rel)[1].strip())
    ignored = _git(project, "check-ignore", "-q", "--", rel)[0]
    return tracked, ignored


def scan_secrets(project, base, name, rules):
    found, cache = {}, {}
    for f in walk(project, lambda d: d not in rules.secret_skip):
        text = _secret_text(f)
        if text is None:
            continue
        env_file = f.name.startswith(".env")
        for i, line in enumerate(lines(text)):
            for kind, severity, rx in rules.secret_patterns:
                for m in rx.finditer(line):
                    if kind == "OpenAI API key" and m.group(0).startswith("sk-ant-"):
                        continue  # an Anthropic key, matched by its own pattern
                    file = relpath(f, base)
                    key = (file, i + 1, kind)
                    if key in found:
                        continue
                    in_project = relpath(f, project)
                    if in_project not in cache:
                        cache[in_project] = _git_status(project, in_project)
                    s = {
                        "project": name,
                        "file": file,
                        "line": i + 1,
                        "kind": kind,
                        "severity": severity,
                        "placeholder": bool(rules.placeholder.search(m.group(0))),
                        "in_source_code": not env_file,
                        "env_file": env_file,
                    }
                    if cache[in_project] is not None:
                        s["tracked"], s["ignored"] = cache[in_project]
                    found[key] = s
    return [found[k] for k in sorted(found)]


# ---------------------------------------------------------------- CA certificates (parsed here; nothing executed)
_B64 = {c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}


def _base64(s):
    data = [c for c in s if c != "="]
    out = bytearray()
    for at in range(0, len(data), 4):
        chunk, n = data[at : at + 4], 0
        for i, c in enumerate(chunk):
            if c not in _B64:
                return None
            n |= _B64[c] << (18 - 6 * i)
        take = {4: 3, 3: 2, 2: 1}.get(len(chunk), 0)
        out += n.to_bytes(4, "big")[1 : 1 + take]
    return bytes(out)


def _tlv(d):
    """One DER element: (tag, content, rest), or None."""
    if len(d) < 2:
        return None
    tag, first, d = d[0], d[1], d[2:]
    if first < 0x80:
        n = first
    else:
        k = first & 0x7F
        if k == 0 or k > 4 or len(d) < k:
            return None
        n, d = int.from_bytes(d[:k], "big"), d[k:]
    if len(d) < n:
        return None
    return tag, d[:n], d[n:]


def _subject_org(der):
    """organizationName (2.5.4.10) of the certificate's subject."""
    cert = _tlv(der)
    tbs = cert and _tlv(cert[1])
    if not tbs:
        return None
    fields, rest = [], tbs[1]
    while rest:
        t = _tlv(rest)
        if not t:
            return None
        fields.append((t[0], t[1]))
        rest = t[2]
    skip = 1 if fields and fields[0][0] == 0xA0 else 0
    if len(fields) <= skip + 4:
        return None
    rdns = fields[skip + 4][1]
    while rdns:
        s = _tlv(rdns)
        if not s:
            return None
        rdns, atvs = s[2], s[1]
        while atvs:
            a = _tlv(atvs)
            if not a:
                return None
            atvs = a[2]
            o = _tlv(a[1])
            if not o:
                return None
            if o[0] == 0x06 and o[1] == b"\x55\x04\x0a":
                v = _tlv(o[2])
                if not v:
                    return None
                if v[0] == 0x1E:
                    raw = v[1] + (b"\0" if len(v[1]) % 2 else b"")
                    return raw.decode("utf-16-be", errors="replace")
                return v[1].decode("utf-8", errors="replace")
    return None


def subject_orgs(pem):
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    out, rest = [], pem
    while begin in rest:
        body = rest.index(begin) + len(begin)
        stop = rest.find(end, body)
        if stop < 0:
            break
        der = _base64("".join(rest[body:stop].split()))
        org = _subject_org(der) if der is not None else None
        if org:
            cut = re.split(r"[,/\n]", org)[0].strip()
            if cut:
                out.append(cut)
        rest = rest[stop:]
    return out


# ---------------------------------------------------------------- whether a project uses a dependency
# Its code imports it, or a run command starts it (a Dockerfile CMD, an npm script, a Procfile). Worked out here; only
# a yes/no per dependency is sent, never the names found in the code. Same as the app's usage.rs.
PY_EXT, JS_EXT = (".py",), (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
PY_IMPORT = re.compile(r"(?m)^[ \t]*import[ \t]+([A-Za-z_][\w.]*(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*)*)")
PY_FROM = re.compile(r"(?m)^[ \t]*from[ \t]+([A-Za-z_][\w.]*)[ \t]+import\b")
JS_IMPORT = re.compile(r"""(?:\bfrom|\bimport|\brequire[ \t]*\(|\bimport[ \t]*\()[ \t]*["']([^"'\s]+)["']""")
WORD = re.compile(r"[A-Za-z0-9@][A-Za-z0-9@/_.\-]*")
DOCKER_RUN = re.compile(r"(?mi)^[ \t]*(?:CMD|ENTRYPOINT|RUN)\b(.*)$")
COMPOSE_RUN = re.compile(r"(?m)^[ \t]*(?:command|entrypoint|cmd)[ \t]*[:=](.*)$")


def norm(name):
    """A package or module name as it is compared: lower case, with "-", "_" and "." alike."""
    return re.sub(r"[-_.]+", "-", name.lower())


def pypi_names(name):
    n = norm(name)
    out = [n]
    out += [n[len(p) :] for p in ("python-", "py-") if n.startswith(p)]
    out += [n[: -len(x)] for x in ("-python", "-py") if n.endswith(x)]
    return out


def npm_package(spec):
    if spec.startswith((".", "/", "node:")) or ":" in spec:
        return None
    parts = spec.split("/")
    if parts[0].startswith("@"):
        return f"{parts[0]}/{parts[1]}" if len(parts) > 1 and parts[1] else None
    return parts[0] or None


class Usage:
    def __init__(self):
        self.has_python = self.has_js = False
        self.python, self.js, self.run = set(), set(), set()

    def used(self, ecosystem, name):
        """True/False, or None when the project has no code in the dependency's language."""
        if ecosystem == "npm":
            if not self.has_js:
                return None
            target = name
            if name.startswith("@types/"):
                t = name[len("@types/") :]
                target = f"@{t.split('__', 1)[0]}/{t.split('__', 1)[1]}" if "__" in t else t
            n = norm(target)
            return any(norm(j) == n for j in self.js) or n in self.run or name.startswith("@types/node")
        if not self.has_python:
            return None
        return any(n in self.python or n in self.run for n in pypi_names(name))


def _python_imports(u, text, aliases):
    def add(module):
        top = norm(module.split(".")[0])
        if top:
            u.python.add(aliases.get(top, top))

    for m in PY_IMPORT.finditer(text):
        for part in m[1].split(","):
            words = part.split()
            add(words[0] if words else "")
    for m in PY_FROM.finditer(text):
        add(m[1])


def _run_words(u, text):
    """The words of a run command (a package started by name, e.g. gunicorn or next)."""
    for w in WORD.findall(text):
        u.run.update(norm(part) for part in w.split("/") if part)
        u.run.add(norm(w))


def _run_commands(name, text):
    """The run-command text in a file: Dockerfile CMD/ENTRYPOINT/RUN, compose command lines, npm scripts, or the
    whole of a Procfile or fly.toml. None for other files."""
    if name.startswith("Dockerfile"):
        return "\n".join(m[1] for m in DOCKER_RUN.finditer(text))
    if name in ("Procfile", "fly.toml"):
        return text
    if name.startswith(("docker-compose", "compose")) and name.endswith((".yml", ".yaml")):
        return "\n".join(m[1] for m in COMPOSE_RUN.finditer(text))
    if name == "package.json":
        pj = parse_json(text)
        scripts = pj.get("scripts") if isinstance(pj, dict) else None
        return "\n".join(v for v in (scripts or {}).values() if isinstance(v, str)) if isinstance(scripts, dict) else ""
    return None


def usage_of(files, aliases):
    """What one project uses: the modules its Python imports, the npm packages its JavaScript imports, and the
    words of its run commands. aliases: Python import name -> PyPI name."""
    aliases = {norm(k): norm(v) for k, v in aliases.items()}
    u = Usage()
    for f in files:
        name = f.name
        if name.endswith(PY_EXT):
            u.has_python = True
            _python_imports(u, read_text(f, 400_000), aliases)
        elif name.endswith(JS_EXT):
            u.has_js = True
            u.js.update(p for m in JS_IMPORT.finditer(read_text(f, 400_000)) if (p := npm_package(m[1])))
        else:
            run = _run_commands(name, read_text(f, None if name == "package.json" else 400_000))
            if run:
                _run_words(u, run)
    return u


# ---------------------------------------------------------------- the scan
def files_in(project, rules):
    return walk(project, lambda d: (d not in rules.project_skip_dirs and not d.startswith(".")) or d == ".github")


def stack_of(files):
    rx, out = re.compile(r"(?mi)^\s*FROM\s+([^\s:@]+)"), set()
    for f in files:
        if f.name.startswith("Dockerfile"):
            for m in rx.finditer(read_text(f)):
                img = m[1].rsplit("/", 1)[-1].lower()
                if img != "scratch" and not img.startswith("$"):
                    out.add(img)
    return out


def cas_of(files):
    out = []
    for f in files:
        if f.name.endswith((".pem", ".crt")):
            for org in subject_orgs(read_text(f)):
                if (f, org) not in out:
                    out.append((f, org))
    return out


def internal_names(files):
    out = set()
    for f in files:
        if f.name == "internal-packages.txt":
            out |= {x.strip() for x in lines(read_text(f)) if x.strip() and not x.startswith("#")}
    return out


def projects_in(root, rules):
    """The folder itself if it has a manifest at its top, else each subfolder."""
    root = Path(os.path.abspath(root))
    entries = listdir(root)
    if any(not is_dir and is_manifest(n) for n, is_dir in entries):
        return [root]
    return sorted(
        (root / n for n, is_dir in entries if is_dir and not n.startswith(".") and n not in rules.project_skip_dirs),
        key=path_key,
    )


def scan(root, rules):
    """-> (scope, projects): the scope for POST /v1/scans and a per-project summary (same as `ssc scope`)."""
    root_abs = Path(os.path.abspath(root))
    base_dir = root_abs.parent

    def rel(p):
        return relpath(p, base_dir)

    root_list = root_abs / "internal-packages.txt"
    root_internal = internal_names([root_list] if root_list.is_file() else [])
    packages, vendors = {}, {}  # (ecosystem, name lower) -> package; vendor name -> [type, projects]
    stack, cas, internal, projects, secrets, cert_files = set(), set(), set(), [], [], []

    def package(eco, name):
        return packages.setdefault(
            (eco, name.lower()),
            {"manager": "pip" if eco == "PyPI" else "npm", "name": name, "versions": set(), "found_in": []},
        )

    for proj in projects_in(root, rules):
        name = proj.name
        files = files_in(proj, rules)
        locks = lock_versions(files)
        usage = usage_of(files, rules.import_aliases)
        manifests = sorted((f for f in files if is_manifest(f.name)), key=path_key)
        count = 0
        for mf in manifests:
            for d in manifest_deps(mf):
                version, how = d["version"], "pinned" if d["pinned"] else "range"
                if not d["pinned"]:
                    locked = locks.get((d["ecosystem"], d["name"].lower()))
                    if locked is not None:
                        version, how = locked, "lockfile"
                    elif version is None:
                        how = "unpinned (latest)"
                p = package(d["ecosystem"], d["name"])
                if version is not None:
                    p["versions"].add(version)
                p["found_in"].append(
                    {
                        "project": name,
                        "file": rel(mf),
                        "line": d["line"],
                        "text": d["text"],
                        "spec": d["spec"],
                        "version": version,
                        "version_from": how,
                        "section": d["section"],
                        "used": usage.used(d["ecosystem"], d["name"]),
                    }
                )
                count += 1
        # every other version the lockfiles pin: dependencies of dependencies
        seen = {
            (eco, n, f["version"])
            for (eco, n), p in packages.items()
            for f in p["found_in"]
            if f["project"] == name and isinstance(f["version"], str)
        }
        for eco, pkg, version, lockfile in lock_entries(files):
            k = (eco, pkg.lower(), version)
            if k in seen:
                continue
            seen.add(k)
            p = package(eco, pkg)
            p["versions"].add(version)
            p["found_in"].append(
                {
                    "project": name,
                    "file": rel(lockfile),
                    "line": None,
                    "text": None,
                    "spec": None,
                    "version": version,
                    "version_from": "lockfile",
                    "section": "transitive",
                    "used": usage.used(eco, pkg),
                }
            )
        pv = []
        for vname, vtype in detect_vendors(proj, rules) or []:
            vendors.setdefault(vname, [vtype, set()])[1].add(name)
            pv.append(vname)
        st, ca_files, intl = stack_of(files), cas_of(files), internal_names(files) | root_internal
        ca = {o for _, o in ca_files}
        cert_files += [{"project": name, "file": rel(f), "ca": o} for f, o in ca_files]
        secrets += scan_secrets(proj, base_dir, name, rules)
        stack |= st
        cas |= ca
        internal |= intl
        projects.append(
            {
                "project": name,
                "path": rel(proj),
                "manifests": [rel(m) for m in manifests],
                "dependencies": count,
                "lockfiles": sorted({rel(f) for f in files if f.name in LOCKFILES}),
                "vendors": pv,
                "stack": sorted(st),
                "certificate_authorities": sorted(ca),
                "internal_packages": sorted(intl),
            }
        )

    vlist = sorted(vendors.items(), key=lambda kv: kv[0])  # by name, then case-insensitively (stable)
    vlist.sort(key=lambda kv: kv[0].lower())
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    scope = {
        "$comment": f"Generated by the ssc-advisor plugin from {root_abs} on {now}. Same format as "
        "intel_api/config/scope.json; found_in says where each package came from.",
        "packages": [
            {
                "package_manager": p["manager"],
                "name": p["name"],
                "found_in": p["found_in"],
                "versions": sorted(p["versions"]),
            }
            for _, p in sorted(packages.items())
        ],
        "vendors": [{"name": n, "aliases": [], "type": t, "projects": sorted(ps)} for n, (t, ps) in vlist],
        "stack": sorted(stack),
        "certificate_authorities": sorted(cas),
        "internal_packages": sorted(internal),
        "base_dir": str(base_dir),
        # facts only: which kind of secret, where, example or real, git status; never the value
        "secrets": secrets,
        "certificate_files": cert_files,
    }
    return scope, projects
