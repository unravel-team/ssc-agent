"""Facts about whether each open action item matters to this project, gathered on the laptop from the files
themselves (read only; git is asked read-only questions). Nothing here is sent anywhere: the facts are for Claude to
weigh, with the file and line behind each one, and for the user to decide on.

For every pending item:
  - where:        each place it was found, and what kind of place that is: test, example, docs, script or shipped code
  - deploys:      what in its project ships it (a Dockerfile, fly.toml, vercel.json, a CI deploy step, ...), if anything
and, by kind of item:
  - secret:       whether a Dockerfile copies the file into an image (and .dockerignore doesn't stop it), and whether
                  git history has ever held the file (it may be in old commits even if it's ignored now)
  - package:      for Python, from a parsed index of the code (code_index.py): each call of the functions the
                  advisories name (or of the package at all), and whether something that starts the program (a run
                  command, a route, a task, __main__) reaches it, with the path, hop by hop; for other languages,
                  where the code calls those functions (file:line, a text search). For a package only a lockfile
                  lists, which of the project's dependencies pull it in
  - vendor rows:  where the project's own files mention the vendor (file:line); for Docker Hub, whether anything
                  logs in or pushes there rather than only pulling base images
"""

import fnmatch
import re
import subprocess
from pathlib import Path

import code_index
import deployment
import ssc_scope

CODE_EXT = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb")
CATEGORIES = [
    ("test", re.compile(r"(^|/)(tests?|__tests__|spec|specs|e2e|testing|fixtures?)(/|$)"
                        r"|(^|/)(test_[^/]*|[^/]*_test\.\w+|[^/]*\.(test|spec)\.\w+)$", re.I)),
    ("example", re.compile(r"(^|/)(examples?|samples?|demos?)(/|$)", re.I)),
    ("docs", re.compile(r"(^|/)(docs?|documentation)(/|$)", re.I)),
    ("script", re.compile(r"(^|/)(scripts?|tools?|bin|hack)(/|$)", re.I)),
]  # fmt: skip
DEPLOY_FILES = {
    "fly.toml": "Fly.io",
    "vercel.json": "Vercel",
    "netlify.toml": "Netlify",
    "railway.json": "Railway",
    "railway.toml": "Railway",
    "Procfile": "Procfile (Heroku-style)",
    "app.yaml": "App Engine",
    "serverless.yml": "Serverless",
    "render.yaml": "Render",
}
CI_DEPLOY = re.compile(r"\b(deploy|publish|release|docker\s+push|--push|kubectl\s+apply|flyctl|vercel|netlify)\b", re.I)
DOCKER_HUB_WRITE = re.compile(
    r"docker\s+login(?![^\n]*\b(ghcr\.io|gcr\.io|ecr|azurecr|quay\.io|registry\.))|docker/login-action|"
    r"docker\s+push|buildx[^\n]*--push|push:\s*true|DOCKERHUB_(USERNAME|TOKEN|PASSWORD)|docker\.io/",
    re.I,
)
MAX_HITS = 5
ADVISORY_URL = "https://osv.dev/vulnerability/{}"


def category(rel):
    """What kind of place a path is: test, example, docs, script, or shipped (everything else)."""
    for name, rx in CATEGORIES:
        if rx.search(rel):
            return name
    return "shipped"


def _rel(path, base):
    try:
        return Path(path).relative_to(base).as_posix()
    except ValueError:
        return str(path)


def _hits(files, base, rx, limit=MAX_HITS):
    """file:line of the first lines matching rx (reads text files only)."""
    out = []
    for f in files:
        text = ssc_scope.read_text(f, 400_000)
        for n, line in enumerate(ssc_scope.lines(text), 1):
            if rx.search(line):
                out.append(f"{_rel(f, base)}:{n}")
                if len(out) >= limit:
                    return out
    return out


def deploys(project, files):
    """What in a project ships it: files that deploy it, Dockerfiles, CI steps that deploy or push."""
    out = []
    for f in files:
        rel = _rel(f, project)
        if f.name in DEPLOY_FILES:
            out.append(f"{rel} ({DEPLOY_FILES[f.name]})")
        elif f.name.startswith("Dockerfile"):
            out.append(f"{rel} (container image)")
        elif rel.startswith(".github/workflows/") or f.name in (".gitlab-ci.yml", "bitbucket-pipelines.yml"):
            hit = _hits([f], project, CI_DEPLOY, 1)
            if hit:
                out.append(f"{hit[0]} (CI deploy step)")
    return out


# ---------------------------------------------------------------- secrets: can the file ship inside an image?
COPY = re.compile(r"(?mi)^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*(.+?)\s*$")


def _dockerignore(context):
    try:
        lines_ = (Path(context) / ".dockerignore").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    return [ln.strip() for ln in lines_ if ln.strip() and not ln.strip().startswith("#")]


def _ignored(rel, patterns):
    """Whether .dockerignore patterns leave rel out of the build context (the last matching pattern wins)."""
    out = False
    parts = rel.split("/")
    candidates = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    for p in patterns or []:
        neg = p.startswith("!")
        pat = p[1:] if neg else p
        pat = pat.lstrip("/").rstrip("/")
        pats = [pat, pat.replace("**/", "")] if "**/" in pat else [pat]
        if any(fnmatch.fnmatch(c, q) or fnmatch.fnmatch(Path(c).name, q) for c in candidates for q in pats):
            out = not neg
    return out


def in_image(project, files, secret_rel):
    """Dockerfiles whose COPY/ADD takes the secret's file into the image (the build context is the Dockerfile's
    folder). -> [{dockerfile, line, dockerignore}] where dockerignore says whether a .dockerignore exists."""
    out = []
    for f in files:
        if not f.name.startswith("Dockerfile"):
            continue
        context = f.parent
        target = project / secret_rel
        try:
            rel = target.relative_to(context).as_posix()
        except ValueError:
            continue  # the file is outside this Dockerfile's build context
        patterns = _dockerignore(context)
        if _ignored(rel, patterns):
            continue
        text = ssc_scope.read_text(f, 400_000)
        for n, line in enumerate(ssc_scope.lines(text), 1):
            m = COPY.match(line)
            if not m:
                continue
            srcs = m.group(1).strip("[]").replace('"', "").replace(",", " ").split()[:-1]  # the last is the target
            if any(
                s in (".", "./", "*") or rel == s.strip("./") or rel.startswith(s.strip("./").rstrip("/") + "/")
                for s in srcs
            ):
                out.append({"dockerfile": f"{_rel(f, project)}:{n}", "dockerignore": patterns is not None})
                break
    return out


def _git(project, *args):
    try:
        r = subprocess.run(["git", "-C", str(project), *args], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def in_history(project, rel):
    """How many commits on any branch have touched the file (None outside git). The value is never read."""
    out = _git(project, "log", "--all", "--format=%h", "--", rel)
    return None if out is None else len([x for x in out.splitlines() if x.strip()])


# ---------------------------------------------------------------- packages: does the code call what's affected?
# names an advisory may mention that are the language's own, not the package's: matching them finds every file
JS_GLOBALS = {"URL", "URLSearchParams", "Request", "Response", "Headers", "Error", "Promise", "Object", "Array",
              "JSON", "Map", "Set", "fetch", "Date", "RegExp", "String", "Number", "Buffer", "OPTIONS", "GET", "POST",
              "Origin", "Connection", "Content-Type", "parts.slice", "url.pathname", "console.log"}  # fmt: skip


def symbol_hits(code_files, project, symbols):
    """For each function an advisory names, where the code calls or uses it (file:line). A dotted name such as
    yaml.load is also found as `load(` in a file that imports from yaml."""
    out = {}
    for sym in symbols:
        if sym in JS_GLOBALS:
            continue
        last = sym.split(".")[-1]
        rx = re.compile(
            r"(?<![\w$])" + re.escape(sym) + r"(?![\w$])"
            if "." in sym
            else r"(?<![\w$.])" + re.escape(last) + r"\s*\(|\." + re.escape(last) + r"(?![\w$])"
        )
        hits = _hits(code_files, project, rx)
        if not hits and "." in sym:  # from yaml import load ... load(
            module = sym.split(".")[0]
            importing = [
                f
                for f in code_files
                if re.search(
                    rf"\bfrom\s+{re.escape(module)}\b|\brequire\(\s*['\"]{re.escape(module)}",
                    ssc_scope.read_text(f, 400_000),
                )
            ]
            hits = _hits(importing, project, re.compile(r"(?<![\w$.])" + re.escape(last) + r"\s*\("))
        out[sym] = hits
    return out


def imported_at(code_files, project, manager, name, aliases, limit=MAX_HITS):
    """Where the code imports a package (file:line): `import yaml`, `from yaml import ...` for PyYAML (the import
    name may differ: aliases maps import name -> PyPI name), require("lodash") or import ... from "lodash"."""
    if manager == "npm":
        q = re.escape(name)
        rx = re.compile(rf"""(?:\bfrom|\brequire\s*\(|\bimport\s*\(|^\s*import)\s*["']{q}(?:/[^"']*)?["']""")
    else:
        mods = import_names(name, aliases)
        alt = "|".join(re.escape(m).replace("\\-", "[-_.]") for m in sorted(mods))
        rx = re.compile(rf"^\s*(?:import|from)\s+(?:{alt})\b", re.I)
    return _hits(code_files, project, rx, limit)


def _bun_lock(text):
    """bun.lock is JSON with trailing commas."""
    return ssc_scope.parse_json(re.sub(r",(\s*[}\]])", r"\1", text)) or {}


def _name_of(spec):
    """'@scope/pkg@1.2.3' -> '@scope/pkg', 'pkg@^1' -> 'pkg'."""
    head, _, _ = spec.rpartition("@")
    return head if head and head != "@" else spec


def parents(files, name):
    """Which packages a lockfile says depend on `name`: npm package-lock.json, bun.lock, yarn.lock, pnpm-lock.yaml,
    uv.lock and poetry.lock."""
    out = set()
    q = re.escape(name)
    for f in files:
        if f.name == "package-lock.json":
            data = ssc_scope.parse_json(ssc_scope.read_text(f)) or {}
            for path, meta in (data.get("packages") or {}).items():
                if isinstance(meta, dict) and name in (meta.get("dependencies") or {}) and path:
                    out.add(path.rsplit("node_modules/", 1)[-1])
        elif f.name == "bun.lock":
            for entry in (_bun_lock(ssc_scope.read_text(f)).get("packages") or {}).values():
                meta = entry[2] if isinstance(entry, list) and len(entry) > 2 and isinstance(entry[2], dict) else {}
                deps = {**(meta.get("dependencies") or {}), **(meta.get("optionalDependencies") or {})}
                if name in deps and isinstance(entry[0], str):
                    out.add(_name_of(entry[0]))
        elif f.name == "yarn.lock":  # "parent@^1":\n  version ...\n  dependencies:\n    name "^2"
            for block in re.split(r"\n(?=\S)", ssc_scope.read_text(f)):
                head = block.split("\n", 1)[0]
                if re.search(rf'(?m)^\s+"?{q}"?\s+"?[^\s"]+"?\s*$', block.split("dependencies:", 1)[-1]) and (
                    "dependencies:" in block
                ):
                    out.add(_name_of(head.split(",")[0].strip().strip('":')))
        elif f.name == "pnpm-lock.yaml":  # snapshots/packages: "  parent@1.0.0:\n    dependencies:\n      name: 2.0.0"
            for block in re.split(r"\n(?=  \S)", ssc_scope.read_text(f)):
                head = block.split("\n", 1)[0].strip().strip("'\":")
                if re.search(rf"(?m)^\s{{6}}'?{q}'?:", block) and head:
                    out.add(_name_of(head.split("(")[0]))
        elif f.name in ("uv.lock", "poetry.lock"):
            for block in ("\n" + ssc_scope.read_text(f)).split("\n[[package]]\n")[1:]:
                n = re.search(r'(?m)^name = "([^"]+)"', block)
                body = block.split("\n[package.", 1)[0] if f.name == "uv.lock" else block
                if n and (re.search(r'\{\s*name\s*=\s*"' + q + r'"', body)
                          or re.search(rf'(?mi)^\[package\.dependencies\][^\[]*^{q}\s*=', block)):  # fmt: skip
                    out.add(n.group(1))
    out.discard(name)
    return sorted(out)[:10]


# ---------------------------------------------------------------- vendors
def vendor_mentions(files, project, vendor):
    """Where the project's own files mention a vendor (lockfiles and minified files left out)."""
    rx = re.compile(re.escape(vendor), re.I)
    keep = [f for f in files if f.name not in ssc_scope.LOCKFILES and not f.name.endswith((".min.js", ".map"))]
    return _hits(keep, project, rx)


def docker_hub_use(files, project):
    """Docker Hub: base images pulled from it (FROM without a registry host), and anything that logs in or pushes."""
    pulls, writes = [], []
    from_rx = re.compile(r"(?mi)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)")
    for f in files:
        if f.name.startswith("Dockerfile"):
            for n, line in enumerate(ssc_scope.lines(ssc_scope.read_text(f, 400_000)), 1):
                m = from_rx.match(line)
                image = m.group(1) if m else ""
                # a registry host comes before the first "/" and has a dot or a port: ghcr.io/x, localhost:5000/x
                first = image.split("/")[0] if "/" in image else ""
                on_hub = image and not ("." in first or ":" in first or first == "localhost")
                if on_hub and image.lower() != "scratch" and not image.startswith("$"):
                    pulls.append(f"{_rel(f, project)}:{n} ({image})")
    ci = [
        f
        for f in files
        if _rel(f, project).startswith(".github/") or f.suffix in (".yml", ".yaml", ".sh") or f.name in ("Makefile",)
    ]
    writes = _hits(ci, project, DOCKER_HUB_WRITE)
    return {"pulls_base_images": pulls[:MAX_HITS], "logs_in_or_pushes": writes}


# ---------------------------------------------------------------- the report
def _package_of(key):
    """(manager, name, version) from a package item's key: package:<manager>:<name>@<version>:<project>. A scoped npm
    name starts with @ itself, so the version follows the last @."""
    manager, _, rest = key.partition(":")[2].partition(":")
    name, _, version = rest.rsplit(":", 1)[0].rpartition("@")
    return manager, name, version


def _secret_facts(a, project, files):
    rel = (a.get("where") or [":"])[0].rsplit(":", 1)[0]
    return {"copied_into_images": in_image(project, files, rel), "commits_touching_file": in_history(project, rel)}


def import_names(name, aliases):
    """The names a PyPI package is imported as: itself without python-/py- affixes, and the shared aliases."""
    mods = {ssc_scope.norm(n) for n in ssc_scope.pypi_names(name)}
    return mods | {ssc_scope.norm(i) for i, dist in aliases.items() if ssc_scope.norm(dist) == ssc_scope.norm(name)}


def reachability(index, mods, names, exposure=None):
    """From the parsed index: the calls of the named functions (or, when none is found or named, of the package at
    all), each with whether an entry point reaches it and the path."""
    out = {}
    if names:
        out["calls_of_named_functions"] = index.uses(mods, names)
    if not out.get("calls_of_named_functions"):
        out["calls_of_the_package"] = index.uses(mods)
    calls = [c for v in out.values() for c in v]
    out["verdict"] = (
        "reached from an entry point" if any(c["reachable"] for c in calls)
        else "called, but no path from an entry point" if calls
        else "never called"
    )  # fmt: skip
    if not index.entries:
        out["verdict"] += " (no entry point found: a library, or started in a way the index doesn't know)"
    if exposure and any(c["reachable"] for c in calls):
        out["exposure"] = exposure["summary"]  # who can reach the project, from its deployment config
    return out


def _package_facts(a, project, files, findings, rules, index, exposure=None):
    manager, name, version = _package_of(a.get("key", ""))
    finding = findings.get((manager, name, version)) or {}
    locations = finding.get("found_in") or []
    names = sorted({s for adv in finding.get("advisories") or [] for s in adv.get("symbols") or []})
    code = [f for f in files if f.name.endswith(CODE_EXT)]
    links = {x.get("text"): x.get("url") for x in a.get("sources") or [] if isinstance(x, dict)}
    out = {
        # each advisory with its link, so every claim about it can be cited
        "advisories": [
            {
                "id": adv.get("id"),
                "summary": adv.get("summary"),
                "severity": adv.get("severity"),
                "fixed_in": adv.get("fixed_in"),
                "url": links.get(adv.get("id")) or ADVISORY_URL.format(adv.get("id")),
            }
            for adv in finding.get("advisories") or []
            if adv.get("id")
        ][:20],
        "advisory_function_names": names or "the advisories name no function",
        "imported_at": imported_at(code, project, manager, name, rules.import_aliases),
        "used_by_code": sorted({loc.get("used") for loc in locations}, key=str),
    }
    if manager != "npm" and index().trees:
        out["reachability"] = reachability(index(), import_names(name, rules.import_aliases), names, exposure())
    elif names:
        # only in the files that import the package: `parseBody(` elsewhere is someone else's parseBody
        every = imported_at(code, project, manager, name, rules.import_aliases, limit=100_000)
        importing = {w.rsplit(":", 1)[0] for w in every}
        mine = [f for f in code if _rel(f, project) in importing]
        hits = symbol_hits(mine, project, names)
        out["advisory_functions"] = {k: v for k, v in hits.items() if v} or "none of the named functions is called"
        out["advisory_functions_checked_in"] = f"{len(mine)} file(s) that import {name}"
    if locations and all(loc.get("section") == "transitive" for loc in locations):
        out["pulled_in_by"] = parents(files, name) or "not found in the lockfiles"
    return out


def _vendor_facts(a, project, files):
    vendor = re.sub(r"\s*\(.*\)$", "", a.get("item") or "").strip()
    out = {"vendor_mentions": vendor_mentions(files, project, vendor) if vendor else []}
    if vendor.lower() == "docker hub":
        out["docker_hub"] = docker_hub_use(files, project)
    return out


def _shipped_secrets(result, folder, projects, files):
    """Secrets the server judged fine (an ignored .env, or no git) that a Dockerfile still copies into an image."""
    out = []
    for s in result.get("secrets") or []:
        if s.get("exposure") != "ok" or s.get("placeholder") or s.get("project") not in projects:
            continue
        project = projects[s["project"]]
        rel = _rel(folder.parent / s["file"], project)
        images = in_image(project, files[s["project"]], rel)
        if images:
            out.append({"secret": s.get("kind"), "place": f"{rel}:{s.get('line')}", "project": s["project"],
                        "copied_into_images": images})  # fmt: skip
    return out


def facts(folder, result, done, rules):
    """{item id: facts} for every pending action item of the folder's latest result (ids as `list` numbers them),
    plus "not_listed": secrets judged fine that still ship inside an image."""
    folder = Path(folder)
    projects = {p.name: p for p in ssc_scope.projects_in(folder, rules)}
    files = {name: ssc_scope.files_in(p, rules) for name, p in projects.items()}
    findings = {(p.get("package_manager"), p.get("package"), p.get("version")): p for p in result.get("findings") or []}
    indexes, exposures, everything = {}, {}, []

    def exposure_of(name):
        if not everything:
            everything.append(ssc_scope.files_in(folder, rules))
        if name not in exposures:
            exposures[name] = deployment.exposure(folder, projects[name], files[name], everything[0])
        return exposures[name]

    def index_of(name):
        if name not in indexes:
            indexes[name] = code_index.Index(projects[name], files[name], lambda rel: category(rel) == "test")
        return indexes[name]

    out = {}
    for i, a in enumerate(result.get("actions") or [], 1):
        if a.get("key") in done:
            continue
        f = {"where": [{"place": w, "category": category(w.split(":")[0])} for w in a.get("where") or []]}
        project, pfiles = projects.get(a.get("project")), files.get(a.get("project"), [])
        if project is None:
            out[i] = {**f, "note": f"project {a.get('project')!r} is not a folder under the scanned folder"}
            continue
        f["deploys"] = deploys(project, pfiles) or ["nothing found: no deploy config, Dockerfile or CI deploy step"]
        f["exposure"] = exposure_of(a.get("project"))["summary"]  # who can reach it: details in "deployment"
        if a.get("kind") == "secret":
            f.update(_secret_facts(a, project, pfiles))
        elif a.get("kind") == "package":
            name = a.get("project")
            f.update(_package_facts(a, project, pfiles, findings, rules, lambda n=name: index_of(n),
                                    lambda n=name: exposure_of(n)))  # fmt: skip
        elif a.get("kind") == "other":
            f.update(_vendor_facts(a, project, pfiles))
        out[i] = f
    shipped = _shipped_secrets(result, folder, projects, files)
    if shipped:
        out["not_listed"] = shipped
    indexed = {n: x.summary() for n, x in indexes.items() if x.trees}
    if indexed:
        out["code_index"] = indexed  # per project: its entry points, and where it calls code by a computed name
    if exposures:
        out["deployment"] = exposures  # per project: what its deployment config says, fact by fact with file:line
    return out
