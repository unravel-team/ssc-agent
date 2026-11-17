"""One list of action items for a scan: everything the developer should do, one row each, so it can be ticked off.

    build(assessment, advice) -> [action]       summary(advice) -> the advisory's Summary text

An action is {key, priority, criticality, kind, project, item, problem, where, action, edits, sources}:
  key          stable across scans while the problem is the same (the laptop keeps ticks by it)
  priority     "block" (fix now) or "hold" (review): the rules' verdict
  criticality  Critical / High / Medium / Low: how bad it is if left alone (see the *_criticality functions)
  kind      package | secret | certificate | other
  edits     indexes into assessment["edits"] that carry out this action automatically (verified edits only)
  sources   links: [{url, text, title}]

Packages, secrets and certificates come straight from the assessment (rules, no AI). "other" rows come from the
advisor agent's "Other actions" table in ADVICE.md (for example a breached vendor whose keys to rotate).
"""

import hashlib
import re
from urllib.parse import quote

PRIORITY = {"block": 0, "hold": 1}
LEVELS = ("Critical", "High", "Medium", "Low")
RANK = {c: i for i, c in enumerate(LEVELS)}
SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}


def package_criticality(pkg):
    """Critical: malicious, or exploited in the wild. High: blocked (missing, typosquatted, pulled). Otherwise the
    worst advisory's severity; without advisories, Medium for unverified reports and internal names, Low for
    deprecation or a malicious *other* version."""
    reasons = " ".join(pkg.get("reasons") or [])
    advisories = pkg.get("advisories") or []
    if pkg.get("malicious") or "Known Exploited" in reasons or any(a.get("in_kev") for a in advisories):
        return "Critical"
    if pkg.get("verdict") == "BLOCK":
        return "High"
    worst = sorted(
        (SEVERITY[a["severity"].upper()] for a in advisories if (a.get("severity") or "").upper() in SEVERITY),
        key=RANK.get,
    )
    if worst:
        return worst[0]
    if "deprecated" in reasons or reasons.startswith("Other versions of this package were malicious"):
        return "Low"
    return "Medium"


# a dependency only used to develop and test (never shipped): npm devDependencies, Python dev/test requirement files
DEV_FILE = re.compile(
    r"(?:^|/)requirements[-_.]?(?:dev|devel|develop|test|tests|testing|lint|docs|ci)\b[^/]*\.txt$", re.I
)


# a pyproject.toml dependency group or optional extra for development ([dependency-groups], Poetry's groups and
# dev-dependencies, [project.optional-dependencies]), as the laptop reports it: "group:dev", "optional:test", ...
DEV_GROUP = re.compile(
    r"^(?:group|optional):(?:dev|devel|develop|development|test|tests|testing|lint|linting|docs?|ci|typing|types|"
    r"check|format|style)$",
    re.I,
)


def dev_only(locs):
    """Whether every place a package is declared is a development-only one."""
    return bool(locs) and all(
        f.get("section") == "devDependencies"
        or DEV_GROUP.match(str(f.get("section") or ""))
        or DEV_FILE.search(str(f.get("file") or ""))
        for f in locs
    )


def lower(level):
    """One criticality level down (Low stays Low)."""
    return LEVELS[min(RANK[level] + 1, len(LEVELS) - 1)]


KIND = {"secret": 0, "package": 1, "certificate": 2, "lockfile": 3, "other": 4}
LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
URL = re.compile(r"https?://[^\s)\"'<>]+")


def osv(vid):
    return f"https://osv.dev/vulnerability/{quote(vid)}"


def host(url):
    m = re.match(r"https?://(?:www\.)?([^/:]+)", url or "")
    return m.group(1) if m else url


def _sources(pkg):
    out = []
    for n in pkg.get("news") or []:
        out.append({"url": n.get("url"), "text": n.get("title") or host(n.get("url")), "title": n.get("source")})
    for vid in pkg.get("malicious") or []:
        out.append({"url": osv(vid), "text": vid, "title": "Malware record"})
    for vid in pkg.get("malicious_other") or []:
        out.append({"url": osv(vid), "text": vid, "title": "Malware record for other versions"})
    for a in pkg.get("advisories") or []:
        if a.get("id"):
            out.append({"url": osv(a["id"]), "text": a["id"], "title": a.get("summary")})
    for r in pkg.get("reasons") or []:
        out += [{"url": u.rstrip(".,;"), "text": host(u), "title": r} for u in URL.findall(r)]
    # always the public registry page last: the package's own facts (and, for an internal name, whether someone has
    # claimed it publicly)
    name = pkg.get("package") or ""
    if pkg.get("package_manager") == "npm":
        out.append(
            {"url": f"https://www.npmjs.com/package/{quote(name)}", "text": "npm registry", "title": f"{name} on npm"}
        )
    elif pkg.get("package_manager") == "pip":
        out.append({"url": f"https://pypi.org/project/{quote(name)}/", "text": "PyPI", "title": f"{name} on PyPI"})
    seen = set()
    return [s for s in out if (s["url"] or "").startswith("http") and not (s["url"] in seen or seen.add(s["url"]))]


def _edit_action(e):
    if e.get("new") is None:
        what = (
            f"Remove this line ({e['replace_with']} is already listed)" if e.get("replace_with") else "Remove this line"
        )
    elif e.get("change") == "replace":
        what = f"Replace with {e.get('replace_with')}"
    else:
        what = f"Change to {e.get('to')}" + (" (major upgrade: test it)" if e.get("major_upgrade") else "")
    return what


def _indirect_action(pkg):
    """What to do about a package only a lockfile lists (a dependency of a dependency): it can't be edited directly."""
    name, fix = pkg["package"], (pkg.get("fix") or {}).get("to")
    if pkg.get("malicious"):
        return (
            f"Find which package pulls in {name} {pkg.get('version')} (it is malicious) and upgrade or remove it, then "
            "regenerate the lockfile; check machines and CI that installed it, and rotate the credentials they could reach"
        )
    if not fix:
        return (
            f"Upgrade the package that pulls it in to a release that uses a fixed {name} (no fixed {name} was "
            "verified automatically), then regenerate the lockfile"
        )
    override = (
        f'force {name} {fix} with "overrides" in package.json'
        if pkg.get("package_manager") == "npm"
        else f"add {name}=={fix} as a constraint"
    )
    return f"Upgrade the package that pulls it in, or {override}; then regenerate the lockfile"


def _package_action(pkg, edits, manual):
    reasons = " ".join(pkg.get("reasons") or [])
    if edits:
        parts = sorted({_edit_action(e) for e in edits})
        text = "; ".join(parts)
        if pkg.get("malicious"):
            text += (
                f". Check machines and CI that installed {pkg['package']} {pkg['version']}: "
                "if any did, rotate the credentials they could reach"
            )
        return text
    if "exists on the PUBLIC registry" in reasons:
        return (
            "Someone has published this internal name on the public registry: make it resolve only from your private "
            "registry, check whether any machine or CI installed the public package, and report it to the registry"
        )
    if "Internal package" in reasons:
        return "Make it resolve only from your private registry, and reserve the name on the public one"
    if "Other versions of this package were malicious" in reasons:
        return "Pin this exact version in every manifest (other versions were malicious)"
    if "deprecated" in reasons:
        return "Plan a replacement: this version is deprecated"
    fix = pkg.get("fix") or {}
    # no line could be edited automatically: say what the edit would be
    check = (
        f". Check machines and CI that installed {pkg['package']} {pkg.get('version')}: "
        "if any did, rotate the credentials they could reach"
        if pkg.get("malicious")
        else ""
    )
    if fix.get("kind") == "remove":
        return "Remove this dependency" + check
    if fix.get("kind") == "replace" and fix.get("with"):
        return f"Replace it with {fix['with']}" + check
    if fix.get("to") and fix.get("verified"):
        major = " (major upgrade: test it)" if fix.get("major_upgrade") else ""
        return f"Change to {fix['to']}{major}" + check
    if fix.get("to") and not fix.get("verified"):
        return f"Choose a safe version and pin it exactly ({fix['to']} was proposed but could not be verified)"
    if pkg.get("advisories") and not fix.get("to"):
        return (
            "No fixed version exists: replace it with a maintained alternative, or remove it if it isn't needed" + check
        )
    note = next((m["action"] for m in manual if not m["action"].startswith("review:")), None)
    return note or "Check the reports against advisories before relying on this version"


def _problem(pkg):
    """The main reason, said shortly when the action already explains it."""
    first = (pkg.get("reasons") or [""])[0]
    if "exists on the PUBLIC registry" in first:
        return "Internal name already registered on the public registry by someone else (dependency confusion)"
    if first.startswith("Internal package"):
        return "Internal name: someone could publish it on the public registry (dependency confusion)"
    if first.startswith("Version is deprecated"):
        return "Deprecated by its maintainers"
    return first


def _packages(a):
    edits = list(enumerate(a.get("edits") or []))
    manual = a.get("manual") or []
    out = []
    for pkg in a.get("packages") or []:
        if pkg.get("verdict") not in ("BLOCK", "HOLD"):
            continue
        by_project = {}
        for f in pkg.get("found_in") or []:
            by_project.setdefault(f.get("project") or "?", []).append(f)
        for project, locs in sorted(by_project.items()):
            indirect = all(f.get("section") == "transitive" for f in locs)
            # a package only a lockfile lists gets a row for hard evidence only (malware, an advisory, a block):
            # deprecation, install scripts, a similar name or news about it are the parent package's business
            if indirect and not (pkg.get("malicious") or pkg.get("advisories") or pkg.get("verdict") == "BLOCK"):
                continue
            mine = [
                (i, e)
                for i, e in edits
                if e.get("package") == pkg["package"]
                and e.get("package_manager") == pkg.get("package_manager")
                and e.get("from") == pkg.get("version")
                and (e.get("project") or "?") == project
            ]
            ready = [(i, e) for i, e in mine if e.get("verified")]
            pm = [m for m in manual if m.get("package") == pkg["package"] and m.get("version") == pkg.get("version")]
            # used only to develop: a bug in it is one level less urgent, since it never ships. What may be malicious
            # code is not (malware, and every BLOCK: a lookalike name, a public copy of an internal name, a pulled
            # version): a dev tool runs on developers' machines and in CI, where the credentials are
            dev = not indirect and dev_only(locs)
            # not used: no code imports it and no run command starts it (the laptop's yes/no, never the code). A
            # heuristic, since a framework may load a package by name (a database driver, a plugin): one level
            # down, never hidden. Dev-only and unused together still count once
            unused = not indirect and not dev and all(f.get("used") is False for f in locs)
            criticality = package_criticality(pkg)
            if (dev or unused) and not pkg.get("malicious") and pkg.get("verdict") != "BLOCK":
                criticality = lower(criticality)
            problem = (_problem(pkg) + " · pulled in by another package") if indirect else _problem(pkg)
            out.append(
                {
                    "key": f"package:{pkg.get('package_manager')}:{pkg['package']}@{pkg.get('version')}:{project}",
                    "priority": "block" if pkg["verdict"] == "BLOCK" else "hold",
                    "criticality": criticality,
                    "kind": "package",
                    "project": project,
                    "item": f"{pkg['package']} {pkg.get('version') or ''}".strip(),
                    "problem": problem
                    + (" · used only in development" if dev else "")
                    + (" · not imported or run by the code (another package may still load it)" if unused else ""),
                    "where": sorted(
                        {_rel(f.get("file"), project) + (f":{f['line']}" if f.get("line") else "") for f in locs}
                    ),
                    "action": _indirect_action(pkg) if indirect else _package_action(pkg, [e for _, e in ready], pm),
                    "edits": [i for i, _ in ready],
                    "sources": _sources(pkg),
                }
            )
    return out


def _rel(path, project):
    parts = (path or "").split("/")
    return "/".join(parts[parts.index(project) + 1 :]) if project in parts else "/".join(parts[-2:])


SECRET_ROWS = {  # exposure (scans.secret_exposure) -> (criticality, priority, problem)
    "committed": ("Critical", "block", "Real secret committed to git"),
    "in_code": ("High", "block", "Real secret in source code"),
    "not_ignored": ("Medium", "hold", "Real secret in a file git doesn't ignore"),
}


def _secrets(a):
    """One row per secret that needs something done. A real secret in a .env file git ignores is where it belongs:
    no row (an older assessment without `exposure` counts as committed when git tracks it, else as in a file)."""
    out = []
    for s in a.get("secrets") or []:
        exposure = s.get("exposure") or ("committed" if s.get("tracked") else "in_code")
        if s.get("placeholder") or exposure not in SECRET_ROWS:
            continue
        criticality, priority, problem = SECRET_ROWS[exposure]
        project = s.get("project") or "?"
        where = f"{_rel(s.get('file'), project)}:{s.get('line')}"
        out.append(
            {
                "key": f"secret:{project}:{where}:{s.get('kind')}",
                "priority": priority,
                "criticality": criticality,
                "kind": "secret",
                "project": project,
                "item": s.get("kind") or "Secret",
                "problem": problem,
                "where": [where],
                "action": s.get("action") or "Rotate it with the provider, then remove it from the file",
                "edits": [],
                "sources": [],
            }
        )
    return out


def _certificates(a):
    out = []
    for c in a.get("certificates") or []:
        if c.get("status") not in ("distrusted", "reported"):
            continue
        files = c.get("files") or [{}]
        project = files[0].get("project") or "?"
        out.append(
            {
                "key": f"certificate:{c.get('ca')}",
                "priority": "block" if c["status"] == "distrusted" else "hold",
                "criticality": "High" if c["status"] == "distrusted" else "Medium",
                "kind": "certificate",
                "project": project,
                "item": f"{c.get('ca')} (certificate authority)",
                "problem": (c.get("reasons") or [""])[0],
                "where": [_rel(f.get("file"), f.get("project") or "?") for f in files if f.get("file")],
                "action": "Replace this CA and stop trusting it"
                if c["status"] == "distrusted"
                else "Check the reports and plan replacing this CA",
                "edits": [],
                "sources": [
                    {"url": e.get("url"), "text": e.get("title"), "title": f"{e.get('source')} {e.get('date')}"}
                    for e in c.get("evidence") or []
                    if (e.get("url") or "").startswith("http")
                ],
            }
        )
    return out


LOCKS = {
    "npm": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"),
    "pip": ("uv.lock", "requirements.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"),  # requirements.lock: hashed
}
LOCK_ACTION = {
    "npm": "Add a lockfile and commit it (npm install --package-lock-only, or bun / pnpm / yarn install), then "
    "install from it only: npm ci (bun install --frozen-lockfile)",
    "pip": "Lock with hashes and commit the lockfile (uv lock, or pip-compile --generate-hashes), then install from "
    "it only (uv sync --frozen, or pip install --require-hashes -r requirements.txt)",
}
LOCK_DOCS = {
    "npm": {"url": "https://docs.npmjs.com/cli/commands/npm-ci", "text": "npm ci (npm docs)", "title": "npm docs"},
    "pip": {
        "url": "https://pip.pypa.io/en/stable/topics/secure-installs/",
        "text": "Secure installs (pip docs)",
        "title": "pip docs",
    },
}


def _lockfiles(a):
    """A project whose npm or Python dependencies have no lockfile: every install may resolve a different version,
    including a newly published malicious one, and nothing checks the downloaded files against known hashes."""
    used = {}
    for pkg in a.get("packages") or []:
        for f in pkg.get("found_in") or []:
            used.setdefault((f.get("project"), pkg.get("package_manager")), set()).add(f.get("file"))
    out = []
    for p in a.get("projects") or []:
        name, locks = p.get("project"), {str(x).rsplit("/", 1)[-1] for x in p.get("lockfiles") or []}
        for pm, label in (("npm", "npm"), ("pip", "Python")):
            files = used.get((name, pm))
            if not files or locks & set(LOCKS[pm]):
                continue
            out.append(
                {
                    "key": f"lockfile:{name}:{pm}",
                    "priority": "hold",
                    "criticality": "Low",
                    "kind": "lockfile",
                    "project": name,
                    "item": f"No {label} lockfile",
                    "problem": "Each install can pick a different version, including a newly published malicious "
                    "one, and downloads are not checked against known hashes",
                    "where": sorted(_rel(f, name) for f in files),
                    "action": LOCK_ACTION[pm],
                    "edits": [],
                    "sources": [LOCK_DOCS[pm]],
                }
            )
    return out


def _section(advice, title):
    m = re.search(rf"^#{{1,3}}\s+{title}\s*$(.*?)(?=^#{{1,3}}\s|\Z)", advice or "", re.M | re.S | re.I)
    return m.group(1).strip() if m else ""


def summary(advice):
    """The advisory's Summary section, or the whole text when it has none (an older advisory)."""
    return _section(advice, "Summary") or (advice or "").strip()


def other_key(project, item):
    """The key of an agent row. The agent words items a little differently each time ("litellm 1.107.0 (malicious
    release)", "litellm (1.107.0 was malicious)"), so the key keeps only the words that name the thing: no notes in
    brackets, no version numbers, no punctuation. The developer's tick is kept by it."""
    subject = re.sub(r"\([^)]*\)", " ", item.lower())
    words = [w for w in re.findall(r"[a-z0-9@/._-]+", subject) if not re.match(r"v?\d", w)]
    name = " ".join(words) or item.lower()
    return "other:" + hashlib.sha256(f"{project.lower()}|{name}".encode()).hexdigest()[:12]


def _cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _titles(a):
    """{url: headline} for every article, notice and post in the assessment (what the agent can cite)."""
    out = {}
    for v in a.get("vendors") or []:
        for r in v.get("records") or []:
            out[r.get("url")] = r.get("title")
    for p in a.get("packages") or []:
        for n in p.get("news") or []:
            out[n.get("url")] = n.get("title")
    for c in a.get("certificates") or []:
        for e in c.get("evidence") or []:
            out[e.get("url")] = e.get("title")
    return {u: t for u, t in out.items() if u and t}


def _slug_title(url):
    """The headline most news sites put in the address: ".../railway-warns-devs-to-rotate-secrets/" ->
    "Railway warns devs to rotate secrets". None when the address has no such words."""
    last = [p for p in re.sub(r"[?#].*", "", url or "").split("/") if p][-1:] or [""]
    words = re.sub(r"\.(html?|php|aspx?)$", "", last[0]).split("-")
    if len(words) < 3 or not all(w.isalnum() for w in words) or sum(w.isdigit() for w in words) > len(words) // 2:
        return None
    text = " ".join(words)
    return text[0].upper() + text[1:]


def _link(url, text, titles):
    """A source link named by what it is: the article's headline when known, else the link text the agent gave."""
    title = titles.get(url)
    if title and title.startswith("Breach notice"):  # a notice's own title is generic: use the article's
        title = f"{_slug_title(url) or title} ({host(url)})"
    return {"url": url, "text": title or text, "title": title or text}


def _other(advice, titles=None):
    """Rows of the agent's "Other actions" table: | project | item | criticality | action | source | (an older advisory
    has no criticality column: Medium)."""
    out = []
    for line in _section(advice, "Other actions").splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = _cells(line)
        header = cells[0].lower() == "project" and cells[1].lower() == "item"  # a project may be named "project"
        if len(cells) < 3 or set("".join(cells)) <= set("-: ") or header:
            continue
        level = next((x for x in LEVELS if len(cells) >= 5 and cells[2].strip("* ").lower() == x.lower()), None)
        project, item = cells[0], cells[1]
        action, src = (cells[3], " ".join(cells[4:])) if level else (cells[2], " ".join(cells[3:]))
        titles = titles or {}
        links = [_link(u, t, titles) for t, u in LINK.findall(src)]
        links += [_link(u, host(u), titles) for u in URL.findall(LINK.sub("", src))]
        plain = LINK.sub(r"\1", item)
        # one project per row, so each can be ticked on its own: "api, web" becomes a row for each
        names = [p.strip() for p in re.split(r",|&|\s+and\s+", project) if p.strip()] or [project]
        out += [_other_row(name, plain, level, action, links) for name in names]
    return out


def _other_row(project, plain, level, action, links):
    return {
        "key": other_key(project, plain),
        "priority": "hold",
        "criticality": level or "Medium",
        "kind": "other",
        "project": project,
        "item": plain,
        "problem": "",
        "where": [],
        "action": LINK.sub(r"\1", action),
        "edits": [],
        "sources": links,
    }


def _structured(advice_data):
    """The agents' rows from structured advice (engine/advice.py): already checked, with their sources resolved."""
    return [
        _other_row(r["project"], r["item"], r["criticality"], r["action"], r["sources"])
        for r in (advice_data or {}).get("other_actions") or []
    ]


def build(assessment, advice=None, advice_data=None):
    """Every action item: the rules' own, then the agents' rows (from structured advice when there is some, else
    from the Other actions table of an older markdown advisory)."""
    rows = (
        _secrets(assessment)
        + _packages(assessment)
        + _certificates(assessment)
        + _lockfiles(assessment)
        + (_structured(advice_data) if advice_data else _other(advice, _titles(assessment)))
    )
    return sorted(
        rows,
        key=lambda r: (
            PRIORITY[r["priority"]],
            RANK[r["criticality"]],
            KIND[r["kind"]],
            r["project"],
            r["item"].lower(),
        ),
    )
