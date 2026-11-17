"""Package lookups: registry facts, typosquat distance, advisories and malware history (OSV, OpenSSF,
CISA KEV, VulnCheck KEV, FIRST EPSS, plus every PackageSource in the registry), and social posts.

This is the evidence the dependency gatekeeper's rules decide on. The sources API collects it for its
database; the gatekeeper imports these same functions for direct lookups, so evidence is identical either way.
Read-only: nothing is installed or run.
"""

import json
import os
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from ..sources import registry as SR
from . import connectors as L

UA = {"User-Agent": "ssc-intel-api/1"}
NOW = datetime.now(timezone.utc)


def get(url, data=None, timeout=20):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode() if data else None,
        headers={**UA, **({"Content-Type": "application/json"} if data else {})},
    )
    if "api.github.com" in url and os.environ.get("GITHUB_TOKEN"):
        req.add_header("Authorization", "Bearer " + os.environ["GITHUB_TOKEN"])
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "null")
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:  # noqa: BLE001 - network issues are evidence too ("registry unreachable")
        return 0, {"error": str(e)}


def lev(a, b):
    """Edit distance where swapping two adjacent letters counts as one edit (optimal string alignment)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] != b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def age_days(iso):
    try:
        d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (TypeError, ValueError, AttributeError):
        return None
    if d.tzinfo is None:  # registries give UTC; never mix naive and aware datetimes
        d = d.replace(tzinfo=timezone.utc)
    return (NOW - d).total_seconds() / 86400


def _missing_or_unknown(out, status):
    """Only a 404 proves a package doesn't exist. Timeouts, rate limits and outages mean we couldn't check."""
    if status != 404:
        out["unverified"] = (
            f"registry unreachable (HTTP {status})" if status else "registry unreachable (network error)"
        )
    return out


# Functions and APIs an advisory names: `code spans`, calls like yaml.load( or zipObjectDeep(), dotted names
# (lodash.template). The Claude plugin searches the project's code for them: an advisory about a function the code
# never calls matters less.
_CODE_SPAN = re.compile(r"`([A-Za-z_$][\w$.]*)(?:\(\))?`")
_CALL = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(\)")
_DOTTED = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\(")
_IDENT = re.compile(r"\b([a-z][a-z0-9]*_[a-z0-9_]*[a-z0-9]|[a-z]+[A-Z][A-Za-z0-9]+)\b")  # full_load, zipObjectDeep
_NOT_SYMBOLS = {"e.g", "i.e", "etc", "node.js", "next.js", "vue.js", "nuxt.js", "express.js"}


# language built-ins that advisories use in examples: never the affected API
_BUILTIN = re.compile(
    r"^(console|date|object|array|json|math|promise|string|number|window|document|process|module|exports|this|self|"
    r"os|sys|re|buffer|reflect|symbol|function)(\.|$)",
    re.I,
)


def symbols(text, package="", limit=8):
    """The function and API names an advisory's text names, in order, without duplicates. Left out: a bare lower-case
    word ("load", "trim": too common to search for), language built-ins (console.log, Object.prototype), and the
    package's own name."""
    out = []
    for rx in (_CODE_SPAN, _CALL, _DOTTED, _IDENT):
        for m in rx.finditer(text or ""):
            name = m.group(1).strip(".")
            plain = "." not in name and "_" not in name and name.islower()
            if (
                plain
                or ".." in name
                or len(name) < 3
                or name.lower() in _NOT_SYMBOLS
                or name.lower() == package.lower()
                or _BUILTIN.match(name)
                or re.fullmatch(r"[\d.]+", name)
            ):
                continue
            if name not in out:
                out.append(name)
    return out[:limit]


_PEP440 = re.compile(r"^v?(\d+(?:\.\d+)*)(.*)$", re.I)


def pep440_key(version):
    """A Python version in the form PEP 440 compares: 4.2.0, 4.2 and v4.2 are one release; 1.0RC1 is 1.0rc1."""
    m = _PEP440.match(str(version).strip())
    if not m:
        return str(version).strip().lower()
    release = [int(x) for x in m.group(1).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    rest = re.sub(r"[-_.]", "", m.group(2).lower()).replace("alpha", "a").replace("beta", "b").replace("c", "rc", 1)
    rest = rest.replace("rrc", "rc").replace("preview", "rc").replace("pre", "rc")
    return ".".join(map(str, release)) + rest


def registry(dep):
    """Identity & metadata signals."""
    out = {"exists": False}
    if dep["ecosystem"] == "PyPI":
        st, d = get(f"https://pypi.org/pypi/{urllib.parse.quote(dep['name'], safe='')}/json")
        if st != 200 or not d:
            return _missing_or_unknown(out, st)
        rel = d.get("releases", {})
        times = [f["upload_time_iso_8601"] for files in rel.values() for f in files if f.get("upload_time_iso_8601")]
        out.update(
            exists=True,
            latest=d["info"].get("version"),
            release_count=len(rel),
            first_release_days=round(age_days(min(times)), 1) if times else None,
            author=d["info"].get("author") or d["info"].get("maintainer"),
            summary=(d["info"].get("summary") or "")[:140],
        )
        if dep["version"]:
            files = rel.get(dep["version"])
            if files is None:  # the same release spelled another way: 4.2.0 is PyPI's 4.2 (PEP 440)
                want = pep440_key(dep["version"])
                files = next((f for k, f in rel.items() if pep440_key(k) == want), None)
            out["version_exists"] = bool(files)
            out["version_yanked"] = bool(files) and all(f.get("yanked") for f in files)
            if files:
                out["version_age_days"] = round(age_days(files[0]["upload_time_iso_8601"]), 2)
    else:
        st, d = get("https://registry.npmjs.org/" + urllib.parse.quote(dep["name"], safe="@"))
        if st != 200 or not d or "versions" not in d:
            return _missing_or_unknown(out, st)
        t = d.get("time", {})
        out.update(
            exists=True,
            latest=(d.get("dist-tags") or {}).get("latest"),
            release_count=len(d["versions"]),
            first_release_days=round(age_days(t["created"]), 1) if t.get("created") else None,
            maintainers=[m.get("name") for m in d.get("maintainers", [])][:5],
            summary=(d.get("description") or "")[:140],
        )
        v = d["versions"].get(dep["version"]) if dep["version"] else None
        out["version_exists"] = v is not None
        if v:
            scripts = {
                k: s for k, s in (v.get("scripts") or {}).items() if k in ("preinstall", "install", "postinstall")
            }
            out["install_scripts"] = scripts
            out["deprecated"] = v.get("deprecated")
            if t.get(dep["version"]):
                out["version_age_days"] = round(age_days(t[dep["version"]]), 2)
    return out


_RANK = {}


def ranks(ecosystem):
    """Live popularity ranking {name: rank} (top PyPI 5000 / npm search), cached for 24h."""
    r = _RANK.get(ecosystem)  # read once: the sources API may swap _RANK for a fresh dict at any time
    if r is None:
        r = {n.lower(): i for i, n in enumerate(L.popular(ecosystem, 5000))}
        _RANK[ecosystem] = r
    return r


def typosquat(dep):
    """Names within edit distance of a popular package that has >=100x our weekly downloads (live data). A package
    that is itself popular is never a typosquat, and on npm one whose downloads can't be read isn't called one."""
    name = dep["name"].lower()
    if len(name) <= 3:
        return []
    r = ranks(dep["ecosystem"])
    if name in r:
        return []
    max_d = 1 if len(name) < 8 else 2
    near = sorted(
        (rank, o) for o, rank in r.items() if o != name and abs(len(o) - len(name)) <= max_d and lev(name, o) <= max_d
    )[:5]
    if not near:
        return []
    mine = L.weekly_downloads(dep["ecosystem"], name)
    if mine is None and dep["ecosystem"] == "npm":
        return []  # npm reports 0 for unpopular packages, so unknown means the lookup failed: not evidence of a fake
    mine = mine or 0  # PyPI's stats have no entry for new packages: those count as unpopular
    hits = []
    for _, other in near:
        theirs = L.weekly_downloads(dep["ecosystem"], other) or 0
        if theirs >= 100 * max(mine, 1):
            hits.append(other)
    return hits[:3]


MAL_HISTORY = {}  # (ecosystem, name) -> [MAL- ids], filled in one OSV batch call by main()


_KEV = None


def kev_set():
    global _KEV
    if _KEV is None:
        st, d = get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=40)
        _KEV = {v["cveID"] for v in (d or {}).get("vulnerabilities", [])} if st == 200 else set()
    return _KEV


def vulns(dep):
    """CVE / SCA signals from OSV (includes MAL- malicious package advisories), the OpenSSF
    Malicious Packages repo, CISA KEV, VulnCheck KEV and FIRST EPSS."""
    out = []
    if dep["version"]:
        st, d = get(
            "https://api.osv.dev/v1/query",
            {"package": {"name": dep["name"], "ecosystem": dep["ecosystem"]}, "version": dep["version"]},
        )
        for v in (d or {}).get("vulns", []) if st == 200 else []:
            aliases = v.get("aliases", [])
            cves = [a for a in [*aliases, v["id"]] if a.startswith("CVE-")]
            sev = (v.get("database_specific") or {}).get("severity")
            fixed = sorted(
                {
                    e["fixed"]
                    for a in v.get("affected", [])
                    for r in a.get("ranges", [])
                    for e in r.get("events", [])
                    if "fixed" in e
                }
            )
            out.append(
                {
                    "id": v["id"],
                    "source": "OSV",
                    "cves": cves,
                    "summary": (v.get("summary") or v.get("details", ""))[:160],
                    "symbols": symbols(f"{v.get('summary') or ''}\n{v.get('details') or ''}", dep["name"]),
                    "severity": sev,
                    "malicious": v["id"].startswith("MAL-"),
                    "fixed_in": fixed[:3],
                    "published": (v.get("published") or "")[:10] or None,
                    "in_kev": any(c in kev_set() for c in cves),
                }
            )
    seen = {v["id"] for v in out}
    # OSV malware history: MAL- entries for ANY version of this package (OSV mirrors OpenSSF's malicious-packages data)
    key = (dep["ecosystem"], dep["name"].lower())
    hist = MAL_HISTORY.get(key)
    if hist is None:
        hist = [i for i in L.osv_batch([dep], with_version=False)[0] if i.startswith("MAL-")]
    for mid in hist:
        if mid in seen:
            continue
        rec = L.fetch("https://api.osv.dev/v1/vulns/" + mid, "OSV") or {}
        versions = sorted({v for a in rec.get("affected", []) for v in a.get("versions", [])})
        hits = L.osv_affects(rec, dep["version"])
        out.append(
            {
                "id": mid,
                "source": "OSV",
                "cves": [],
                "summary": (rec.get("summary") or rec.get("details") or "")[:160],
                "severity": "CRITICAL" if hits else None,
                "malicious": hits,
                "malicious_other_version": not hits,
                "fixed_in": [],
                "in_kev": False,
                "url": "https://osv.dev/vulnerability/" + mid,
                "versions": versions[:20],
                "ranges": L.osv_ranges(rec),
                "published": (rec.get("published") or "")[:10] or None,
            }
        )
        seen.add(mid)
    # OpenSSF Malicious Packages repo (direct; needs GITHUB_TOKEN at scale): checked even without a version
    for m in L.ossf_malicious(dep["ecosystem"], dep["name"]):
        hits = L.osv_affects({"affected": m["affected"]}, dep["version"])
        if m["id"] in seen:
            next(v for v in out if v["id"] == m["id"])["source"] += " + OpenSSF"
        else:
            out.append(
                {
                    "id": m["id"],
                    "source": "OpenSSF Malicious Packages",
                    "cves": [],
                    "summary": m["summary"][:160],
                    "severity": "CRITICAL" if hits else None,
                    "malicious": hits,
                    "malicious_other_version": not hits,
                    "fixed_in": [],
                    "in_kev": False,
                    "url": m["url"],
                    "versions": m["versions"],
                    "ranges": m["ranges"],
                    "published": m.get("published") or None,
                }
            )
    cves = sorted({c for v in out for c in v["cves"]})
    if cves:
        st, e = get("https://api.first.org/data/v1/epss?cve=" + ",".join(cves[:50]))
        epss = {x["cve"]: float(x["epss"]) for x in (e or {}).get("data", [])} if st == 200 else {}
        vc = L.vulncheck_kev(cves)
        for v in out:
            v["epss_max"] = max([epss.get(c, 0.0) for c in v["cves"]] or [0.0])
            v["in_vulncheck_kev"] = any(c in vc for c in v["cves"])
    return out


def vulns_all(dep):
    """vulns() plus findings from every PackageSource registered under intel_api/sources/."""
    out = vulns(dep)
    return out + SR.package_findings(dep, exclude_ids={v["id"] for v in out})


def source_may_block(label):
    """Can findings from this source BLOCK on their own? (rating from intel_api/config/sources.json or the source class)"""
    parts = [p.strip() for p in label.split(" + ")]
    for p in parts:
        s = next((x for x in SR.all_sources().values() if x.label == p), None)
        if s.may_block if s else L.may_block(p):
            return True
    return False


def other_version(title, version):
    """True if the post names a specific version that is not ours."""
    vs = re.findall(r"\b\d+\.\d+(?:\.\d+)?\b", title)
    return bool(vs) and version not in vs


PKG_CONTEXT = re.compile(
    r"\b(npm|pypi|package|library|python|javascript|node\.?js|dependency|supply[- ]chain|open[- ]source|pip)\b", re.I
)
_DICT = None


def common_word(name):
    global _DICT
    words = _DICT
    if words is None:  # built whole, then published: another thread never sees a half-read (or empty) list
        words = set()
        if os.path.exists("/usr/share/dict/words"):
            with open("/usr/share/dict/words", encoding="utf-8", errors="replace") as f:
                words = {word.strip().lower() for word in f}
        _DICT = words
    return name.lower() in words


def social(dep):
    """Live community signals: Hacker News, GitHub issues, Mastodon, Bluesky*, X* (*when credentials are set)."""
    posts = SR.search("social", term=dep["name"], days=120)
    if common_word(dep["name"]):
        posts = [p for p in posts if PKG_CONTEXT.search(p["title"])]
    for p in posts:
        p["other_version"] = other_version(p["title"], dep["version"] or "")
    return posts
