"""Flatten every signal, from every source, into rows of the generic `items` table.

One row per item x subject x version, with package manager, package, version, CVE/advisory id, link,
dates, source and rating. Package and vendor subjects come from the source itself (malware feed,
advisories, KEV, breach notices) or, for news and social posts, from the text:

  - explicit mentions:  "npm package foo", "PyPI library 'bar'", `npm install foo`, `pip install bar`,
                        foo@1.2.3 (npm), bar==1.2.3 (PyPI)
  - watched names:      packages and vendors on any registered repo's watchlist
  - versions:           written right after a package's name ("pushed axios 1.14.1 and 0.30.4")

For direct article links that look security-related, the article page is read once (the signal is marked
article_checked) so versions that only appear in the body are found too.
"""

import json
import os
import re
from functools import lru_cache

from .._paths import CONFIG_DIR, L
from ..lib import packages as P

ECO_WORDS = {
    "npm": "npm",
    "javascript": "npm",
    "node.js": "npm",
    "nodejs": "npm",
    "node": "npm",
    "pypi": "PyPI",
    "pip": "PyPI",
    "python": "PyPI",
}
PM = {"npm": "npm", "PyPI": "pip"}
_ECO = r"(?P<eco>npm|PyPI|pip|Python|JavaScript|Node\.?js)"
_NAME = r"(?P<name>@?[a-z0-9][a-z0-9._\-]*(?:/[a-z0-9._\-]+)?)"
_Q = "[\"'“”‘’`]"
PATTERNS = [  # (regex, ecosystem or None = from the <eco> group, match label, confidence)
    (
        re.compile(rf"\b{_ECO}\s+(?:package|library|module|dependency)s?\s+(?:called\s+|named\s+)?{_Q}?{_NAME}", re.I),
        None,
        "named_package",
        "high",
    ),
    (
        re.compile(rf"{_Q}{_NAME}{_Q}\s+(?:{_ECO}\s+)?(?:package|library|module)", re.I),
        None,
        "quoted_package",
        "medium",
    ),
    (
        re.compile(
            rf"\b(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install)|bun\s+add|npx)\s+(?:-[\w-]+\s+)*{_NAME}",
            re.I,
        ),
        "npm",
        "install_command",
        "high",
    ),
    (
        re.compile(
            rf"\b(?:pip3?\s+install|uv\s+(?:add|pip\s+install)|poetry\s+add|pipx\s+install)\s+(?:-[\w-]+\s+)*{_NAME}",
            re.I,
        ),
        "PyPI",
        "install_command",
        "high",
    ),
    (
        re.compile(
            r"(?<![\w.@/])(?P<name>@?[a-z0-9][a-z0-9._\-]*(?:/[a-z0-9._\-]+)?)@(?P<ver>\d+\.\d+\.\d+[\w.\-]*)", re.I
        ),
        "npm",
        "name@version",
        "high",
    ),
    (re.compile(r"\b(?P<name>[a-z0-9][a-z0-9._\-]*)==(?P<ver>\d+[\w.\-]*)", re.I), "PyPI", "name==version", "high"),
]
STOP = set(
    """
a an the and or of for to in on at by with from that which this these those it its is was were be been has have
had called named new latest popular malicious compromised fake rogue legitimate official open source package
packages library libraries module modules manager registry ecosystem maintainer maintainers users developers
dependency dependencies version versions update updates supply chain attack attacks malware account accounts
repository repositories index npm pypi pip python javascript node install add i x dlx exec run use uses used
using target targets targeting steal steals stealing deliver delivers drop drops dropping found spotted
discovered hit hits abuse abuses abusing are were can could may might will would via also now again here there
then than into over after before about
""".split()
)
CONTEXT_NEAR = re.compile(
    r"\b(npm|pypi|pip|packages?|library|libraries|modules?|sdks?|dependenc(y|ies)|install(ed|s)?|maintainers?|registry|"
    r"python|javascript|node\.?js|typosquat\w*|supply[- ]chain|versions?)\b",
    re.I,
)
VERSION = re.compile(r"v?(\d{1,4}\.\d{1,4}(?:\.\d{1,6})?(?:[-+][0-9A-Za-z.]+)?)")


def _ok_name(n):
    n = n.strip(".-_").lower()
    return n if n and n not in STOP and not n.isdigit() and len(n) <= 214 and not re.fullmatch(r"\d[\d.]*", n) else None


FIXED_BEFORE = re.compile(
    r"(fixed|patched|resolved|addressed)\s+in\s+(version\s+)?$|(upgrade|update)\s+to\s+(version\s+)?$|pin(ned)?\s+(to\s+)?$",
    re.I,
)
FILLER = {
    "and",
    "or",
    "&",
    "version",
    "versions",
    "ver",
    "v",
    "release",
    "releases",
    "through",
    "to",
    "-",
    "\u2013",
    "package",
    "library",
    "module",
    "pkg",
    "is",
    "was",
    "at",
}


def _clean_version(v):
    return v.rstrip(".-+,;:)")


def _versions_after(text, start, end, limit=8):
    """The unbroken list of versions written right after a mention ("axios 1.14.1 and 0.30.4 to npm" -> both).
    Stops at the first ordinary word, so a version that belongs to the next package isn't taken."""
    out = []
    for tok in text[end : end + 120].split():
        bare = tok.strip(",;:()[]\"'\u201c\u201d")
        m = VERSION.fullmatch(bare.rstrip("."))
        if m:
            v = _clean_version(m.group(1))
            if v.count(".") <= 3 and not re.fullmatch(r"(19|20)\d\d\.\d\d?", v):
                out.append(v)
            if len(out) >= limit or (tok.endswith((".", ";", ")")) and not VERSION.fullmatch(tok)):
                break
            continue
        if bare.lower() in FILLER and not (bare.lower() == "to" and out):
            continue
        break
    return out


def _snippet(text, start, end):
    return " ".join(text[max(0, start - 100) : end + 120].split())


def watch_names(store):
    """{(ecosystem, name_lower): display} and {vendor term: vendor} to look for in text: the scope's packages and
    vendors (config/scope.json) plus every package looked up through the API."""
    from ..core import scope as scope_mod

    sc = scope_mod.load(store)
    pkgs = {k: v["name"] for k, v in sc.packages.items()}
    for eco, n in store.evidence_packages():
        pkgs.setdefault((eco, n), n)
    vendors = {t.lower(): v["name"] for v in sc.vendors for t in v["terms"]}
    return pkgs, vendors


# everyday words the system dictionary (/usr/share/dict/words) is too old to know
MODERN_WORDS = set(
    """
email app online website login logout cookie token download upload update blog inbox spam bot chat cloud server
browser wifi smartphone podcast hashtag username password phishing malware ransomware crypto bitcoin blockchain
webhook api sdk cli internet startup gamer selfie emoji vlog stream streaming
""".split()
)


@lru_cache(maxsize=1)
def brand_names():
    """Company and product names the laptop scanner knows as vendors (config/scanner_rules.json), as a package would
    spell them: "openai", "anthropic", "huggingface", "hugging-face"."""
    try:
        with open(os.path.join(CONFIG_DIR, "scanner_rules.json"), encoding="utf-8") as f:
            rules = json.load(f)
    except (OSError, ValueError):
        return frozenset()
    names = set()

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k in ("vendor", "name") and isinstance(v, str):
                    names.add(v.lower())
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk({k: v for k, v in rules.items() if not k.startswith("secret")})
    return frozenset(n.replace(" ", sep) for n in names for sep in (" ", "", "-"))


def english(name):
    """An ordinary word ("coverage", "click", "requests", "emails"): only a package when the text around it says so."""
    g = P
    n = name.lower()
    stems = {n, n[:-1] if n.endswith("s") else n, n[:-2] if n.endswith("es") else n}
    return any(g.common_word(w) or w in MODERN_WORDS for w in stems)


GOOGLE_PUBLISHER = re.compile(r"\s+-\s+[^-]{2,80}$")
EXTENSION_CONTEXT = re.compile(r"\b(extension|VS ?Code|Open ?VSX|marketplace|Cursor)\b", re.I)


def _near(rx, text, s, e, width=80):
    return bool(rx.search(text[max(0, s - width) : s]) or rx.search(text[e : e + width]))


def _context_near(text, s, e, width=80):
    return _near(CONTEXT_NEAR, text, s, e, width)


def extract(title, summary="", article="", watched_pkgs=None, watched_vendors=None):
    """Package and vendor mentions in a news/social item -> [{subject_type, ecosystem, name, version, version_role, match,
    confidence, snippet}]. title/summary are the feed's own text; article is the page body (stricter rules: it is long
    and mentions many things in passing)."""
    text = f"{title}\n{summary or ''}\n{article or ''}"
    lead_end = len(title) + 1 + len(summary or "")  # title + summary
    found = {}

    def add(subject_type, eco, name, versions, match, conf, s, e):
        role = (
            "fixed"
            if versions and FIXED_BEFORE.search(text[max(0, s - 30) : s])
            else ("mentioned" if versions else None)
        )
        for v in versions or [None]:
            k = (subject_type, eco, name.lower(), v)
            if k not in found or (found[k]["confidence"] != "high" and conf == "high"):
                found[k] = {
                    "subject_type": subject_type,
                    "ecosystem": eco,
                    "name": name,
                    "version": v,
                    "version_role": role,
                    "match": match,
                    "confidence": conf,
                    "snippet": _snippet(text, s, e),
                }

    for rx, eco_fixed, label, conf in PATTERNS:
        for m in rx.finditer(text):
            name = _ok_name(m.group("name"))
            if not name:
                continue
            if (
                label == "name@version"
                and "." in name.split("/")[-1]
                and _near(EXTENSION_CONTEXT, text, m.start(), m.end())
            ):
                continue  # publisher.extension@1.2.3: an editor extension, not an npm package
            quoted = text[max(0, m.start("name") - 1) : m.start("name")] in "\"'\u201c\u2018`" and m.start("name") > 0
            if label in ("named_package", "quoted_package") and english(name) and not quoted:
                continue  # "npm packages Use ..." / "npm package manager"
            eco = eco_fixed or ECO_WORDS.get((m.groupdict().get("eco") or "").lower())
            if not eco and name in {n for _, n in (watched_pkgs or {})}:
                eco = next(e for e, n in watched_pkgs if n == name)
            if not eco:
                continue
            vers = (
                [_clean_version(m.group("ver"))]
                if "ver" in m.groupdict() and m.group("ver")
                else _versions_after(text, m.start(), m.end())
            )
            add("package", eco, name, vers, label, conf if m.start() < lead_end else "medium", m.start(), m.end())
    vendor_terms = {t.lower() for t in watched_vendors or {}} | brand_names()
    for (eco, name), display in (watched_pkgs or {}).items():
        if len(name) < 3:
            continue
        is_word = english(name)
        # a package named after a company or product we track as a vendor ("openai", "anthropic", "sentry"): news
        # about the company is not about the package, so it needs a version or package wording next to it
        is_brand = name.lower() in vendor_terms
        # an ordinary-word name only counts written exactly as the package ("coverage", not "Coverage" in a headline)
        for m in re.finditer(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", text, 0 if is_word else re.I):
            vers = _versions_after(text, m.start(), m.end())
            near = _context_near(text, m.start(), m.end())
            in_lead = m.start() < lead_end
            if is_word and not near:
                continue  # "coverage", "requests" used as ordinary words
            if is_brand and not (near or vers):
                continue  # "OpenAI agents edited Wikipedia": the company, not the openai package
            if not in_lead and not (near or vers):
                continue  # passing mention deep in an article
            add(
                "package",
                eco,
                display,
                vers,
                "watched_name",
                "high" if m.start() < len(title) else "medium",
                m.start(),
                m.end(),
            )
    for term, vendor in (watched_vendors or {}).items():
        if L.mentions(term, title):
            i = title.lower().find(term)
            add("vendor", None, vendor, None, "watched_vendor", "high", max(i, 0), max(i, 0) + len(term))
    # a versionless row is redundant when the same package also has versioned rows
    out = list(found.values())
    versioned = {(r["subject_type"], r["ecosystem"], r["name"].lower()) for r in out if r["version"]}
    return [r for r in out if r["version"] or (r["subject_type"], r["ecosystem"], r["name"].lower()) not in versioned]


SEVERITY_WORDS = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


def severity(sig):
    """critical | high | medium | low, or None for news and social posts."""
    kind, d = sig["kind"], sig["data"] or {}
    if kind == "malicious":
        return "critical" if not (d.get("malicious_other_version") or d.get("other_version")) else "high"
    if kind == "exploited":
        return "critical"
    if kind in ("breach", "ca_distrust"):
        return "high"
    if kind == "vuln":
        sev = SEVERITY_WORDS.get(str(d.get("severity") or "").lower())
        if sev:
            return sev
        cvss = d.get("cvss")
        if isinstance(cvss, (int, float)):
            return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
    return None


def description(sig, snippet=None):
    d, kind = sig["data"] or {}, sig["kind"]
    text = snippet or d.get("summary") or ""
    if not text and kind in ("malicious", "vuln", "exploited") and " - " in sig["title"]:
        text = sig["title"].split(" - ", 1)[1]  # advisory titles read "<id>: <package> - <summary>"
    extras = []
    if d.get("fixed_in"):
        extras.append("Fixed in " + ", ".join(d["fixed_in"]) + ".")
    if isinstance(d.get("cvss"), (int, float)):
        extras.append(f"CVSS {d['cvss']}.")
    if kind == "exploited" and d.get("due_date"):
        extras.append(f"CISA remediation due {d['due_date']}.")
    out = " ".join([t for t in [" ".join(text.split()), *extras] if t])
    return out[:600] or None


def rows_for(sig, watched_pkgs=None, watched_vendors=None, body=None):
    """The item rows for one signal: one per package x version it concerns, or one row with no package."""
    sub, d, kind = sig["subject"], sig["data"] or {}, sig["kind"]
    date = (sig.get("published_at") or sig.get("first_seen_at") or "")[:10] or None
    base = {
        "kind": kind,
        "source": sig["source"],
        "title": sig["title"],
        "url": sig["url"],
        "date": date,
        "severity": severity(sig),
    }
    t = sub.get("type")
    if t == "package" and kind in ("news", "social"):  # posts tied to a package: still read versions from the text
        wp = dict(watched_pkgs or {})
        wp[(sub.get("ecosystem"), sub["name"].lower())] = sub["name"]
        watched_pkgs, t = wp, None
    if t == "package":
        if kind == "malicious":
            versions = [] if d.get("all_versions") else (d.get("versions") or d.get("versions_hit") or [])
        else:
            versions = d.get("versions_hit") or d.get("versions") or []
        return [
            {
                **base,
                "package": sub["name"],
                "version": v,
                "package_manager": PM.get(sub.get("ecosystem")),
                "description": description(sig),
            }
            for v in (versions[:200] or [None])
        ]
    if kind in ("news", "social"):
        google = (
            sig["source"] == "News: Google News"
        )  # title ends "- Publisher"; summary only repeats title + publisher
        title = GOOGLE_PUBLISHER.sub("", sig["title"]) if google else sig["title"]
        ms = [
            m
            for m in extract(
                title, "" if google else (d.get("summary") or ""), body or "", watched_pkgs, watched_vendors
            )
            if m["subject_type"] == "package"
        ]
        if ms:
            return [
                {
                    **base,
                    "package": m["name"],
                    "version": m["version"],
                    "package_manager": PM.get(m["ecosystem"]),
                    "description": description(
                        sig, m["snippet"] if body or len(m["snippet"]) > len(d.get("summary") or "") else None
                    ),
                }
                for m in ms
            ]
    return [{**base, "description": description(sig)}]


# ---------------------------------------------------------------- article pages (read once, for versions in the body)
_SCRIPT = re.compile(r"<(script|style|noscript|svg|nav|footer|header)\b.*?</\1>", re.S | re.I)


_ARTICLE = [
    re.compile(
        r'<[^>]+itemprop=["\']articleBody["\'][^>]*>(.*?)</(?:div|section)>\s*(?:<(?:div|section|footer)[^>]*(?:share|related|tags|author|comments)|$)',
        re.S | re.I,
    ),
    re.compile(r"<article\b[^>]*>(.*)</article>", re.S | re.I),
    re.compile(r"<main\b[^>]*>(.*)</main>", re.S | re.I),
]
_CLUTTER = re.compile(
    r"<(aside|form|figure)\b.*?</\1>|<div[^>]+class=[\"'][^\"']*(related|sidebar|popular|newsletter|share|comments|"
    r"recommended|trending|widget|promo)[^\"']*[\"'][^>]*>.*?</div>",
    re.S | re.I,
)


def article_text(url):
    """The article's own text: the <article>/articleBody part of the page without sidebars, related links or
    navigation (those mention other stories and would attach this item to unrelated packages)."""
    if not url or not url.startswith("http") or "news.google.com" in url:
        return None
    # the URL comes from a feed item, so it may point anywhere: only public addresses, and at most 5 MB
    html = L.fetch(url, "Article pages", raw=True, timeout=15, public_only=True, max_bytes=5 * 1024 * 1024)
    if not html:
        return None
    html = _SCRIPT.sub(" ", html)
    part = None
    for rx in _ARTICLE:
        m = rx.search(html)
        if m and len(m.group(1)) > 500:
            part = m.group(1)
            break
    if part is None:
        return None  # no recognisable article body: don't guess from the whole page
    return L.strip_html(_CLUTTER.sub(" ", part))[:30000]


def index(store, signals=None, fetch_articles=0, log=None):
    """Write item rows for the given signals (default: every signal not indexed yet). Returns rows written.
    fetch_articles = how many security-looking news items may have their article page read in this call."""
    pkgs, vendors = watch_names(store)
    todo = signals if signals is not None else store.unindexed()
    n, fetched = 0, 0
    for sig in todo:
        body, d = None, sig["data"] or {}
        if sig["kind"] == "news" and d.get("article_chars"):
            continue  # rows from the article body were stored when it was read; it isn't downloaded again
        if (
            sig["kind"] == "news"
            and fetched < fetch_articles
            and not d.get("article_checked")
            and L.SEC_WORDS.search(sig["title"])
        ):
            body = article_text(sig["url"])
            fetched += 1
            store.set_data(sig["id"], {"article_checked": True, "article_chars": len(body or "")})
        rows = rows_for(sig, pkgs, vendors, body)
        store.put_items(sig["id"], rows)
        n += len(rows)
    if log and todo:
        log(f"index: {len(todo)} item(s) -> {n} row(s), {fetched} article page(s) read")
    return n
