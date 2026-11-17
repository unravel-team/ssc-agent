#!/usr/bin/env python3
"""Source connectors of the sources API (stdlib only, read-only). The agents use them too.

Every network call goes through fetch(), which records whether each source worked so reports can
show coverage. Nothing is cached on disk.

Sources
  Vulnerabilities  OSV, NVD CVE API 2.0, GitHub Advisory DB, CISA KEV, FIRST EPSS,
                   OpenSSF Malicious Packages, VulnCheck KEV (needs VULNCHECK_API_KEY),
                   oss-security mailing list
  Popularity       top PyPI packages (hugovk), npm registry search
  News (RSS)       The Hacker News, BleepingComputer, Help Net Security, CISA advisories,
                   Reddit r/netsec, Lobsters security, Google News search
  Social           Hacker News (Algolia), GitHub issues, Mastodon hashtag timelines,
                   Bluesky (needs BSKY_HANDLE + BSKY_APP_PASSWORD), X (needs X_BEARER_TOKEN)
  Trust stores     Mozilla CA store (curl.se cacert.pem)

Which sources run, their refresh times, feeds, tags and reliability come from
intel_api/config/sources.json (override the path with INTEL_SOURCES_CONFIG).

Optional credentials (environment): GITHUB_TOKEN, NVD_API_KEY, VULNCHECK_API_KEY, X_BEARER_TOKEN,
BSKY_HANDLE, BSKY_APP_PASSWORD.
"""

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

API_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
UA = "ssc-poc-intel/0.2 (supply-chain security research)"
NOW = datetime.now(timezone.utc)
STATUS = {}  # source -> {"ok": n, "fail": n, "last_error": str, "disabled": reason}

# ---------------------------------------------------------------- source config
CONFIG_PATH = os.environ.get("INTEL_SOURCES_CONFIG") or os.path.join(API_DIR, "config", "sources.json")
try:
    with open(CONFIG_PATH, encoding="utf-8") as _f:
        CONFIG = json.load(_f)
except FileNotFoundError:
    CONFIG = {"sources": {}, "policy": {}}
_BY_LABEL = {c["label"]: c for c in CONFIG["sources"].values()}


def source_cfg(src):
    """Config entry for a connector label (per-feed 'News: X' labels map to their feed group)."""
    if src in _BY_LABEL:
        return _BY_LABEL[src]
    if src.startswith("News: "):
        return next((c for c in CONFIG["sources"].values() if src[6:] in (c.get("feeds") or {})), None)
    return None


SPEEDS = {"urgent": 600, "regular": 3600, "slow": 86400}


def speed_seconds(speed):
    """Seconds between pulls for a speed name (urgent / regular / slow), from "speeds" in the config."""
    table = {**SPEEDS, **{k: v for k, v in (CONFIG.get("speeds") or {}).items() if not k.startswith("$")}}
    if speed not in table:
        raise ValueError(f"unknown speed {speed!r}; use one of {', '.join(k for k in table)}")
    return int(table[speed])


def enabled(src):
    c = source_cfg(src)
    return c is None or c.get("enabled", True)


def reliability(src):
    """1-5 trust score from the config (None if the source isn't listed)."""
    c = source_cfg(src)
    if not c:
        return None
    return (c.get("feed_reliability") or {}).get(src[6:] if src.startswith("News: ") else src, c.get("reliability"))


def may_block(src):
    """True only for sources trusted enough to cause a BLOCK on their own."""
    c, r = source_cfg(src), reliability(src)
    return bool(c and c.get("may_block") and r is not None and r >= CONFIG["policy"].get("block_min_reliability", 5))


SEC_WORDS = re.compile(
    r"\b(breach\w*|compromis\w*|malicious|malware|backdoor\w*|hack(ed|ers?)?|stolen|steal\w*|leak\w*|exfiltrat\w*|"
    r"vulnerab\w*|exploit\w*|CVE-\d{4}-\d+|RCE|zero-day|0-day|typosquat\w*|hijack\w*|ransomware|"
    r"distrust\w*|revok\w*|incident|attack\w*|supply[- ]chain)\b",
    re.I,
)


# ---------------------------------------------------------------- transport
_LOCK = threading.Lock()  # connectors are called from worker threads


def _mark(src, ok, err=None):
    with _LOCK:
        s = STATUS.setdefault(src, {"ok": 0, "fail": 0})
        s["ok" if ok else "fail"] += 1
        if err:
            s["last_error"] = str(err)[:120]


def disable(src, reason):
    with _LOCK:
        STATUS.setdefault(src, {"ok": 0, "fail": 0})["disabled"] = reason


MAX_RESPONSE = 64 * 1024 * 1024  # bytes; the largest source (CISA KEV, the top-PyPI list) is a few MB


def is_public_url(url):
    """True for an http(s) URL whose host resolves only to public addresses (not loopback, private, link-local such
    as cloud metadata, ...). For URLs that come from feeds rather than from our own code (article pages)."""
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        port = parts.port or (443 if parts.scheme == "https" else 80)
        infos = socket.getaddrinfo(parts.hostname, port, proto=socket.IPPROTO_TCP)
        return bool(infos) and all(ipaddress.ip_address(i[4][0].split("%")[0]).is_global for i in infos)
    except (ValueError, OSError):  # a bad port, or the name doesn't resolve
        return False


class _PublicRedirectsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_public_url(newurl):
            raise urllib.error.URLError(f"redirect to a non-public address refused: {newurl[:120]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_PUBLIC_OPENER = urllib.request.build_opener(_PublicRedirectsOnly)


def fetch(
    url, src, data=None, headers=None, raw=False, timeout=25, not_found=None, public_only=False, max_bytes=MAX_RESPONSE
):
    """GET/POST a source. Returns parsed JSON (default) or text (raw=True), or None on failure.
    Nothing is cached on disk: what we keep goes into the database (the sources API), and reference data a
    process re-uses (KEV catalogue, popular-package lists) is kept in memory by its callers.
    Sources switched off in the config return None. If not_found is given, an HTTP 404 returns not_found.
    public_only: the URL came from untrusted data (a feed item): refuse it, or a redirect, to a non-public address.
    A response over max_bytes counts as a failure."""
    if not enabled(src):
        disable(src, (source_cfg(src) or {}).get("disabled_reason") or "disabled in " + os.path.basename(CONFIG_PATH))
        return None
    if public_only and not is_public_url(url):
        _mark(src, False, "refused: not a public http(s) address")
        return None
    h = {"User-Agent": UA, **(headers or {})}
    body = json.dumps(data).encode() if data is not None else None
    if body:
        h["Content-Type"] = "application/json"
    opener = _PUBLIC_OPENER.open if public_only else urllib.request.urlopen
    try:
        with opener(urllib.request.Request(url, data=body, headers=h), timeout=timeout) as r:
            content = r.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise ValueError(f"response larger than {max_bytes} bytes")
        txt = content.decode("utf-8", "ignore")
        _mark(src, True)
        return txt if raw else json.loads(txt or "null")
    except urllib.error.HTTPError as e:
        if e.code == 404 and not_found is not None:
            _mark(src, True)
            return not_found
        _mark(src, False, f"HTTP {e.code}")
        return None
    except Exception as e:  # noqa: BLE001 - any failure is recorded in the source's health; callers get None
        _mark(src, False, e)
        return None


def gh_headers():
    return {"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"]} if os.environ.get("GITHUB_TOKEN") else {}


def mentions(term, text):
    return bool(re.search(r"(?<![\w-])" + re.escape(term) + r"(?![\w-])", text or "", re.I))


def strip_html(s):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or "")).strip()


# ---------------------------------------------------------------- vulnerabilities
def osv_batch(pkgs, with_version=True):
    """One OSV request for many packages. pkgs = [{"name","ecosystem","version"}] -> [[vuln ids], ...] in order.
    with_version=False returns every advisory ever published for the package (all versions)."""
    out = []
    for i in range(0, len(pkgs), 500):
        chunk = pkgs[i : i + 500]
        q = [
            {
                "package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                **({"version": p["version"]} if with_version and p.get("version") else {}),
            }
            for p in chunk
        ]
        d = fetch("https://api.osv.dev/v1/querybatch", "OSV", data={"queries": q}, timeout=40)
        res = (d or {}).get("results") or [{}] * len(chunk)
        out += [[v["id"] for v in (r.get("vulns") or [])] for r in res]
    return out


_KEV = None


def kev():
    global _KEV
    if _KEV is None:
        d = fetch(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "CISA KEV",
            timeout=40,
        )
        _KEV = (d or {}).get("vulnerabilities", [])
    return _KEV


def kev_recent(days=30):
    cut = (NOW - timedelta(days=days)).date().isoformat()
    return [v for v in kev() if v.get("dateAdded", "") >= cut]


def epss(cves):
    if not cves:
        return {}
    d = fetch("https://api.first.org/data/v1/epss?cve=" + ",".join(sorted(cves)[:100]), "FIRST EPSS")
    return {x["cve"]: float(x["epss"]) for x in (d or {}).get("data", [])}


def nvd_search(keyword, days=120):
    """Recent CVEs mentioning a keyword. NVD allows ~5 requests/30s without NVD_API_KEY."""
    end = NOW
    start = end - timedelta(days=min(days, 119))
    q = urllib.parse.urlencode(
        {
            "keywordSearch": keyword,
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 20,
        }
    )
    hdr = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    d = fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?" + q, "NVD", headers=hdr)
    if not hdr:
        time.sleep(6.5)  # respect the public rate limit
    out = []
    for it in (d or {}).get("vulnerabilities", []):
        c = it["cve"]
        desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
        metrics = c.get("metrics", {})
        score = None
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if metrics.get(k):
                score = metrics[k][0]["cvssData"].get("baseScore")
                break
        if mentions(keyword, desc):
            out.append(
                {
                    "id": c["id"],
                    "published": c.get("published", "")[:10],
                    "cvss": score,
                    "summary": desc[:220],
                    "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                }
            )
    return out


def ghsa(ecosystem, package):
    eco = {"PyPI": "pip", "npm": "npm"}[ecosystem]
    d = fetch(
        f"https://api.github.com/advisories?ecosystem={eco}&affects={urllib.parse.quote(package)}&per_page=20",
        "GitHub Advisory DB",
        headers=gh_headers(),
    )
    return [
        {
            "id": a["ghsa_id"],
            "cve": a.get("cve_id"),
            "severity": a.get("severity"),
            "type": a.get("type"),
            "summary": a.get("summary"),
            "published": (a.get("published_at") or "")[:10],
            "url": a.get("html_url"),
        }
        for a in (d or [])
    ]


# ---------------------------------------------------------------- OSV affected versions
def _vkey(v):
    """Comparable key for a release version (1.2.10 < 1.2.11; 2.0.0-beta < 2.0.0). None if it isn't numeric."""
    m = re.match(r"^v?(\d+(?:\.\d+)*)(.*)$", str(v or "").strip())
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    return (nums + (0,) * (6 - len(nums)), 0 if m.group(2) else 1, m.group(2))


def _in_range(version, events):
    """OSV range events (introduced / fixed / last_affected, in order). True, False, or None if a version can't be compared."""
    v, hit = _vkey(version), False
    if v is None:
        return None
    for e in events:
        if "introduced" in e:
            x = _vkey(e["introduced"])
            if e["introduced"] == "0" or (x is not None and v >= x):
                hit = True
            elif x is None:
                return None
        elif "fixed" in e or "last_affected" in e:
            raw = e.get("fixed", e.get("last_affected"))
            x = _vkey(raw)
            if x is None:
                return None
            if ("fixed" in e and v >= x) or ("last_affected" in e and v > x):
                hit = False
    return hit


def osv_ranges(rec):
    """Version ranges of an OSV record as text, e.g. [">=1.0.0 <1.2.11"]."""
    out = []
    for a in rec.get("affected") or []:
        for r in a.get("ranges") or []:
            if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            parts = []
            for e in r.get("events") or []:
                if "introduced" in e:
                    parts.append("any version" if e["introduced"] == "0" else ">=" + e["introduced"])
                elif "fixed" in e:
                    parts.append("<" + e["fixed"])
                elif "last_affected" in e:
                    parts.append("<=" + e["last_affected"])
            if parts:
                out.append(" ".join(parts))
    return out


def osv_affects(rec, version):
    """Does an OSV record cover this version? Uses its exact version list and its SEMVER/ECOSYSTEM ranges.
    A record with neither covers every version; a version we can't compare counts as covered (safe side)."""
    if not version:
        return True
    known = False
    for a in rec.get("affected") or []:
        if a.get("versions"):
            known = True
            if version in a["versions"]:
                return True
        for r in a.get("ranges") or []:
            if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            known = True
            if _in_range(version, r.get("events") or []) is not False:
                return True
    return not known


def ossf_malicious(ecosystem, name):
    """Reports for a package in the OpenSSF Malicious Packages repo (one folder per package)."""
    eco = {"PyPI": "pypi", "npm": "npm"}[ecosystem]
    pkg = re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name
    url = f"https://api.github.com/repos/ossf/malicious-packages/contents/osv/malicious/{eco}/{urllib.parse.quote(pkg, safe='@')}"
    files = fetch(url, "OpenSSF Malicious Packages", headers=gh_headers(), not_found=[])
    out = []
    for f in [x for x in (files or []) if x.get("name", "").endswith(".json")][:5]:
        if not str(f.get("download_url") or "").startswith("https://raw.githubusercontent.com/"):
            continue  # follow only links to the repo's own files
        r = fetch(f["download_url"], "OpenSSF Malicious Packages")
        if not r:
            continue
        versions = sorted({v for a in r.get("affected", []) for v in a.get("versions", [])})
        ranges = osv_ranges(r)
        out.append(
            {
                "id": r.get("id"),
                "summary": (r.get("summary") or r.get("details") or "")[:200],
                "published": (r.get("published") or "")[:10],
                "versions": versions[:20],
                "ranges": ranges,
                "all_versions": not versions and not ranges,
                "affected": r.get("affected") or [],
                "url": f"https://github.com/ossf/malicious-packages/blob/main/{f['path']}",
            }
        )
    return out


def vulncheck_kev(cves):
    """{cve: details} for CVEs on VulnCheck's KEV list. Needs VULNCHECK_API_KEY (free community tier)."""
    tok = os.environ.get("VULNCHECK_API_KEY")
    if not tok:
        disable("VulnCheck KEV", "set VULNCHECK_API_KEY (free community account at vulncheck.com)")
        return {}
    out = {}
    for c in sorted(set(cves))[:50]:
        d = fetch(
            "https://api.vulncheck.com/v3/index/vulncheck-kev?cve=" + urllib.parse.quote(c, safe=""),
            "VulnCheck KEV",
            headers={"Authorization": "Bearer " + tok, "Accept": "application/json"},
        )
        for e in (d or {}).get("data", []) or []:
            out[c] = {
                "date_added": (e.get("date_added") or e.get("dateAdded") or "")[:10],
                "ransomware": e.get("knownRansomwareCampaignUse"),
                "evidence": len(e.get("vulncheck_reported_exploitation") or []),
                "url": "https://vulncheck.com/browse/cve/" + c,
            }
    return out


def oss_security(days=45):
    """Recent posts on the oss-security mailing list (via the seclists.org RSS mirror)."""
    txt = fetch("https://seclists.org/rss/oss-sec.rss", "oss-security mailing list", raw=True) or ""
    cut = NOW - timedelta(days=days)
    return [i for i in parse_feed(txt, "oss-security") if i["date"] is None or i["date"] >= cut]


# ---------------------------------------------------------------- popularity (for typosquat checks)
FALLBACK_POPULAR = {
    "PyPI": [
        "requests",
        "flask",
        "django",
        "numpy",
        "pandas",
        "pyyaml",
        "jinja2",
        "urllib3",
        "boto3",
        "pydantic",
        "fastapi",
        "openai",
        "anthropic",
        "langchain",
        "litellm",
        "httpx",
        "cryptography",
        "pillow",
        "click",
        "certifi",
    ],
    "npm": [
        "express",
        "lodash",
        "react",
        "axios",
        "moment",
        "chalk",
        "commander",
        "debug",
        "minimist",
        "uuid",
        "zod",
        "dotenv",
    ],
}


def popular(ecosystem, n=2000):
    if ecosystem == "PyPI":
        d = fetch("https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json", "Top PyPI (hugovk)")
        names = [r["project"].lower() for r in (d or {}).get("rows", [])[:n]]
    else:
        # npm-high-impact's ranked list, read as a plain data file via jsDelivr (never installed or executed)
        txt = (
            fetch("https://cdn.jsdelivr.net/npm/npm-high-impact/lib/top.js", "Top npm (npm-high-impact)", raw=True)
            or ""
        )
        names = re.findall(r"'([^']+)'", txt)[:n]
    return names or FALLBACK_POPULAR[ecosystem]


_DOWNLOADS = {}  # (ecosystem, name) -> (count, when): counts that were read, kept for a day
DOWNLOADS_TTL = 86400


def weekly_downloads(ecosystem, name):
    """Live weekly download count (npm registry API / pypistats.org), cached for a day. None if unknown: a failed
    lookup (often a rate limit while a big lockfile is checked) is tried once more, never counted as zero."""
    key = (ecosystem, name.lower())
    hit = _DOWNLOADS.get(key)
    if hit and time.time() - hit[1] < DOWNLOADS_TTL:
        return hit[0]
    n = _weekly_downloads(ecosystem, name)
    if n is None:
        time.sleep(1)
        n = _weekly_downloads(ecosystem, name)
    if n is not None:
        with _LOCK:
            if len(_DOWNLOADS) > 50000:
                _DOWNLOADS.clear()
            _DOWNLOADS[key] = (n, time.time())
    return n


def _weekly_downloads(ecosystem, name):
    if ecosystem == "npm":
        d = fetch(
            "https://api.npmjs.org/downloads/point/last-week/" + urllib.parse.quote(name, safe="@"), "npm downloads"
        )
        return (d or {}).get("downloads")
    d = fetch(
        f"https://pypistats.org/api/packages/{urllib.parse.quote(name.lower(), safe='')}/recent",
        "PyPI downloads (pypistats)",
    )
    return ((d or {}).get("data") or {}).get("last_week")


# ---------------------------------------------------------------- news (RSS / Atom)
_DEFAULT_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
}
FEEDS = (CONFIG["sources"].get("news_rss") or {}).get("feeds") or _DEFAULT_FEEDS


def _iso_date(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _parse_date(s):
    for f in (parsedate_to_datetime, _iso_date):
        try:
            d = f(s.strip())
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError, OverflowError, AttributeError):  # not this format
            continue
    return None


def parse_feed(xml_text, source):
    items = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return items
    ns = {"a": "http://www.w3.org/2005/Atom"}
    for it in root.iter("item"):
        items.append(
            {
                "source": source,
                "title": strip_html(it.findtext("title")),
                "url": (it.findtext("link") or "").strip(),
                "date": _parse_date(it.findtext("pubDate") or ""),
                "summary": strip_html(it.findtext("description"))[:400],
            }
        )
    for it in root.iter("{http://www.w3.org/2005/Atom}entry"):
        link = it.find("a:link", ns)
        items.append(
            {
                "source": source,
                "title": strip_html(it.findtext("a:title", namespaces=ns)),
                "url": link.get("href") if link is not None else "",
                "date": _parse_date(
                    it.findtext("a:updated", namespaces=ns) or it.findtext("a:published", namespaces=ns) or ""
                ),
                "summary": strip_html(
                    it.findtext("a:content", namespaces=ns) or it.findtext("a:summary", namespaces=ns)
                )[:400],
            }
        )
    return items


def news_feeds():
    items = []
    for name, url in FEEDS.items():
        txt = fetch(url, "News: " + name, raw=True)
        items += parse_feed(txt or "", name)
    return items


def google_news(query, days=45):
    q = urllib.parse.quote(f"{query} when:{days}d")
    txt = fetch(f"https://news.google.com/rss/search?q={q}&hl=en-US&gl=US&ceid=US:en", "News: Google News", raw=True)
    return parse_feed(txt or "", "Google News")


# ---------------------------------------------------------------- social
def social_hn(term, days=120):
    since = int(time.time()) - days * 86400
    d = fetch(
        f"https://hn.algolia.com/api/v1/search?query={urllib.parse.quote(term)}&tags=story&numericFilters=created_at_i>{since}&hitsPerPage=30",
        "Social: Hacker News",
    )
    return [
        {
            "source": "Hacker News",
            "title": h.get("title") or "",
            "url": h.get("url") or f"https://news.ycombinator.com/item?id={h['objectID']}",
            "date": (h.get("created_at") or "")[:10],
            "engagement": h.get("points"),
        }
        for h in (d or {}).get("hits", [])
    ]


def social_github(term):
    q = urllib.parse.quote(
        f'"{term}" in:title (malicious OR compromised OR backdoor OR stealer OR typosquat OR breach)'
    )
    d = fetch(
        f"https://api.github.com/search/issues?q={q}&sort=created&per_page=10",
        "Social: GitHub issues",
        headers=gh_headers(),
    )
    return [
        {
            "source": "GitHub issue",
            "title": i["title"],
            "url": i["html_url"],
            "date": i["created_at"][:10],
            "engagement": i.get("comments"),
        }
        for i in (d or {}).get("items", [])
    ]


MASTODON_TAGS = (CONFIG["sources"].get("mastodon") or {}).get("tags") or [
    "infosec",
    "cybersecurity",
    "supplychain",
    "malware",
]
_MASTO = None


def social_mastodon_pool():
    global _MASTO
    if _MASTO is None:
        _MASTO = []
        for t in MASTODON_TAGS:
            d = fetch(f"https://mastodon.social/api/v1/timelines/tag/{t}?limit=40", "Social: Mastodon")
            for s in d or []:
                _MASTO.append(
                    {
                        "source": "Mastodon",
                        "title": strip_html(s.get("content"))[:240],
                        "url": s.get("url"),
                        "date": (s.get("created_at") or "")[:10],
                        "engagement": s.get("reblogs_count"),
                        "author": (s.get("account") or {}).get("acct"),
                    }
                )
    return _MASTO


# Bluesky session: access tokens expire after about two hours, so a long-running service logs in again after
# BSKY_TOKEN_TTL, or as soon as a search fails; after a failed login it waits BSKY_RETRY before trying again.
BSKY_TOKEN_TTL, BSKY_RETRY = 3600, 600
_BSKY = {"jwt": "", "at": 0.0}
_BSKY_LOCK = threading.Lock()


def _bsky_token():
    with _BSKY_LOCK:
        age = time.time() - _BSKY["at"]
        if (_BSKY["jwt"] and age > BSKY_TOKEN_TTL) or (not _BSKY["jwt"] and age > BSKY_RETRY):
            s = fetch(
                "https://bsky.social/xrpc/com.atproto.server.createSession",
                "Social: Bluesky",
                data={"identifier": os.environ["BSKY_HANDLE"], "password": os.environ["BSKY_APP_PASSWORD"]},
            )
            _BSKY.update(jwt=(s or {}).get("accessJwt", ""), at=time.time())
        return _BSKY["jwt"]


def social_bluesky(term):
    if not (os.environ.get("BSKY_HANDLE") and os.environ.get("BSKY_APP_PASSWORD")):
        disable("Social: Bluesky", "set BSKY_HANDLE and BSKY_APP_PASSWORD (free app password)")
        return []
    token = _bsky_token()
    if not token:
        return []
    d = fetch(
        f"https://bsky.social/xrpc/app.bsky.feed.searchPosts?q={urllib.parse.quote(term)}&limit=25&sort=latest",
        "Social: Bluesky",
        headers={"Authorization": "Bearer " + token},
    )
    if d is None:  # most often an expired token: log in again on the next search
        with _BSKY_LOCK:
            if _BSKY["jwt"] == token:
                _BSKY.update(jwt="", at=0.0)
    out = []
    for p in (d or {}).get("posts", []):
        handle, rkey = p["author"]["handle"], p["uri"].rsplit("/", 1)[-1]
        out.append(
            {
                "source": "Bluesky",
                "title": p["record"].get("text", "")[:240],
                "url": f"https://bsky.app/profile/{handle}/post/{rkey}",
                "date": p["record"].get("createdAt", "")[:10],
                "engagement": p.get("repostCount"),
                "author": handle,
            }
        )
    return out


def social_x(term):
    tok = os.environ.get("X_BEARER_TOKEN")
    if not tok:
        disable("Social: X", "set X_BEARER_TOKEN (X API plan with recent search)")
        return []
    q = urllib.parse.quote(
        f'"{term}" (malicious OR compromised OR breach OR backdoor OR vulnerability) -is:retweet lang:en'
    )
    d = fetch(
        f"https://api.x.com/2/tweets/search/recent?query={q}&max_results=25&tweet.fields=created_at,public_metrics,author_id",
        "Social: X",
        headers={"Authorization": "Bearer " + tok},
    )
    return [
        {
            "source": "X",
            "title": t["text"][:240],
            "url": f"https://x.com/i/web/status/{t['id']}",
            "date": t.get("created_at", "")[:10],
            "engagement": (t.get("public_metrics") or {}).get("retweet_count"),
        }
        for t in (d or {}).get("data", [])
    ]


def social_all(term, days=120):
    """All social sources for one term, filtered to posts that name the term AND use a security word."""
    posts = social_hn(term, days) + social_github(term) + social_bluesky(term) + social_x(term)
    posts += [p for p in social_mastodon_pool() if mentions(term, p["title"])]
    cut = (NOW - timedelta(days=days)).date().isoformat()
    seen, out = set(), []
    for p in posts:
        if (
            p["url"] in seen
            or not mentions(term, p["title"])
            or not SEC_WORDS.search(p["title"])
            or (p["date"] and p["date"] < cut)
        ):
            continue
        seen.add(p["url"])
        out.append(p)
    return out


# ---------------------------------------------------------------- trust stores
def mozilla_store():
    """{sha256_fingerprint: label} for Mozilla's current trusted roots."""
    txt = fetch("https://curl.se/ca/cacert.pem", "Mozilla CA store", raw=True) or ""
    out = {}
    for m in re.finditer(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", txt, re.S):
        before = [
            line.strip()
            for line in txt[: m.start()].splitlines()[-12:]
            if line.strip() and not line.startswith(("#", "=")) and ":" not in line
        ]
        der = base64.b64decode("".join(m.group(1).split()))
        out[hashlib.sha256(der).hexdigest()] = before[-1] if before else "?"
    return out


def pem_fingerprint(pem):
    b64 = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", pem, re.S).group(1)
    return hashlib.sha256(base64.b64decode("".join(b64.split()))).hexdigest()


def sources_status():
    out = {}
    for k, v in sorted(STATUS.items()):
        out[k] = {**v, "reliability": reliability(k), "may_block": may_block(k)}
    return out
