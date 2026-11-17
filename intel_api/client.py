"""Client used by the gatekeeper, the install guardrail, pre-commit and the threat-intel collector.

Set SSC_INTEL_API (e.g. http://127.0.0.1:8787) and, if the server uses keys, SSC_INTEL_API_KEY;
SSC_INTEL_API_CA for a certificate not in the system store.
Without SSC_INTEL_API, or when the API can't be reached, every call returns None and callers
fall back to querying the sources directly (as before). MODE says which path was used.
"""

import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from .lib.rules import full_evidence  # the evidence shape the rules expect

BASE = (os.environ.get("SSC_INTEL_API") or "").rstrip("/")
KEY = os.environ.get("SSC_INTEL_API_KEY") or ""
# HTTPS with a company CA (or a self-signed test certificate): SSC_INTEL_API_CA=/path/to/ca.pem
TLS = ssl.create_default_context(cafile=os.environ["SSC_INTEL_API_CA"]) if os.environ.get("SSC_INTEL_API_CA") else None
MODE = "direct" if not BASE else "api"
_up = None
STATS = {"packages_from_api": 0, "packages_missing": 0, "searches_from_api": 0, "searches_not_covered": 0}


class ApiUnavailable(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status = status


def _note(msg):
    if not os.environ.get("SSC_QUIET"):
        print(f"intel-api client: {msg}", file=sys.stderr)


def _call(method, path, body=None, timeout=30):
    """One retry on a dropped connection (not on HTTP errors or timeouts)."""
    try:
        return _call_once(method, path, body, timeout)
    except ApiUnavailable as e:
        if e.status is None and any(
            w in str(e) for w in ("Connection reset", "Connection refused", "RemoteDisconnected", "BrokenPipe")
        ):
            import time

            time.sleep(0.3)
            return _call_once(method, path, body, timeout)
        raise


def _call_once(method, path, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", "User-Agent": "ssc-intel-client/1"}
    if KEY:
        h["Authorization"] = "Bearer " + KEY
    try:
        with urllib.request.urlopen(
            urllib.request.Request(BASE + path, data=data, headers=h, method=method), timeout=timeout, context=TLS
        ) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error")
        except (ValueError, OSError, AttributeError):  # no JSON error body
            msg = ""
        raise ApiUnavailable(f"HTTP {e.code} {msg}".strip(), e.code) from e
    except Exception as e:  # any failure means "API unavailable": the caller falls back to the sources
        raise ApiUnavailable(f"{type(e).__name__}: {e}") from e


def enabled():
    """True if an API is configured and answered its health check (checked once per process)."""
    global _up, MODE
    if not BASE:
        return False
    if _up is None:
        try:
            _up = bool(_call("GET", "/v1/health", timeout=3).get("ok"))
        except ApiUnavailable as e:
            _up = False
            _note(f"{BASE} unreachable ({e}); querying sources directly")
        MODE = "api" if _up else "direct (api unreachable)"
    return _up


def _try(method, path, body=None, timeout=30):
    """Call the API; on failure note it, switch MODE and return None so the caller falls back."""
    global MODE
    if not enabled():
        return None
    try:
        return _call(method, path, body, timeout)
    except ApiUnavailable as e:
        if e.status not in (400, 401, 403, 404, 413):  # a refused request isn't an outage
            MODE = "direct (api error)"
        _note(f"{method} {path} failed ({e}); querying sources directly")
        return None


# ------------------------------------------------------------------ packages
def check_packages(deps, social=False, resolve_latest=False, timeout=120):
    """{(ecosystem, name_lower, version_or_''): {"resolved_version", "evidence"}} or None (use direct lookups)."""
    if not deps:
        return {}
    body = {
        "packages": [{"ecosystem": d["ecosystem"], "name": d["name"], "version": d.get("version")} for d in deps],
        "social": social,
        "resolve_latest": resolve_latest,
    }
    r = _try("POST", "/v1/packages/check", body, timeout)
    if r is None:
        return None
    STATS["packages_from_api"] += len(r["results"])
    STATS["packages_missing"] += len(r.get("missing", []))  # queued by the API; the caller checks them directly
    return {
        (x["ecosystem"], x["name"].lower(), x.get("version") or ""): {
            "resolved_version": x.get("resolved_version") or x.get("version"),
            "evidence": full_evidence(x["evidence"]),
            "collected_at": x.get("collected_at"),
        }
        for x in r["results"]
    }


# ------------------------------------------------------------------ what's new / notices
def alerts(since=None, package=None):
    """Item rows first stored after `since` (default: last 24 h), scope-wide."""
    q = "&".join(f"{k}={quote(v)}" for k, v in (("since", since), ("package", package)) if v)
    return _try("GET", "/v1/alerts" + (f"?{q}" if q else ""))


def push_breach_notices(notices):
    return _try("POST", "/v1/signals/breach-notices", {"notices": notices})


def sources_status():
    """Source health as the API sees it, in connectors.sources_status()'s shape (label -> ok/fail/...)."""
    r = _try("GET", "/v1/sources")
    if r is None:
        return {}
    out = {}
    for v in r["sources"].values():
        if v["mode"] == "not connected":
            continue
        st = {
            "ok": 1 if v.get("last_ok_at") else 0,
            "fail": 1 if v.get("last_error") else 0,
            "reliability": v.get("reliability"),
            "may_block": v.get("may_block"),
            "mode": v["mode"],
        }
        if v.get("last_error"):
            st["last_error"] = v["last_error"]
        if not v.get("enabled"):
            st["disabled"] = v.get("disabled_reason") or "disabled"
        out[v["label"]] = st
    for label, st in (r.get("lookups_since_start") or {}).items():  # lookups run by the service on request
        cur = out.setdefault(
            label, {"reliability": st.get("reliability"), "may_block": st.get("may_block"), "mode": "lookup"}
        )
        for k in ("ok", "fail"):
            cur[k] = cur.get(k, 0) + st.get(k, 0)
        for k in ("last_error", "disabled"):
            if st.get(k):
                cur[k] = st[k]
    return out


# ------------------------------------------------------------------ source facade for the collector
def _dt(s):
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _local():
    """The source registry, used directly when there is no API (same sources, same order)."""
    from .sources import registry

    return registry


class Sources:
    """Same calls as the connectors, served from the API when available, otherwise straight from the sources."""

    def __init__(self, L):
        self.L = L
        self._health = None

    def _feed_ready(self, key):
        """Only serve a feed from the API once the service has pulled it successfully at least once."""
        if self._health is None:
            r = _try("GET", "/v1/sources")
            self._health = (r or {}).get("sources") or {}
        return bool((self._health.get(key) or {}).get("last_ok_at"))

    def _feed_items(self, source_prefix=None, source=None, days=45):
        since = (self.L.NOW - timedelta(days=days)).date().isoformat()
        q = (
            f"/v1/signals?kind=news&limit=5000&published_since={since}"
            + (f"&source_prefix={quote(source_prefix)}" if source_prefix else "")
            + (f"&source={quote(source)}" if source else "")
        )
        r = _try("GET", q)
        if r is None:
            return None
        out = []
        for s in r["signals"]:
            if s["source"] == "News: Google News":
                continue
            src = s["source"][6:] if s["source"].startswith("News: ") else s["source"]
            out.append(
                {
                    "source": "oss-security" if s["source"] == "oss-security mailing list" else src,
                    "title": s["title"],
                    "url": s["url"],
                    "date": _dt(s.get("published_at")),
                    "summary": (s.get("data") or {}).get("summary", ""),
                }
            )
        return out

    def news_feeds(self):
        r = self._feed_items(source_prefix="News: ") if self._feed_ready("news_rss") else None
        return r if r is not None else self.L.news_feeds()

    def oss_security(self, days=45):
        r = (
            self._feed_items(source="oss-security mailing list", days=days)
            if self._feed_ready("oss_security")
            else None
        )
        return r if r is not None else self.L.oss_security(days)

    def kev_recent(self, days=30):
        since = (self.L.NOW - timedelta(days=days)).date().isoformat()
        r = (
            _try("GET", f"/v1/signals?kind=exploited&source={quote('CISA KEV')}&published_since={since}&limit=5000")
            if self._feed_ready("cisa_kev")
            else None
        )
        if r is None:
            return self.L.kev_recent(days)
        return [
            {
                "cveID": (s.get("subject") or {}).get("name"),
                "vendorProject": (s.get("data") or {}).get("vendor"),
                "product": (s.get("data") or {}).get("product"),
                "dateAdded": s.get("published_at"),
                "shortDescription": (s.get("data") or {}).get("summary"),
                "dueDate": (s.get("data") or {}).get("due_date"),
            }
            for s in r["signals"]
        ]

    def mozilla_store(self):
        r = _try("GET", "/v1/trust/mozilla-roots") if self._feed_ready("mozilla_ca_store") else None
        return r["roots"] if r else self.L.mozilla_store()

    def _stored(self, kind, term, term_type=None, days=45):
        """Results the API's background search stored for this term, or None if it hasn't searched it yet."""
        q = f"/v1/search/{kind}?term={quote(term)}&days={days}" + (f"&term_type={term_type}" if term_type else "")
        r = _try("GET", q)
        if r is None or not r.get("covered"):  # API unreachable, or the search failed
            STATS["searches_not_covered"] += 1
            return None
        STATS["searches_from_api"] += 1
        return r["items"]

    def google_news(self, query, days=45, term=None, term_type=None):
        rows = self._stored("news", term, term_type, days) if term else None
        if rows is None:
            return _local().search("news", query=query, days=days)
        return [
            {
                "source": s["source"][6:] if s["source"].startswith("News: ") else s["source"],
                "title": s["title"],
                "url": s["url"],
                "date": _dt(s.get("published_at")),
                "summary": (s.get("data") or {}).get("summary", ""),
            }
            for s in rows
        ]

    def social_all(self, term, days=120):
        rows = self._stored("social", term, None, days)
        if rows is None:
            return _local().search("social", term=term, days=days)
        return [
            {
                "source": s["source"].replace("Social: ", ""),
                "title": s["title"],
                "url": s["url"],
                "date": (s.get("published_at") or "")[:10] or None,
                "engagement": (s.get("data") or {}).get("engagement"),
            }
            for s in rows
        ]

    def nvd_search(self, term, days=120):
        rows = self._stored("nvd", term, None, days)
        if rows is None:
            return _local().search("nvd", term=term, days=days)
        return [
            {
                "id": (s.get("subject") or {}).get("name"),
                "published": (s.get("published_at") or "")[:10],
                "cvss": (s.get("data") or {}).get("cvss"),
                "summary": (s.get("data") or {}).get("summary", ""),
                "url": s["url"],
            }
            for s in rows
        ]
