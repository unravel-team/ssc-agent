"""What the API sends: only fields a consumer uses. Internal bookkeeping (indexing marks, article-fetch flags,
last-seen times, duplicate name columns) stays in the database, and fields with no value are left out.

Clients must treat a missing field as empty / false / null (intel_api/client.py does this before the rules run).
"""

# data keys that are bookkeeping, not information
INTERNAL_DATA = {"indexed_at", "article_checked", "article_chars", "term", "query", "versions_hit", "facts_version"}

# registry facts the gatekeeper's rules read (author, summary, maintainers are not used)
REGISTRY_KEYS = (
    "exists",
    "unverified",
    "latest",
    "release_count",
    "first_release_days",
    "version_exists",
    "version_yanked",
    "version_age_days",
    "install_scripts",
    "deprecated",
)

# finding fields the rules read; always sent so every finding has the same shape
FINDING_REQUIRED = ("id", "source", "malicious", "in_kev")
FINDING_OPTIONAL = (
    "summary",
    "severity",
    "cves",
    "fixed_in",
    "symbols",  # the functions and APIs the advisory names (lib/packages.symbols)
    "malicious_other_version",
    "in_vulncheck_kev",
    "epss_max",
    "versions",
    "url",
    "published",
)


def _empty(v):
    """Empty = carries no information for this field. (Registry facts are handled separately: false matters there.)"""
    return v is None or v == "" or v == [] or v == {} or v is False


def clean(d, keep=()):
    """Drop keys whose value is empty (None, "", [], {}, False), except those in keep."""
    return {k: v for k, v in d.items() if k in keep or not _empty(v)}


def _data(d):
    return clean({k: v for k, v in (d or {}).items() if k not in INTERNAL_DATA})


def item(r):
    """One row of the items table (fields with no value are left out)."""
    return clean(
        {
            k: r.get(k)
            for k in (
                "signal_id",
                "kind",
                "package",
                "version",
                "package_manager",
                "source",
                "title",
                "description",
                "url",
                "date",
                "severity",
            )
        }
    )


def signal(s):
    """A raw record (one per advisory / article / post)."""
    out = {
        "id": s["id"],
        "kind": s["kind"],
        "subject": clean(s.get("subject") or {}),
        "title": s["title"],
        "url": s["url"],
        "published_at": s.get("published_at"),
        "first_seen_at": s.get("first_seen_at"),
        "source": s["source"],
        "reliability": s.get("reliability"),
        "may_block": s.get("may_block"),
        "data": _data(s.get("data")),
    }
    if out["subject"].get("type") == "none":
        out.pop("subject")
    return clean(out, keep=("may_block",))


def finding(v):
    out = {k: v.get(k) for k in FINDING_REQUIRED}
    out["malicious"], out["in_kev"] = bool(out["malicious"]), bool(out["in_kev"])
    out.update(clean({k: v.get(k) for k in FINDING_OPTIONAL}))
    if out.get("epss_max") == 0:
        out.pop("epss_max")
    return out


def evidence(ev):
    reg = ev.get("registry") or {}
    # registry facts: false is information here (version_exists: false = pulled from the registry), so keep it
    out = {
        "registry": {k: reg[k] for k in REGISTRY_KEYS if reg.get(k) is not None and reg.get(k) not in ("", {}, [])},
        "typosquat_of": ev.get("typosquat_of") or [],
        "vulns": [finding(v) for v in ev.get("vulns") or []],
    }
    if ev.get("social_checked"):
        out["social"] = [
            clean({k: p.get(k) for k in ("source", "title", "url", "date", "engagement", "other_version")})
            for p in ev.get("social") or []
        ]
        out["social_checked"] = True
    return out


def check_result(r):
    out = {
        "ecosystem": r["ecosystem"],
        "name": r["name"],
        "version": r.get("version"),
        "collected_at": r["collected_at"],
        "evidence": evidence(r["evidence"]),
    }
    if r.get("resolved_version") and r.get("resolved_version") != r.get("version"):
        out["resolved_version"] = r["resolved_version"]  # only when the API picked the version (latest)
    return clean(out, keep=("evidence",))
