"""API routes: plain functions (app, query, body, match) -> JSON-able, plus the route table.

Moving to another framework later means mapping ROUTES onto it; the handlers don't touch HTTP.
"""

import hashlib
import json
import math
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from .._paths import CONFIG_DIR, L
from ..core import scope as scope_mod
from ..core.models import KINDS, now_iso, signal
from ..engine import advice as advice_mod
from ..engine import checks, evidence, jobs, scans
from ..engine import index as indexer
from ..engine.scheduler import log
from ..sources import registry
from . import views

# what each kind of key may do. read < write < admin for people and the agents' tools; laptops get a "scan" key
# (send scans, read their own results) and the agents container an "agent" key (take jobs, return advisories)
ROLES = {
    "read": {"read"},
    "write": {"read", "write"},
    "admin": {"read", "write", "admin", "scan", "agent"},
    "scan": {"scan"},
    "agent": {"agent"},
}
MAX_BODY = 5 * 1024 * 1024
MAX_CHECK = 2000
VERSION = "1"


class ApiError(Exception):
    def __init__(self, status, msg, **extra):
        super().__init__(msg)
        self.status, self.extra = status, extra  # extra: more fields for the answer (e.g. the problems found)


def _num(params, name, default, lo, hi, cast=int):
    """A numeric query/body parameter, clamped to [lo, hi]; 400 (not 500) when it isn't a number.
    The clamp also stops a negative limit, which SQLite reads as "no limit"."""
    raw = params.get(name, default)
    try:
        v = cast(raw)
    except (TypeError, ValueError, OverflowError):
        raise ApiError(400, f"{name} must be a number") from None
    if isinstance(v, float) and not math.isfinite(v):
        raise ApiError(400, f"{name} must be a finite number")
    return max(lo, min(v, hi))


def _since(q, default_hours=24):
    if q.get("since"):
        return q["since"]
    return (datetime.now(timezone.utc) - timedelta(hours=default_hours)).isoformat(timespec="seconds")


def _deps(body, limit=MAX_CHECK):
    pk = body.get("packages")
    if not isinstance(pk, list) or not pk:
        raise ApiError(400, "packages: non-empty list of {package_manager (npm|pip), name, version} required")
    if len(pk) > limit:
        raise ApiError(413, f"at most {limit} packages per request")
    out = []
    for p in pk:
        if not isinstance(p, dict):
            raise ApiError(400, f"bad package entry: {str(p)[:200]}")
        eco = {"pypi": "PyPI", "pip": "PyPI", "npm": "npm"}.get(
            str(p.get("ecosystem") or p.get("package_manager") or "").lower()
        )
        name = str(p.get("name") or "").strip()
        if not eco or not name or len(name) > 214:
            raise ApiError(400, f"bad package entry: {str(p)[:200]}")
        out.append({"ecosystem": eco, "name": name, "version": (str(p["version"]) if p.get("version") else None)})
    return out


# ------------------------------------------------------------------ handlers: (app, query, body, match) -> json
def h_health(app, q, b, m):
    return {
        "ok": True,
        "version": VERSION,
        "time": now_iso(),
        "auth": "keys" if app.keys else "dev (localhost, no keys)",
    }


def h_sources(app, q, b, m):
    health = app.store.sources()
    out = {}
    for key, d in registry.describe().items():
        st = health.get(key, {})
        caps = d["capabilities"]
        mode = "feed" if "feed" in caps else ("lookup" if caps else "not connected")
        out[key] = {
            **d,
            "mode": mode,
            "last_run_at": st.get("last_run_at"),
            "last_ok_at": st.get("last_ok_at"),
            "last_error": st.get("last_error"),
            "items": st.get("items"),
            "new_items": st.get("new_items"),
        }
    job_health = {}
    for j in jobs.all_jobs():
        st = health.get(j.key, {})
        job_health[j.key] = {
            "enabled": j.enabled,
            "every_seconds": j.every,
            "last_run_at": st.get("last_run_at"),
            "last_ok_at": st.get("last_ok_at"),
            "last_error": st.get("last_error"),
        }
    return {
        "policy": L.CONFIG.get("policy", {}),
        "sources": out,
        "jobs": job_health,
        "search_coverage": app.store.search_coverage(),
        "package_evidence": app.store.evidence_stats(),
        "items": app.store.item_stats(),
        "lookups_since_start": L.sources_status(),
        "store": app.store.stats(),
    }


def h_signals(app, q, b, m):
    kinds = [k for k in (q.get("kind") or "").split(",") if k]
    if any(k not in KINDS for k in kinds):
        raise ApiError(400, f"kind must be one of {', '.join(KINDS)}")
    rows = app.store.query(
        since=q.get("since"),
        kinds=kinds or None,
        min_reliability=_num(q, "min_reliability", 0, 0, 1000) or None,
        subject_type=q.get("subject_type"),
        ecosystem=q.get("ecosystem"),
        name=q.get("name"),
        source=q.get("source"),
        published_since=q.get("published_since"),
        limit=_num(q, "limit", 500, 0, 5000),
    )
    if q.get("source_prefix"):
        rows = [r for r in rows if r["source"].startswith(q["source_prefix"])]
    return {"count": len(rows), "signals": [views.signal(r) for r in rows]}


def _max_age(b):
    default = float(((L.CONFIG.get("collection") or {}).get("package_evidence") or {}).get("max_age_hours", 24))
    return _num(b, "max_age_hours", default, 0.0, 24.0 * 3650, cast=float)


def h_check(app, q, b, m):
    """Evidence for packages (used by the gatekeeper and install guardrail): stored when fresh, otherwise looked
    up now, stored and returned. Packages that could not be looked up are listed in `missing`."""
    deps = _deps(b)
    res = evidence.lookup(
        app.store,
        deps,
        resolve_latest=bool(b.get("resolve_latest")),
        social=bool(b.get("social")),
        max_age_hours=_max_age(b),
    )
    ok = [r for r in res if r["status"] != "error"]
    bad = [r for r in res if r["status"] == "error"]
    return {
        "read_at": now_iso(),
        "results": [views.check_result(r) for r in ok],
        "missing": [views.clean({k: r.get(k) for k in ("ecosystem", "name", "version", "error")}) for r in bad],
    }


def _package_result(store, r):
    pm = scope_mod.ECO_TO_PM[r["ecosystem"]]
    out = {"package": r["name"], "version": r.get("version"), "package_manager": pm}
    if r["status"] == "error":
        return views.clean({**out, "error": r.get("error")})
    v = r.get("version") or r.get("resolved_version")
    rows = store.items(package=r["name"], package_manager=pm, version=v, limit=2000) if v else []
    rows += store.items(package=r["name"], package_manager=pm, version="", limit=2000)
    out.update(
        collected_at=r["collected_at"], evidence=views.evidence(r["evidence"]), items=[views.item(x) for x in rows]
    )
    if r.get("resolved_version") and r.get("resolved_version") != r.get("version"):
        out["resolved_version"] = r["resolved_version"]
    return views.clean(out, keep=("items",))


def vendor_records(store, name, days=45):
    """Records about a vendor. Searched now (and stored) if the vendor has never been searched."""
    if not any((store.search_state(k, name, "vendor") or {}).get("last_ok_at") for k in ("news", "social")):
        for kind in ("news", "social"):
            jobs.search_now(store, kind, name, "vendor")
    cut = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
    rows = [
        r
        for r in store.query(kinds=["news", "social", "breach"], published_since=cut, limit=5000)
        if (r["subject"].get("name") or "").lower() == name.lower()
        or (L.mentions(name, r["title"]) and L.SEC_WORDS.search(r["title"] + " " + (r["data"].get("summary") or "")))
    ]
    return rows


def h_lookup(app, q, b, m):
    """What an app found in the files it was pointed at: packages (and optionally vendors). For each, stored
    information is returned when fresh; otherwise it is looked up from the sources now, stored, and returned."""
    deps = _deps(b) if b.get("packages") else []
    raw_vendors = b.get("vendors") or []
    if not isinstance(raw_vendors, list):
        raise ApiError(400, "vendors: a list of names")
    vendors = [str(v).strip() for v in raw_vendors if str(v).strip()]
    if not deps and not vendors:
        raise ApiError(400, "packages and/or vendors required")
    if len(vendors) > 50:
        raise ApiError(413, "at most 50 vendors per request")
    res = (
        evidence.lookup(
            app.store,
            deps,
            resolve_latest=bool(b.get("resolve_latest")),
            social=bool(b.get("social")),
            max_age_hours=_max_age(b),
        )
        if deps
        else []
    )
    out_v = []
    for v in vendors:
        rows = vendor_records(app.store, v, _num(b, "days", 45, 1, 3650))
        if rows:  # vendors with nothing on record are left out
            out_v.append({"vendor": v, "count": len(rows), "signals": [views.signal(x) for x in rows]})
    return {"looked_up_at": now_iso(), "packages": [_package_result(app.store, r) for r in res], "vendors": out_v}


def _days_cut(q, default):
    days = _num(q, "days", default, 1, 3650)
    return days, (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()


def h_search_results(app, q, b, m):
    """Stored results of a news / social / NVD search for a term; searched now (and stored) if it never was."""
    kind, term = m.group(1), q.get("term")
    if kind not in ("news", "social", "nvd") or not term:
        raise ApiError(400, "kind news|social|nvd and ?term= required")
    tt = q.get("term_type")
    st = (
        app.store.search_state(kind, term, tt)
        if tt
        else next(
            (
                x
                for x in (
                    app.store.search_state(kind, term, t)
                    for t in ("vendor", "package", "certificate_authority", "stack")
                )
                if x
            ),
            None,
        )
    )
    if not st or not st.get("last_ok_at"):  # never searched: search now, store, return
        sc = scope_mod.load(app.store)
        tt = tt or ("package" if any(p["name"].lower() == term.lower() for p in sc.packages.values()) else "vendor")
        jobs.search_now(app.store, kind, term, tt)
        st = app.store.search_state(kind, term, tt)
        if not st or not st.get("last_ok_at"):
            raise ApiError(502, f"search failed: {(st or {}).get('last_error') or 'no result'}")
    _, cut = _days_cut(q, 45)
    return {
        "kind": kind,
        "term": term,
        "covered": True,
        "searched_at": st["last_ok_at"],
        "query": st["query"],
        "items": [views.signal(x) for x in app.store.search_items(kind, term, tt, published_since=cut)],
    }


PM = {"pypi": "pip", "pip": "pip", "npm": "npm"}


def _item_filters(q):
    pm = q.get("package_manager") or q.get("ecosystem")
    if pm and pm.lower() not in PM:
        raise ApiError(400, "package_manager must be npm or pip")
    kinds = [k for k in (q.get("kind") or "").split(",") if k]
    since = q.get("published_since") or (_days_cut(q, 45)[1] if "days" in q else None)
    return {
        "kinds": kinds or None,
        "package": q.get("package") or q.get("name"),
        "version": q.get("version"),
        "package_manager": PM[pm.lower()] if pm else None,
        "source": q.get("source"),
        "severity": q.get("severity"),
        "published_since": since,
        "limit": _num(q, "limit", 500, 0, 10000),
    }


def h_items(app, q, b, m):
    """The generic table: one row per item x package x version, from every source."""
    rows = app.store.items(**_item_filters(q))
    return {"count": len(rows), "items": [views.item(r) for r in rows]}


def h_news(app, q, b, m):
    """News and social rows, structured by package and version."""
    f = _item_filters(q)
    f["kinds"] = f["kinds"] or ["news", "social"]
    rows = app.store.items(**f)
    return {"count": len(rows), "items": [views.item(r) for r in rows]}


def h_package(app, q, b, m):
    """Everything about one package version: stored when fresh, otherwise looked up now, stored and returned."""
    pm = PM.get(m.group(1).lower())
    if not pm:
        raise ApiError(400, "package manager must be npm or pip (pypi)")
    dep = {"ecosystem": scope_mod.PM_TO_ECO[pm], "name": unquote(m.group(2)), "version": q.get("version")}
    r = evidence.lookup(app.store, [dep], resolve_latest=not dep["version"], max_age_hours=_max_age(q))[0]
    out = _package_result(app.store, r)
    if r["status"] == "error":
        raise ApiError(502, f"lookup failed: {r.get('error')}")
    return out


def h_vendor(app, q, b, m):
    """News, social posts and breach notices about a vendor; searched now (and stored) if never searched."""
    name = unquote(m.group(1))
    days = _num(q, "days", 45, 1, 3650)
    rows = vendor_records(app.store, name, days)
    return {"vendor": name, "days": days, "count": len(rows), "signals": [views.signal(r) for r in rows]}


def h_ca_distrust(app, q, b, m):
    return {"signals": [views.signal(x) for x in app.store.query(kinds=["ca_distrust"], limit=1000)]}


def h_mozilla_roots(app, q, b, m):
    st = app.store.source_state("mozilla_ca_store")
    roots = ((st or {}).get("state") or {}).get("roots") or {}
    if not roots:
        raise ApiError(503, "Mozilla CA store not pulled yet")
    return {"as_of": st["last_ok_at"], "count": len(roots), "roots": roots}


def h_scope(app, q, b, m):
    """What the service tracks: intel_api/config/scope.json, plus the packages discovered through lookups."""
    sc = scope_mod.load(app.store)
    return {
        **sc.summary(),
        "scope": {k: v for k, v in sc.raw.items() if not k.startswith("$")},
        "discovered": scope_mod.discovered(app.store),
    }


def h_alerts(app, q, b, m):
    """What's new: item rows whose record was first stored after `since` (default: the last 24 hours)."""
    pm = q.get("package_manager")
    if pm and pm.lower() not in PM:
        raise ApiError(400, "package_manager must be npm or pip")
    since = _since(q)
    rows = app.store.items_since(
        since,
        kinds=[k for k in (q.get("kind") or "").split(",") if k] or None,
        package=q.get("package"),
        package_manager=PM[pm.lower()] if pm else None,
        limit=_num(q, "limit", 1000, 0, 10000),
    )
    return {
        "since": since,
        "count": len(rows),
        "items": [views.clean({**views.item(r), "first_seen_at": r["first_seen_at"]}) for r in rows],
    }


def _notice_source(n):
    """(link, source name) for a breach notice: the site the agent took it from, e.g. docs.litellm.ai.
    Uses the notice's main source link, else the first link among its other sources, else the publication it names."""
    others = n.get("sources") or []
    cands = [n.get("source"), *(others if isinstance(others, list) else [others])]
    for c in cands:
        link = re.match(r"https?://([^/:?#\s]+)", c.strip()) if isinstance(c, str) else None
        if link:  # a bare "https://" has no host: it falls through to the name below
            return c.strip(), re.sub(r"^www\.", "", link.group(1).lower())
    for c in cands:  # e.g. "Railway Blog: 'Preliminary Report…' (no direct link)"
        if isinstance(c, str) and c.strip():
            return "", re.split(r"[:(]", c.strip())[0].strip()[:80] or "unknown"
    return "", "unknown"


def h_ingest(app, q, b, m):
    """Breach notices written by the threat-intel agent (AI-extracted, so reliability is capped: HOLD at most)."""
    notices = b.get("notices")
    if not isinstance(notices, list):
        raise ApiError(400, "notices: list required")
    sigs = []
    for n in notices[:500]:
        if not isinstance(n, dict):
            continue
        typ = n.get("type") or "vendor"
        name = n.get("package") if typ == "package" else (n.get("vendor") or n.get("name"))
        if not name or not isinstance(name, str):
            continue
        subj = {"type": "package" if typ == "package" else "vendor", "name": name}
        if typ == "package":
            subj["ecosystem"] = {"pypi": "PyPI", "npm": "npm"}.get(
                str(n.get("ecosystem", "")).lower(), n.get("ecosystem")
            )
        url, publisher = _notice_source(n)
        sigs.append(
            signal(
                publisher,
                "breach",
                str(n.get("title") or n.get("summary") or f"Breach notice: {name}"),
                url=url,
                key=n.get("id") or url or name,
                subject=subj,
                published_at=n.get("date") or n.get("published"),
                ai_extracted=True,
                data={
                    "id": n.get("id"),
                    "confidence": n.get("confidence"),
                    "versions": n.get("versions") or [],
                    "summary": str(n.get("summary") or n.get("exposed") or "")[:600],
                    "vendor_guidance": str(n.get("vendor_guidance") or "")[:400],
                },
            )
        )
    new = app.store.upsert(sigs)
    indexer.index(app.store, app.store.signals_by_ids([x["id"] for x in sigs]))
    return {"received": len(notices), "stored": len(sigs), "new": len(new)}


def h_refresh(app, q, b, m):
    """Run one background job now (admin). This is the only call that makes the service contact sources."""
    key = b.get("source") or b.get("job")
    keys = [j.key for j in jobs.all_jobs()]
    if key and key not in keys:
        raise ApiError(400, f"job must be one of {', '.join(keys)}")
    if app.scheduler:
        app.scheduler.trigger(key)
        return {"accepted": True, "job": key or "everything due", "mode": "background"}
    from ..engine import scheduler  # no scheduler running (serve --no-scheduler): run it now

    res = scheduler.run(app.store, key) if key else scheduler.run_due(app.store)
    return {"accepted": True, "job": key or "everything due", "mode": "ran now", "result": res}


def h_openapi(app, q, b, m):
    from .openapi import spec

    return spec()


# ---------------------------------------------------------------- scans (laptop scanner) and the agents
def lookup_for_scans(store):
    """The lookup the scan pipeline uses: same as POST /v1/lookup (database first, sources on a miss)."""

    def lookup(packages, vendors, social):
        # the scan's own packages (looked up with social) join the scope; fix candidates it tries do not. Packages
        # only in lockfiles skip the per-package social search and join the scope as "lockfile"
        direct = [p for p in packages or [] if not p.get("transitive")]
        locked = [p for p in packages or [] if p.get("transitive")]
        age = _max_age({})
        res = []
        if direct:
            deps = _deps({"packages": direct}, scans.MAX_PACKAGES)
            res += evidence.lookup(store, deps, resolve_latest=True, social=social, max_age_hours=age, track=social)
        if locked:
            deps = _deps({"packages": locked}, scans.MAX_PACKAGES)
            res += evidence.lookup(store, deps, resolve_latest=True, max_age_hours=age, track=social, origin="lockfile")
        out_v = []
        for v in vendors:
            rows = vendor_records(store, v)
            if rows:
                out_v.append({"vendor": v, "count": len(rows), "signals": [views.signal(x) for x in rows]})
        return {"packages": [_package_result(store, r) for r in res], "vendors": out_v}

    return lookup


def trust_for_scans(store):
    """The certificate-authority check the scan pipeline uses (engine/trust.py); a CA never searched for is searched once."""
    from ..engine import trust

    def search_once(term):
        if not (store.search_state("news", term, "certificate_authority") or {}).get("last_ok_at"):
            try:
                jobs.search_now(store, "news", term, "certificate_authority")
            except Exception as e:  # noqa: BLE001 - the check still uses what is stored
                log(f"CA search for {term!r} failed: {type(e).__name__}: {e}")

    def check(scope):
        return trust.check_cas(
            store, scope.get("certificate_authorities") or [], scope.get("certificate_files"), search_once
        )

    return check


def h_scan_submit(app, q, b, m):
    """A scanner sends what it found in a folder; the pipeline assesses it and the agents write the advisory."""
    try:
        folder, device_name, scope = scans.validate(b)
        scope["done_actions"] = scans.done_items(b)
    except ValueError as e:
        raise ApiError(400, str(e)) from None
    scan = scans.new_scan(app.caller(), folder, device_name, scope)
    app.store.add_scan(scan)
    return {"id": scan["id"], "status": scan["status"], "poll": f"/v1/scans/{scan['id']}"}


def _own_scan(app, sid):
    scan = app.store.get_scan(sid)
    if not scan or (app.caller_role() != "admin" and scan["device"] != app.caller()):
        raise ApiError(404, "no such scan")
    return scan


def h_scan_get(app, q, b, m):
    return scans.view(_own_scan(app, m.group(1)))


def h_scans_list(app, q, b, m):
    device = None if app.caller_role() == "admin" else app.caller()
    return {"scans": app.store.list_scans(device, limit=_num(q, "limit", 20, 0, 200))}


REGISTER_PER_CLIENT_HOUR = int(os.environ.get("SSC_REGISTER_PER_CLIENT_HOUR") or 10)
REGISTER_PER_DAY = int(os.environ.get("SSC_REGISTER_PER_DAY") or 200)


def h_register(app, q, b, m):
    """A laptop's app or Claude plugin gets its own scan key on first use, so nobody has to hand keys out.

    The key is made here (random, 256 bits) and returned once; only its SHA-256 is stored. It has the "scan" role
    only: it can send scans and read its own results, nothing else. Limited per address and per day, and off with
    SSC_SELF_REGISTER=0. Revoke one with `python3 -m intel_api keys revoke DEVICE`."""
    if not app.self_register:
        raise ApiError(403, "this server hands out no keys: ask its admin for a scan key")
    client = hashlib.sha256(app.client().encode()).hexdigest()[:16]
    hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds")
    day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
    if app.store.scan_keys_since(hour_ago, client) >= REGISTER_PER_CLIENT_HOUR:
        raise ApiError(429, "too many new keys from this address; try again in an hour")
    if app.store.scan_keys_since(day_ago) >= REGISTER_PER_DAY:
        raise ApiError(429, "this server has handed out its new keys for today; try again tomorrow")
    key = secrets.token_hex(32)
    device = scans.device_id(key)
    app.store.add_scan_key(scans.key_hash(key), device, str(b.get("device_name") or "")[:100], client)
    log(f"registered a scan key for {device} ({str(b.get('device_name') or '')[:100]})")
    return {"key": key, "role": "scan", "device": device}


def h_scanner_rules(app, q, b, m):
    """What the laptop scanner detects (config/scanner_rules.json): read at each scan, so detection improves
    without a new scanner build."""
    with open(os.path.join(CONFIG_DIR, "scanner_rules.json"), encoding="utf-8") as f:
        return json.load(f)


def h_agent_claim(app, q, b, m):
    """The agents container takes the oldest scan waiting for its advisory (a job not answered in time is offered again)."""
    stale = (datetime.now(timezone.utc) - timedelta(minutes=scans.AGENT_LEASE_MINUTES)).isoformat(timespec="seconds")
    pb = str(b.get("playbook") or "")[:40]
    if pb and pb != scans.current_playbook(app.store):
        app.store.record_run(scans.PLAYBOOK_KEY, True, state={"playbook": pb})  # the agents run a new playbook
    scan = app.store.claim_scan("advising", "agent_running", "agent_running", stale)
    if not scan:
        return {"job": None}
    previous = app.store.get_scan(scan["previous_id"]) if scan.get("previous_id") else None
    history = app.store.advices(scan["device"], scan["folder"])
    return {"job": {"id": scan["id"], "folder": scan["folder"], "files": scans.agent_files(scan, previous, history)}}


RETRIES = 1  # how many times the agents may correct an advisory that breaks a rule
MAX_ADVICE = 200_000  # characters of markdown, or of advice JSON


def _int(v, default):
    """An integer from a JSON body (true/false are not integers here)."""
    return v if isinstance(v, int) and not isinstance(v, bool) else default


def _checked_advice(app, scan, b, result):
    """Check structured advice against the scan (engine/advice.py). -> the markdown advisory the server writes from
    it; `result` gets the resolved advice and the problems found. Raises a 422 with the problems while the agents
    may still correct it, so they get another try."""
    scope = scan.get("scope") or {}
    projects = [p.get("project") for p in scope.get("projects") or [] if p.get("project")]
    unsupported = b.get("unsupported") if isinstance(b.get("unsupported"), list) else []
    resolved, problems = advice_mod.validate(
        b["advice_data"], result.get("assessment") or {}, projects, scans.done_keys(scope), unsupported[:50]
    )
    tries = [*result.get("advice_problems", {}).get("tries", []), problems]
    if problems and _int(b.get("attempt"), 1) <= RETRIES:
        app.store.update_scan(scan["id"], result={**result, "advice_problems": {"tries": tries}})
        raise ApiError(422, "the advisory breaks these rules; correct it and send it again", problems=problems)
    result["advice_problems"] = {
        "tries": tries,
        "dropped": problems,
        "support_checked": b.get("support_checked") is True,
    }
    if resolved is None:
        return None
    result["advice_data"] = resolved
    return advice_mod.render(resolved)


def h_agent_result(app, q, b, m):
    """The agents' advisory for a scan. Structured advice (advice_data) is checked against the scan first: one that
    breaks a rule is sent back with its problems (422) for the agents to correct, up to RETRIES times; after that,
    whatever still breaks a rule is left out, and the problems are kept with the scan. Markdown advice (an older
    agents container) is stored as it is."""
    scan = app.store.get_scan(m.group(1))
    if not scan:
        raise ApiError(404, "no such scan")
    if scan["status"] != "agent_running":
        raise ApiError(409, f"scan is {scan['status']}, not waiting for an advisory")
    advice = b.get("advice")
    if advice is not None and (not isinstance(advice, str) or len(advice) > MAX_ADVICE):
        raise ApiError(400, f"advice: markdown text, at most {MAX_ADVICE} characters")
    if b.get("advice_data") is not None and len(json.dumps(b["advice_data"])) > MAX_ADVICE:
        raise ApiError(400, f"advice_data: at most {MAX_ADVICE} characters of JSON")
    result = dict(scan.get("result") or {})
    if b.get("advice_data") is not None:
        advice = _checked_advice(app, scan, b, result)
    if advice and b.get("playbook"):  # which playbook wrote this advisory
        result["playbook"] = str(b["playbook"])[:40]
    cost = b.get("cost_usd")
    app.store.update_scan(  # one write: the advisory, its structured form and the playbook land together
        scan["id"],
        status="done",
        advice=advice or None,
        advice_status="written" if advice else "failed",
        agent_cost=float(cost) if isinstance(cost, (int, float)) and not isinstance(cost, bool) else None,
        error=None if advice else str(b.get("error") or "the agents wrote no advisory")[:500],
        result=result,
    )
    checks.report(app.store, scan["id"], log)  # logs what the finished result contradicts, if anything
    return {"ok": True, "id": scan["id"], "advice_status": "written" if advice else "failed"}


ROUTES = [  # method, pattern, role, handler
    ("GET", r"/v1/health", None, h_health),
    ("GET", r"/v1/openapi\.json", None, h_openapi),
    ("GET", r"/v1/sources", "read", h_sources),
    ("GET", r"/v1/signals", "read", h_signals),
    ("POST", r"/v1/lookup", "read", h_lookup),
    ("POST", r"/v1/packages/check", "read", h_check),
    ("GET", r"/v1/items", "read", h_items),
    ("GET", r"/v1/news", "read", h_news),
    ("GET", r"/v1/packages/([^/]+)/(@[^/]+/[^/]+|[^/]+)", "read", h_package),
    ("GET", r"/v1/search/([^/]+)", "read", h_search_results),
    ("GET", r"/v1/vendors/([^/]+)/signals", "read", h_vendor),
    ("GET", r"/v1/trust/ca-distrust", "read", h_ca_distrust),
    ("GET", r"/v1/trust/mozilla-roots", "read", h_mozilla_roots),
    ("GET", r"/v1/alerts", "read", h_alerts),
    ("GET", r"/v1/scope", "read", h_scope),
    ("POST", r"/v1/signals/breach-notices", "write", h_ingest),
    ("POST", r"/v1/admin/refresh", "admin", h_refresh),
    ("POST", r"/v1/register", None, h_register),
    ("POST", r"/v1/scans", "scan", h_scan_submit),
    ("GET", r"/v1/scans", "scan", h_scans_list),
    ("GET", r"/v1/scans/([^/]+)", "scan", h_scan_get),
    ("GET", r"/v1/scanner-rules", "scan", h_scanner_rules),
    ("POST", r"/v1/agents/claim", "agent", h_agent_claim),
    ("POST", r"/v1/agents/jobs/([^/]+)/result", "agent", h_agent_result),
]
