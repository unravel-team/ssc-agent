"""Package evidence and searches, on request, with a short cache.

check() returns exactly what the gatekeeper builds locally ({registry, typosquat_of, vulns, social}) by
calling the gatekeeper's own functions; vulns include findings from every PackageSource in the registry.
So verdicts are the same whether a client uses the API or not. Everything found is also stored as signals.
"""

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from .._paths import L
from ..core.models import signal
from ..core.store import version_key
from ..lib import packages as P
from ..sources import registry
from . import index as indexer

# Which version of the lookup code collected a stored result: a fingerprint of the files that decide what a package's
# evidence says. A result collected by other code is stale however recent it is, so a fixed lookup takes effect on the
# next scan instead of a day later.
_CODE = [
    Path(__file__).resolve().parents[1] / f for f in ("lib/packages.py", "lib/connectors.py", "engine/evidence.py")
]
COLLECTOR = hashlib.sha256(b"".join(f.read_bytes() for f in _CODE)).hexdigest()[:12]

_warm = {"kev": 0.0, "ranks": 0.0}


def refresh_clock():
    """The connectors were written for one-shot runs: keep 'now' and their in-memory caches fresh in a long-running service."""
    g = P
    now = datetime.now(timezone.utc)
    L.NOW = g.NOW = now
    t = time.time()
    if t - _warm["kev"] > 6 * 3600:
        g._KEV = None
        L._KEV = None
        _warm["kev"] = t
    if t - _warm["ranks"] > 24 * 3600:
        g._RANK = {}
        _warm["ranks"] = t  # replaced, not cleared, so readers mid-lookup keep a whole dict


def _evidence(dep, social, resolve_latest):
    g = P
    dep = dict(dep)
    reg = g.registry(dep)
    if resolve_latest and not dep.get("version") and reg.get("latest"):
        dep["version"] = reg["latest"]  # what an installer would pick
        reg = g.registry(dep)
    ev = {"registry": reg, "typosquat_of": g.typosquat(dep), "vulns": g.vulns_all(dep), "social": []}
    if social:
        ev["social"] = g.social(dep)
        ev["social_checked"] = True
    return dep.get("version"), ev


def _signals_for(dep, version, ev):
    out = []
    subj = {"type": "package", "ecosystem": dep["ecosystem"], "name": dep["name"]}
    for v in ev["vulns"]:
        mal = v.get("malicious") or v.get("malicious_other_version")
        hit = bool(version) and not v.get("malicious_other_version")
        src = v["source"].split(" + ")[0]
        out.append(
            signal(
                src,
                "malicious" if mal else ("exploited" if v.get("in_kev") else "vuln"),
                f"{v['id']}: {dep['name']} - {v.get('summary') or ''}"[:300],
                url=v.get("url") or f"https://osv.dev/vulnerability/{v['id']}",
                key=v["id"],
                subject=subj,
                published_at=v.get("published"),
                reliability=_rating(src)[0],
                may_block=_rating(src)[1],
                data={
                    "id": v["id"],
                    "cves": v.get("cves", []),
                    "severity": v.get("severity"),
                    "fixed_in": v.get("fixed_in", []),
                    "in_kev": v.get("in_kev"),
                    "in_vulncheck_kev": v.get("in_vulncheck_kev"),
                    "epss_max": v.get("epss_max"),
                    "versions": v.get("versions", []),
                    "versions_hit": [version] if hit else [],
                },
            )
        )
    return out  # social posts are stored by the social_search job (one copy per post)


def _rating(label):
    """(reliability, may_block) for a finding's source: the registered source's rating, else the config's."""
    s = next((s for s in registry.all_sources().values() if s.label == label), None)
    return (s.reliability, s.may_block) if s else (L.reliability(label), L.may_block(label))


def check(deps, store=None, social=False, resolve_latest=False, workers=8):
    """deps = [{ecosystem, name, version}] -> [{ecosystem, name, version, resolved_version, evidence, cached}] in order."""
    g = P
    refresh_clock()
    g.kev_set()
    for eco in {d["ecosystem"] for d in deps}:
        g.ranks(eco)
    need = list(deps)  # malware history is fetched fresh for every lookup
    for d, ids in zip(need, L.osv_batch(need, with_version=False) if need else []):
        g.MAL_HISTORY[(d["ecosystem"], d["name"].lower())] = [i for i in ids if i.startswith("MAL-")]
    registry.prepare_packages(deps)

    def one(d):
        try:
            version, ev = _evidence(d, social, resolve_latest)
        except Exception as e:  # noqa: BLE001 - one package failing must not sink the batch (error is returned)
            return {**d, "error": f"{type(e).__name__}: {e}"[:200]}
        if store is not None:
            store.upsert(_signals_for(d, version, ev))
        return {**d, "resolved_version": version, "evidence": ev}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, deps))


# ---------------------------------------------------------------- background collection -> DB, and DB reads for the API
def collect(store, deps, resolve_latest=False):
    """Query the sources for these packages and store the evidence plus signals and item rows.
    -> {(ecosystem, name_lower, version): error} for packages that could not be looked up."""
    res = check(deps, store=None, resolve_latest=resolve_latest)
    errors = {}
    for r in res:
        if r.get("error"):
            errors[(r["ecosystem"], r["name"].lower(), r.get("version") or "")] = r["error"]
            continue
        dep = {"ecosystem": r["ecosystem"], "name": r["name"], "version": r.get("version")}
        sigs = _signals_for(dep, r["resolved_version"], r["evidence"])  # registry facts stay in the evidence only
        store.upsert(sigs)
        indexer.index(store, store.signals_by_ids([s["id"] for s in sigs]))
        store.put_evidence(
            dep["ecosystem"],
            dep["name"],
            version_key(dep["version"], resolve_latest),
            r["resolved_version"],
            {**r["evidence"], "collector": COLLECTOR},
        )
    return errors


def _age_adjusted(ev, collected_at):
    """Registry ages were computed when collected; move them forward so cooling-off checks stay correct."""
    elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(collected_at)).total_seconds() / 86400
    reg = dict(ev["registry"])
    for k in ("first_release_days", "version_age_days"):
        if isinstance(reg.get(k), (int, float)):
            reg[k] = round(reg[k] + elapsed, 2)
    return {**ev, "registry": reg}


def stored_social(store, dep, days=120):
    """Social posts the background search stored for this package (None if the term hasn't been searched yet)."""
    st = store.search_state("social", dep["name"], "package")
    if not st or not st.get("last_ok_at"):
        return None
    g = P
    cut = datetime.now(timezone.utc).date().toordinal() - days
    posts = []
    for sg in store.search_items("social", dep["name"], "package"):
        date = (sg["published_at"] or "")[:10]
        if date and datetime.fromisoformat(date).toordinal() < cut:
            continue
        p = {
            "source": sg["source"].replace("Social: ", ""),
            "title": sg["title"],
            "url": sg["url"],
            "date": date or None,
            "engagement": (sg["data"] or {}).get("engagement"),
        }
        if g.common_word(dep["name"]) and not g.PKG_CONTEXT.search(p["title"]):
            continue
        p["other_version"] = g.other_version(p["title"], dep.get("version") or "")
        posts.append(p)
    return posts


def _fresh(store, d, resolve_latest, max_age_hours):
    hit = store.get_evidence(d["ecosystem"], d["name"], version_key(d.get("version"), resolve_latest))
    if (
        hit
        and hit["evidence"].get("collector") == COLLECTOR  # collected by the lookup code running now
        and (datetime.now(timezone.utc) - datetime.fromisoformat(hit["collected_at"])).total_seconds() / 3600
        <= max_age_hours
    ):
        return hit
    return None


def lookup(store, deps, resolve_latest=False, social=False, max_age_hours=24, track=True, origin="lookup"):
    """Stored evidence when it is fresh enough; otherwise fetch from the sources now, store, and return it.
    -> one result per dep, in order: {ecosystem, name, version, resolved_version, collected_at, status, evidence}
    with status "stored" (from the database), "fetched" (looked up now) or "error".
    With `track`, a version the database had never seen is also added to the scope (core/scope.track), so the
    background jobs keep it current from then on."""
    out, todo, unseen = [None] * len(deps), [], []
    for i, d in enumerate(deps):
        hit = _fresh(store, d, resolve_latest, max_age_hours)
        if hit:
            out[i] = {**d, "status": "stored", **hit}
        else:
            todo.append(i)
            if track and not store.get_evidence(
                d["ecosystem"], d["name"], version_key(d.get("version"), resolve_latest)
            ):
                unseen.append(i)
    if todo:
        errors = collect(store, [deps[i] for i in todo], resolve_latest=resolve_latest)
        for i in todo:
            d = deps[i]
            hit = store.get_evidence(d["ecosystem"], d["name"], version_key(d.get("version"), resolve_latest))
            err = errors.get((d["ecosystem"], d["name"].lower(), d.get("version") or ""))
            out[i] = (
                {**d, "status": "fetched", **hit}
                if hit and not err
                else {**d, "status": "error", "error": err or "lookup failed"}
            )
    found = [deps[i] for i in unseen if out[i]["status"] != "error"]
    if found:
        from ..core import scope as scope_mod

        scope_mod.track(store, found, origin)
    for r in out:
        if r["status"] == "error":
            continue
        r["evidence"] = _age_adjusted({k: v for k, v in r["evidence"].items() if k != "collector"}, r["collected_at"])
        if social:
            dep = {**r, "version": r.get("resolved_version") or r.get("version")}
            posts = stored_social(store, dep)
            if posts is None:  # never searched: search now, store, then read
                from .jobs import search_now

                search_now(store, "social", r["name"], "package")
                posts = stored_social(store, dep)
            r["evidence"] = {**r["evidence"], "social": posts or [], "social_checked": posts is not None}
    return out
