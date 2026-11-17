"""Background jobs: keep the database current for the scope in intel_api/config/scope.json.

  feed:<source>      every FeedSource, at its speed (urgent 10 min / regular 1 h / slow 1 day); only records about the scope are stored
  news_search        Google News per scope vendor / package / CA (each term on its own interval); results that
                     don't name the term are dropped
  social_search      social sources per scope vendor / package
  nvd_search         NVD keyword search per scope vendor / stack component
  package_evidence   registry + advisories for every scope package version
  articles           read security articles once, to find package versions in the body
  index              flatten any record not yet in the items table
  maintenance        fill missing dates, prune old news/social and anything no longer about the scope

Lookups of packages outside the scope happen on request (engine/evidence.lookup) and are stored too.
Settings: "collection" in intel_api/config/sources.json. Health of every job: GET /v1/sources.
"""

import time
import traceback
from datetime import datetime, timezone
from urllib.parse import quote

from .._paths import L
from ..core import scope as scope_mod
from ..core.models import signal
from ..sources import registry
from . import evidence
from . import index as indexer
from .queries import news_query
from .relevance import Relevance


def cfg(name):
    return (L.CONFIG.get("collection") or {}).get(name) or {}


def _age(ts):
    return float("inf") if not ts else (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).total_seconds()


class Job:
    key = None
    every = 3600

    @property
    def enabled(self):
        return cfg(self.config_key).get("enabled", True)

    config_key = None

    def due(self, store):
        st = store.source_state(self.key)
        return self.enabled and _age((st or {}).get("last_run_at")) >= self.every

    def run(self, store, log):
        raise NotImplementedError


# ---------------------------------------------------------------- feeds
class FeedJob(Job):
    def __init__(self, src):
        self.src, self.key, self.every = src, src.key, src.every_seconds

    @property
    def enabled(self):
        return self.src.enabled

    def run(self, store, log):
        st = store.source_state(self.key) or {}
        pulled, state = self.src.pull(st.get("state") or {})
        rel = Relevance(store)
        sigs = [x for x in pulled if rel.keep(x)]  # the feed is read whole; only records about the scope are stored
        new = set(store.upsert(sigs))
        indexer.index(store, store.signals_by_ids([x["id"] for x in sigs]))
        refreshed = 0
        for x in sigs:  # something new about a package: its stored evidence is out of date
            if x["id"] in new and x["subject"].get("type") == "package":
                refreshed += store.drop_evidence(x["subject"]["ecosystem"], x["subject"]["name"])
        return {
            "pulled": len(pulled),
            "items": len(sigs),
            "new": len(new),
            "evidence_dropped": refreshed,
            "state": state,
        }


# ---------------------------------------------------------------- scheduled searches
def watch_terms(store=None):
    """{term_type: {term: ecosystem-or-None}} from the scope (config/scope.json plus discovered packages)."""
    sc = scope_mod.load(store)
    return {
        "vendor": {t: None for v in sc.vendors for t in v["terms"][:3]},
        "package": {p["name"]: eco for (eco, _), p in sc.search_packages().items()},
        "certificate_authority": {c.split()[0]: None for c in sc.cas},
        "stack": dict.fromkeys(sc.stack),
    }


def flagged_packages(store):
    """Packages with malware history or an exploited vulnerability (for packages: "flagged")."""
    rows = store.items(kinds=["malicious", "exploited"], has_package=True, limit=100000)
    return {r["package"] for r in rows}


class SearchJob(Job):
    """Runs every few minutes; each term is re-searched on its own interval, oldest first, a few per run."""

    kind, term_types = None, ()

    def __init__(self):
        c = cfg(self.config_key)
        self.every = int(c.get("run_every_seconds", 300))

    def plan(self, store):
        c = cfg(self.config_key)
        terms = watch_terms(store)
        mode = c.get("packages", "all")
        flagged = flagged_packages(store) if mode == "flagged" else None
        due = []
        for tt in self.term_types:
            every = int(
                c.get(
                    "packages_every_seconds" if tt == "package" else "vendors_every_seconds",
                    c.get("every_seconds", 3600),
                )
            )
            for term in terms.get(tt, {}):
                if tt == "package" and flagged is not None and term.lower() not in flagged:
                    continue
                st = store.search_state(self.kind, term, tt)
                age = _age((st or {}).get("last_run_at"))
                if age >= every:
                    due.append((age, term, tt))
        due.sort(reverse=True)  # never-searched first, then the oldest
        return [(t, tt) for _, t, tt in due[: int(c.get("max_terms_per_run", 25))]]

    def due(self, store):
        return (
            self.enabled
            and _age((store.source_state(self.key) or {}).get("last_run_at")) >= self.every
            and bool(self.plan(store))
        )

    def store_results(self, store, term, tt, items):
        raise NotImplementedError

    def run(self, store, log):
        done, found, failed = 0, 0, 0
        for term, tt in self.plan(store):
            ok, n = self.search_term(store, term, tt)
            done, found, failed = done + 1, found + n, failed + (not ok)
        return {"terms": done, "items": found, "failed": failed}

    def keep(self, sig, term, tt, ecosystem):
        """Search engines return loose matches: keep only results that name the term."""
        return True

    def search_term(self, store, term, tt):
        c = cfg(self.config_key)
        query = news_query(term, tt) if self.kind == "news" else term
        eco = watch_terms(store).get(tt, {}).get(term)
        try:
            items = registry.search(self.kind, term=term, query=query, days=int(c.get("days", 45)))
            sigs = [x for x in self.store_results(store, term, tt, items) if self.keep(x, term, tt, eco)]
            ids = [x["id"] for x in sigs]
            store.upsert(sigs)
            indexer.index(store, store.signals_by_ids(ids))
            store.record_search(self.kind, term, tt, query, ids, True)
            return True, len(ids)
        except Exception as e:  # noqa: BLE001 - recorded in the term's search state (last_error)
            store.record_search(self.kind, term, tt, query, [], False, f"{type(e).__name__}: {e}")
            return False, 0


class NewsSearchJob(SearchJob):
    key = config_key = "news_search"
    kind = "news"
    term_types = ("vendor", "package", "certificate_authority")

    def keep(self, sig, term, tt, ecosystem):
        title = indexer.GOOGLE_PUBLISHER.sub("", sig["title"]) if sig["source"] == "News: Google News" else sig["title"]
        if tt == "package":
            return any(
                m
                for m in indexer.extract(title, "", "", {(ecosystem, term.lower()): term}, {})
                if m["subject_type"] == "package"
            )
        return L.mentions(term, title)

    def store_results(self, store, term, tt, items):
        return [
            signal(
                "News: " + i["source"] if not i["source"].startswith("News") else i["source"],
                "news",
                i["title"],
                url=i["url"],
                key=i["url"],
                published_at=i["date"].isoformat() if hasattr(i.get("date"), "isoformat") else i.get("date"),
                data={"summary": (i.get("summary") or "")[:400], "term": term},
            )
            for i in items
            if i.get("url")
        ]


class SocialSearchJob(SearchJob):
    key = config_key = "social_search"
    kind = "social"
    term_types = ("vendor", "package")

    def keep(self, sig, term, tt, ecosystem):
        return True  # the social sources already keep only posts that name the term and use a security word

    def store_results(self, store, term, tt, items):
        return [
            signal(
                p["source"] if p["source"].startswith("Social") else "Social: " + p["source"],
                "social",
                p.get("title", ""),
                url=p.get("url", ""),
                published_at=p.get("date") or None,
                data={"term": term, "engagement": p.get("engagement"), "author": p.get("author")},
            )
            for p in items
            if p.get("url")
        ]


class NvdSearchJob(SearchJob):
    key = config_key = "nvd_search"
    kind = "nvd"
    term_types = ("vendor", "stack")

    def store_results(self, store, term, tt, items):
        return [
            signal(
                "NVD",
                "vuln",
                f"{c['id']}: {c.get('summary', '')}"[:300],
                url=c.get("url", ""),
                key=c["id"],
                subject={"type": "cve", "name": c["id"]},
                published_at=c.get("published"),
                data={"cvss": c.get("cvss"), "summary": c.get("summary"), "term": term},
            )
            for c in items
            if c.get("id")
        ]


# ---------------------------------------------------------------- packages
class PackageEvidenceJob(Job):
    key = config_key = "package_evidence"

    def __init__(self):
        self.every = int(cfg(self.config_key).get("every_seconds", 21600))

    def run(self, store, log):
        deps = scope_mod.load(store).deps()
        errors = evidence.collect(store, deps) if deps else {}
        return {"packages": len(deps), "failed": len(errors)}


# ---------------------------------------------------------------- indexing + upkeep
class ArticlesJob(Job):
    key = config_key = "articles"
    every = 600

    @property
    def enabled(self):
        return cfg("article_text").get("enabled", True)

    def run(self, store, log):
        limit = int(cfg("article_text").get("max_per_run", 40))
        todo = [
            s
            for s in store.query(kinds=["news"], limit=3000)
            if not (s["data"] or {}).get("article_checked")
            and L.SEC_WORDS.search(s["title"])
            and s["url"].startswith("http")
            and "news.google.com" not in s["url"]
        ][:limit]
        rows = indexer.index(store, todo, fetch_articles=limit)
        return {"articles": len(todo), "rows": rows}


class IndexJob(Job):
    key = "index"
    every = 300

    @property
    def enabled(self):
        return True

    def run(self, store, log):
        todo = store.unindexed()
        return {"signals": len(todo), "rows": indexer.index(store, todo) if todo else 0}


class MaintenanceJob(Job):
    key = config_key = "maintenance"

    def __init__(self):
        self.every = int(cfg(self.config_key).get("every_seconds", 86400))

    def run(self, store, log):
        from ..core.dates import normalize

        filled = store.backfill_mentioned()
        for sid, aid in store.missing_dates():
            rec = (L.fetch("https://api.osv.dev/v1/vulns/" + quote(str(aid), safe=""), "OSV") or {}) if aid else {}
            if rec.get("published"):
                store.set_published(sid, normalize(rec["published"]))
                filled += 1
        pruned = store.prune(days=int(cfg(self.config_key).get("prune_days", 120)))
        out_of_scope = prune_out_of_scope(store)
        return {"dates_filled": filled, "pruned": pruned, "out_of_scope_removed": out_of_scope}


def all_jobs():
    """Every job, in run order: feeds first (they may drop stale package evidence), then searches, packages, upkeep."""
    feeds = [FeedJob(s) for s in registry.feeds(enabled_only=False).values()]
    return [
        *feeds,
        NewsSearchJob(),
        SocialSearchJob(),
        NvdSearchJob(),
        PackageEvidenceJob(),
        ArticlesJob(),
        IndexJob(),
        MaintenanceJob(),
    ]


def prune_out_of_scope(store):
    """Remove records that are no longer about the scope (e.g. after editing scope.json)."""
    rel = Relevance(store)
    return store.delete_signals([x["id"] for x in store.query(limit=1000000) if not rel.keep(x)])


SEARCH_JOBS = {"news": NewsSearchJob, "social": SocialSearchJob, "nvd": NvdSearchJob}


def search_now(store, kind, term, term_type):
    """Search one term now (a lookup asked about something not searched yet) and store the results."""
    return SEARCH_JOBS[kind]().search_term(store, term, term_type)


def get(key):
    return next((j for j in all_jobs() if j.key == key), None)


def run_job(store, job, log):
    t0 = time.time()
    # the connectors keep "now" (date windows such as NVD's pubEndDate) and some caches in module globals:
    # bring them up to date before every job, not only when a package lookup happens to run
    evidence.refresh_clock()
    try:
        res = job.run(store, log) or {}
        state = res.pop("state", None)
        store.record_run(
            job.key,
            True,
            items=res.get("items", res.get("packages", res.get("terms", 0))),
            new_items=res.get("new", 0),
            state=state,
        )
        log(f"{job.key}: {res} ({time.time() - t0:.0f}s)")
        return {"key": job.key, "ok": True, **res}
    except Exception as e:  # noqa: BLE001 - recorded in the job's health (GET /v1/sources) and logged
        store.record_run(job.key, False, error=f"{type(e).__name__}: {e}")
        log(f"{job.key}: FAILED {type(e).__name__}: {e}\n" + traceback.format_exc(limit=3))
        return {"key": job.key, "ok": False, "error": str(e)}
