"""The store: raw records (signals), the generic items table, package evidence, scheduled searches and job health.

Two backends, same SQL:
  Postgres  when SSC_INTEL_DB_URL is set (postgresql://user:pass@host:5432/db): the server deployment (intel_api/DEPLOY.md).
            Needs the psycopg driver (Poetry group `server` in pyproject.toml); a small built-in pool shares connections between threads.
  SQLite    otherwise: intel_api/data/intel_api.sqlite (override with SSC_INTEL_DB). Local runs and the tests; stdlib only.

The SQL is written once with "?" placeholders and ON CONFLICT upserts, which both databases understand
(the Postgres adapter swaps "?" for "%s"). Writes are serialised in-process, as one API process owns the database.
"""

import json
import logging
import os
import queue
import re
import sqlite3
import threading
import time
from contextlib import contextmanager, nullcontext, suppress
from datetime import datetime, timedelta, timezone
from typing import ClassVar

from .._paths import DATA_DIR
from .models import dumps, now_iso

log = logging.getLogger(__name__)

# DATABASE_URL: what hosts like Fly.io set when a database is attached to the app
DB_URL = os.environ.get("SSC_INTEL_DB_URL") or os.environ.get("DATABASE_URL") or ""
DB_PATH = os.environ.get("SSC_INTEL_DB") or os.path.join(DATA_DIR, "intel_api.sqlite")
POOL_SIZE = int(os.environ.get("SSC_INTEL_DB_POOL") or 10)

TABLES = {
    "signals": (
        "id TEXT PRIMARY KEY, source TEXT, reliability INTEGER, may_block INTEGER, kind TEXT, "
        "subject_type TEXT, ecosystem TEXT, name TEXT, subject TEXT, "
        "title TEXT, url TEXT, published_at TEXT, first_seen_at TEXT, last_seen_at TEXT, data TEXT, indexed_at TEXT"
    ),
    "sources": "key TEXT PRIMARY KEY, last_run_at TEXT, last_ok_at TEXT, last_error TEXT, items INTEGER, new_items INTEGER, state TEXT",
    # every item from every source, flattened: one row per item x package x version (package empty when it names none)
    "items": (
        "signal_id TEXT, kind TEXT, package TEXT, version TEXT, package_manager TEXT, "
        "source TEXT, title TEXT, description TEXT, url TEXT, date TEXT, severity TEXT, "
        "PRIMARY KEY (signal_id, package_manager, package, version)"
    ),
    # scheduled searches (news / social / nvd) per watched term, and the items each one found
    "search_terms": (
        "kind TEXT, term TEXT, term_type TEXT, query TEXT, last_run_at TEXT, last_ok_at TEXT, items INTEGER, "
        "last_error TEXT, PRIMARY KEY (kind, term, term_type)"
    ),
    "search_hits": "kind TEXT, term TEXT, term_type TEXT, signal_id TEXT, seen_at TEXT, PRIMARY KEY (kind, term, term_type, signal_id)",
    # package evidence collected in the background or on a lookup miss; lookups serve only this
    "package_evidence": (
        "ecosystem TEXT, name TEXT, version_key TEXT, resolved_version TEXT, evidence TEXT, collected_at TEXT, "
        "PRIMARY KEY (ecosystem, name, version_key)"
    ),
    # the package versions the background jobs keep current: seeded from config/scope.json, then grown by lookups
    # (core/scope.py). name is lower case (display_name keeps the spelling); version "" means the latest
    "scope_packages": (
        "package_manager TEXT, name TEXT, version TEXT, display_name TEXT, origin TEXT, added_at TEXT, "
        "PRIMARY KEY (package_manager, name, version)"
    ),
    # scans sent by laptop scanners (engine/scans.py): the scope in, the assessment and the agents' advisory out
    "scans": (
        "id TEXT PRIMARY KEY, device TEXT, device_name TEXT, folder TEXT, status TEXT, created_at TEXT, updated_at TEXT, "
        "scope TEXT, result TEXT, advice TEXT, advice_status TEXT, error TEXT, claimed_at TEXT, agent_cost REAL, previous_id TEXT"
    ),
    # scan keys laptops registered for themselves (POST /v1/register): only a SHA-256 of each key is kept. device is
    # the id scans are filed under (engine/scans.device_id); client is a hash of the address it registered from
    "scan_keys": (
        "key_hash TEXT PRIMARY KEY, device TEXT, device_name TEXT, client TEXT, created_at TEXT, revoked_at TEXT"
    ),
}
INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_sig_first ON signals(first_seen_at)",
    "CREATE INDEX IF NOT EXISTS ix_sig_subject ON signals(subject_type, ecosystem, name)",
    "CREATE INDEX IF NOT EXISTS ix_sig_kind ON signals(kind)",
    "CREATE INDEX IF NOT EXISTS ix_sig_unindexed ON signals(indexed_at)",
    "CREATE INDEX IF NOT EXISTS ix_items_pkg ON items(package_manager, package, version)",
    "CREATE INDEX IF NOT EXISTS ix_items_kind ON items(kind, date)",
    "CREATE INDEX IF NOT EXISTS ix_items_date ON items(date)",
    "CREATE INDEX IF NOT EXISTS ix_scans_device ON scans(device, folder, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_scans_status ON scans(status, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_scope_origin ON scope_packages(origin, added_at)",
    "CREATE INDEX IF NOT EXISTS ix_scan_keys_created ON scan_keys(created_at, client)",
]
COLUMNS = {
    t: [c.split()[0] for c in re.split(r",\s*(?![^()]*\))", d) if not c.startswith("PRIMARY")]
    for t, d in TABLES.items()
}
KEYS = {
    "signals": ["id"],
    "sources": ["key"],
    "items": ["signal_id", "package_manager", "package", "version"],
    "search_terms": ["kind", "term", "term_type"],
    "search_hits": ["kind", "term", "term_type", "signal_id"],
    "package_evidence": ["ecosystem", "name", "version_key"],
    "scans": ["id"],
    "scope_packages": ["package_manager", "name", "version"],
    "scan_keys": ["key_hash"],
}


def upsert_sql(table, ignore=False):
    """INSERT that replaces (or, with ignore, keeps) a row with the same primary key. Valid in SQLite and Postgres."""
    cols, keys = COLUMNS[table], KEYS[table]
    sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))}) ON CONFLICT ({', '.join(keys)}) DO "
    if ignore:
        return sql + "NOTHING"
    return sql + "UPDATE SET " + ", ".join(f"{c} = excluded.{c}" for c in cols if c not in keys)


def version_key(version, resolve_latest=False):
    """Key for a stored package check: the exact version, 'latest' (installer picks newest) or '' (unpinned)."""
    return "latest" if resolve_latest and not version else (version or "")


class Row(dict):
    """A result row: by column name (r["id"]) or position (r[0]), like sqlite3.Row, on both backends."""

    def __getitem__(self, k):
        return list(self.values())[k] if isinstance(k, int) else dict.__getitem__(self, k)


class _Conn:
    """One connection inside a transaction: q() -> rows, one() -> row or None, run() -> rows changed."""

    def __init__(self, raw, postgres):
        self.raw, self.pg = raw, postgres

    def _sql(self, sql):
        return sql.replace("%", "%%").replace("?", "%s") if self.pg else sql

    @contextmanager
    def _cur(self, sql, args):
        cur = self.raw.cursor()
        try:
            cur.execute(self._sql(sql), tuple(args or ()))
            yield cur
        finally:
            cur.close()

    def q(self, sql, args=()):
        with self._cur(sql, args) as cur:
            if cur.description is None:
                return []
            names = [d[0] for d in cur.description]
            return [Row(zip(names, r)) for r in cur.fetchall()]

    def one(self, sql, args=()):
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def run(self, sql, args=()):
        with self._cur(sql, args) as cur:
            return cur.rowcount

    def many(self, sql, rows):
        rows = list(rows)
        if rows:
            cur = self.raw.cursor()
            try:
                cur.executemany(self._sql(sql), rows)
            finally:
                cur.close()


class _PgPool:
    """A few Postgres connections shared by the request and job threads.

    Hosted databases (Fly.io's goes through PgBouncer) may drop a connection without telling the client. A query sent
    on such a connection would wait forever, while its thread may hold the write lock everyone else needs. So:
    connections idle for more than MAX_IDLE are not reused, TCP keepalives and a user timeout turn a dead connection
    into an error within about half a minute, and automatic prepared statements are off (they break behind a pooler).
    """

    MAX_IDLE = 60  # seconds
    CONNECT: ClassVar[dict] = {
        "connect_timeout": 10,
        "keepalives": 1,
        "keepalives_idle": 30,
        "keepalives_interval": 10,
        "keepalives_count": 3,
        "tcp_user_timeout": 30000,  # ms: sent data not acknowledged for this long -> the connection is dead
        "prepare_threshold": None,
    }

    def __init__(self, url, size):
        import psycopg  # only needed on the server (Poetry group `server`)

        self.psycopg, self.url, self.size = psycopg, url, size
        self.free, self.made, self.lock = queue.LifoQueue(), 0, threading.Lock()

    def _forget(self, c):
        with self.lock:
            self.made -= 1
        with suppress(Exception):  # it is being thrown away
            c.close()

    CONNECT_TRIES = 3

    def _connect(self):
        """A new connection. The pooler in front of a hosted database sometimes drops one while it is being opened
        ("server closed the connection unexpectedly"): that is tried again a couple of times, briefly."""
        for attempt in range(self.CONNECT_TRIES):
            try:
                return self.psycopg.connect(self.url, **self.CONNECT)
            except self.psycopg.OperationalError as e:
                if attempt == self.CONNECT_TRIES - 1:
                    raise
                log.warning("database connection failed (%s); trying again", str(e).splitlines()[0][:200])
                time.sleep(0.5 * 2**attempt)
        raise AssertionError("unreachable")

    def get(self, wait=60):
        while True:
            try:
                c, idle_since = self.free.get_nowait()
            except queue.Empty:
                with self.lock:
                    make = self.made < self.size
                    if make:
                        self.made += 1
                if make:
                    try:
                        return self._connect()
                    except BaseException:
                        with self.lock:
                            self.made -= 1
                        raise
                try:
                    c, idle_since = self.free.get(timeout=wait)
                except queue.Empty:
                    raise RuntimeError(f"no database connection free after {wait}s (pool of {self.size})") from None
            if not (c.closed or c.broken) and time.monotonic() - idle_since < self.MAX_IDLE:
                return c
            self._forget(c)  # dead or idle too long (maybe dropped by the server): take or make another

    def put(self, c):
        if c.closed or c.broken:
            self._forget(c)
        else:
            self.free.put((c, time.monotonic()))


class Store:
    def __init__(self, path=None, url=None):
        """Store(path) = SQLite file; Store(url=...) = Postgres; Store() = SSC_INTEL_DB_URL if set, else the SQLite file."""
        self.url = url if url is not None else ("" if path else DB_URL)
        self.pg = bool(self.url)
        self.path = None if self.pg else (path or DB_PATH)
        self._local = threading.local()
        self._write = threading.Lock()
        if self.pg:
            self._pool = _PgPool(self.url, POOL_SIZE)
        else:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with self.tx(write=True) as c:
            if not self.pg:
                c.run("PRAGMA journal_mode=WAL")
                self._migrate_sqlite(c)
            for t, d in TABLES.items():
                c.run(f"CREATE TABLE IF NOT EXISTS {t} ({d})")
            if not self.pg:
                self._add_indexed_at(c)
            for ix in INDEXES:
                c.run(ix)
            self._normalize_dates(c)

    @property
    def where(self):
        """The database, for display (no password)."""
        return re.sub(r"//[^@/]*@", "//", self.url) if self.pg else self.path

    # ------------------------------------------------------------ connections and transactions
    def _sqlite(self):
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30)
            self._local.c = c
        return c

    @contextmanager
    def tx(self, write=False):
        """A transaction: commits at the end, rolls back on an error. Writes are serialised."""
        # the lock is taken first and always released, also when no connection can be had (database down):
        # a leaked write lock would block every later write
        with self._write if write else nullcontext():
            raw = self._pool.get() if self.pg else self._sqlite()
            try:
                yield _Conn(raw, self.pg)
                raw.commit()
            except BaseException:
                try:
                    raw.rollback()
                except Exception:  # e.g. the connection died; the original error matters more
                    log.warning("rollback failed", exc_info=True)
                raise
            finally:
                if self.pg:
                    self._pool.put(raw)

    def _q(self, sql, args=()):
        with self.tx() as c:
            return c.q(sql, args)

    def _one(self, sql, args=()):
        with self.tx() as c:
            return c.one(sql, args)

    # ------------------------------------------------------------ SQLite migrations (older local databases)
    @staticmethod
    def _migrate_sqlite(c):
        c.run("DROP TABLE IF EXISTS watchlists")  # replaced by config/scope.json
        c.run("DROP TABLE IF EXISTS package_queue")  # replaced by fetch-on-lookup
        cols = {r[1] for r in c.q("PRAGMA table_info(items)")}
        if cols and "description" not in cols:  # items is derived: drop an old layout, the index job rebuilds it
            c.run("DROP TABLE items")
            if c.one("SELECT name FROM sqlite_master WHERE name='signals'"):
                c.run("UPDATE signals SET data = json_remove(data, '$.indexed_at')")

    @staticmethod
    def _add_indexed_at(c):
        """indexed_at used to live inside the data JSON; it is a column now (portable to Postgres)."""
        if "indexed_at" not in {r[1] for r in c.q("PRAGMA table_info(signals)")}:
            c.run("ALTER TABLE signals ADD COLUMN indexed_at TEXT")
            c.run("UPDATE signals SET indexed_at = json_extract(data, '$.indexed_at')")

    @staticmethod
    def _normalize_dates(c):
        """Older rows may hold local-time offsets (-05:00, +05:30): convert to UTC so date filters and sorting work."""
        from .dates import normalize

        for r in c.q(
            "SELECT id, published_at FROM signals WHERE length(published_at) > 10 AND published_at NOT LIKE '%+00:00'"
        ):
            c.run("UPDATE signals SET published_at=? WHERE id=?", (normalize(r["published_at"]), r["id"]))

    # ------------------------------------------------------------ signals
    def upsert(self, signals):
        """Insert new signals, refresh last_seen on known ones. Returns the ids that were new."""
        if not signals:
            return []
        ts, new = now_iso(), []
        with self.tx(write=True) as c:
            for s in signals:
                sub = s["subject"]
                row = c.one("SELECT data FROM signals WHERE id=?", (s["id"],))
                if row is None:
                    c.run(
                        "INSERT INTO signals (id, source, reliability, may_block, kind, subject_type, ecosystem, name, subject, "
                        "title, url, published_at, first_seen_at, last_seen_at, data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            s["id"],
                            s["source"],
                            s["reliability"],
                            int(s["may_block"]),
                            s["kind"],
                            sub.get("type"),
                            sub.get("ecosystem"),
                            (sub.get("name") or "").lower() or None,
                            dumps(sub),
                            s["title"],
                            s["url"],
                            s["published_at"],
                            ts,
                            ts,
                            dumps(s["data"]),
                        ),
                    )
                    new.append(s["id"])
                else:
                    data = json.loads(row["data"] or "{}")
                    for k, v in (s["data"] or {}).items():  # merge list fields (e.g. versions seen affected)
                        if isinstance(v, list) and isinstance(data.get(k), list):
                            data[k] = sorted(set(map(str, data[k])) | set(map(str, v)))
                        else:
                            data[k] = v
                    c.run(
                        "UPDATE signals SET last_seen_at=?, title=?, reliability=?, data=?, "
                        "published_at=COALESCE(published_at, ?) WHERE id=?",
                        (ts, s["title"], s["reliability"], dumps(data), s["published_at"], s["id"]),
                    )
        return new

    def query(
        self,
        since=None,
        kinds=None,
        min_reliability=None,
        subject_type=None,
        ecosystem=None,
        name=None,
        source=None,
        published_since=None,
        limit=500,
    ):
        q, args = "SELECT * FROM signals WHERE 1=1", []
        if since:
            q += " AND first_seen_at > ?"
            args.append(since)
        if published_since:
            q += " AND (published_at IS NULL OR published_at >= ?)"
            args.append(published_since)
        if kinds:
            q += f" AND kind IN ({','.join('?' * len(kinds))})"
            args += list(kinds)
        if min_reliability:
            q += " AND reliability >= ?"
            args.append(int(min_reliability))
        if subject_type:
            q += " AND subject_type = ?"
            args.append(subject_type)
        if ecosystem:
            q += " AND ecosystem = ?"
            args.append(ecosystem)
        if name:
            q += " AND name = ?"
            args.append(name.lower())
        if source:
            q += " AND source = ?"
            args.append(source)
        q += " ORDER BY first_seen_at DESC, (published_at IS NULL), published_at DESC LIMIT ?"
        args.append(int(limit))
        return [self._row(r) for r in self._q(q, args)]

    @staticmethod
    def _row(r):
        return {
            "id": r["id"],
            "source": r["source"],
            "reliability": r["reliability"],
            "may_block": bool(r["may_block"]),
            "kind": r["kind"],
            "subject": json.loads(r["subject"] or "{}"),
            "title": r["title"],
            "url": r["url"],
            "published_at": r["published_at"],
            "first_seen_at": r["first_seen_at"],
            "last_seen_at": r["last_seen_at"],
            "data": json.loads(r["data"] or "{}"),
        }

    def prune(self, kinds=("news", "social"), days=120):
        cut = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self.tx(write=True) as c:
            n = c.run(
                f"DELETE FROM signals WHERE kind IN ({','.join('?' * len(kinds))}) AND last_seen_at < ?", (*kinds, cut)
            )
            c.run("DELETE FROM items WHERE signal_id NOT IN (SELECT id FROM signals)")
            c.run("DELETE FROM search_hits WHERE signal_id NOT IN (SELECT id FROM signals)")
        return n

    def missing_dates(self, limit=200):
        """(signal id, advisory id) for package advisories stored without a publish date."""
        return [
            (r["id"], json.loads(r["data"] or "{}").get("id"))
            for r in self._q(
                "SELECT id, data FROM signals WHERE published_at IS NULL AND subject_type='package' "
                "AND kind IN ('vuln','malicious','exploited') LIMIT ?",
                (limit,),
            )
        ]

    def backfill_mentioned(self):
        """Add mentioned_dates to news/social/breach rows stored before date extraction existed."""
        from .dates import mentioned

        n = 0
        with self.tx(write=True) as c:
            for r in c.q(
                "SELECT id, title, data FROM signals WHERE kind IN ('news','social','breach') "
                "AND data NOT LIKE '%mentioned_dates%'"
            ):
                d = json.loads(r["data"] or "{}")
                found = mentioned(f"{r['title'] or ''} {d.get('summary') or ''}")
                if found:
                    d["mentioned_dates"] = found
                    c.run("UPDATE signals SET data=? WHERE id=?", (dumps(d), r["id"]))
                    n += 1
        return n

    def set_published(self, sid, published_at):
        with self.tx(write=True) as c:
            c.run("UPDATE signals SET published_at=? WHERE id=? AND published_at IS NULL", (published_at, sid))

    # ------------------------------------------------------------ source health + connector state
    def source_state(self, key):
        r = self._one("SELECT * FROM sources WHERE key=?", (key,))
        return {**r, "state": json.loads(r["state"] or "{}")} if r else None

    def record_run(self, key, ok, items=0, new_items=0, error=None, state=None):
        ts = now_iso()
        with self.tx(write=True) as c:  # read and write under the write lock, so two runs can't interleave
            r = c.one("SELECT last_ok_at, state FROM sources WHERE key=?", (key,))
            prev = {"last_ok_at": r["last_ok_at"], "state": json.loads(r["state"] or "{}")} if r else {}
            c.run(
                upsert_sql("sources"),
                (
                    key,
                    ts,
                    ts if ok else prev.get("last_ok_at"),
                    None if ok else str(error)[:300],
                    items,
                    new_items,
                    dumps(state if state is not None else prev.get("state") or {}),
                ),
            )

    def sources(self):
        return {
            r["key"]: {k: v for k, v in r.items() if k not in ("key", "state")}
            for r in self._q("SELECT * FROM sources")
        }

    # ------------------------------------------------------------ items: the generic structured table
    ITEM_COLS = tuple(COLUMNS["items"])

    def put_items(self, signal_id, rows):
        """Replace the item rows of one signal (rows come from engine/index.py)."""
        with self.tx(write=True) as c:
            c.run("DELETE FROM items WHERE signal_id=?", (signal_id,))
            for r in rows:
                r = {
                    **r,
                    "signal_id": signal_id,
                    "package": (r.get("package") or "").lower(),
                    "version": r.get("version") or "",
                    "package_manager": r.get("package_manager") or "",
                }
                c.run(upsert_sql("items"), tuple(r.get(k) for k in self.ITEM_COLS))
            c.run("UPDATE signals SET indexed_at=? WHERE id=?", (now_iso(), signal_id))

    def items(
        self,
        kinds=None,
        package=None,
        version=None,
        package_manager=None,
        source=None,
        severity=None,
        published_since=None,
        has_package=None,
        limit=500,
    ):
        q, args = "SELECT * FROM items WHERE 1=1", []
        for col, val in (
            ("package", (package or "").lower() or None),
            ("version", version),
            ("package_manager", package_manager),
            ("source", source),
            ("severity", severity),
        ):
            if val is not None:
                q += f" AND {col} = ?"
                args.append(val)
        if kinds:
            q += f" AND kind IN ({','.join('?' * len(kinds))})"
            args += list(kinds)
        if published_since:
            q += " AND date >= ?"
            args.append(published_since)
        if has_package is not None:
            q += " AND package != ''" if has_package else " AND package = ''"
        q += " ORDER BY (date IS NULL), date DESC LIMIT ?"
        args.append(int(limit))
        return [{k: (v if v != "" else None) for k, v in r.items()} for r in self._q(q, args)]

    def unindexed(self, limit=5000):
        """Signals (any source) not yet flattened into items."""
        return [
            self._row(r)
            for r in self._q(
                "SELECT * FROM signals WHERE indexed_at IS NULL ORDER BY first_seen_at DESC LIMIT ?", (limit,)
            )
        ]

    def item_stats(self):
        with self.tx() as c:
            return {
                "rows": c.one("SELECT COUNT(*) FROM items")[0],
                "by_kind": {r[0]: r[1] for r in c.q("SELECT kind, COUNT(*) FROM items GROUP BY kind")},
                "with_package": c.one("SELECT COUNT(*) FROM items WHERE package != ''")[0],
                "with_version": c.one("SELECT COUNT(*) FROM items WHERE version != ''")[0],
            }

    def set_data(self, sid, extra):
        """Merge keys into one signal's data."""
        with self.tx(write=True) as c:
            r = c.one("SELECT data FROM signals WHERE id=?", (sid,))
            if r:
                c.run("UPDATE signals SET data=? WHERE id=?", (dumps({**json.loads(r["data"] or "{}"), **extra}), sid))

    def signals_by_ids(self, ids):
        out, ids = [], list(ids)
        for i in range(0, len(ids), 500):
            chunk = ids[i : i + 500]
            out += [
                self._row(r)
                for r in self._q(f"SELECT * FROM signals WHERE id IN ({','.join('?' * len(chunk))})", chunk)
            ]
        return out

    # ------------------------------------------------------------ scheduled searches
    def search_state(self, kind, term, term_type):
        r = self._one("SELECT * FROM search_terms WHERE kind=? AND term=? AND term_type=?", (kind, term, term_type))
        return dict(r) if r else None

    def record_search(self, kind, term, term_type, query, signal_ids, ok, error=None):
        ts = now_iso()
        with self.tx(write=True) as c:
            prev = c.one(
                "SELECT last_ok_at FROM search_terms WHERE kind=? AND term=? AND term_type=?", (kind, term, term_type)
            )
            c.run(
                upsert_sql("search_terms"),
                (
                    kind,
                    term,
                    term_type,
                    query,
                    ts,
                    ts if ok else (prev[0] if prev else None),
                    len(signal_ids),
                    None if ok else str(error)[:300],
                ),
            )
            c.many(upsert_sql("search_hits", ignore=True), [(kind, term, term_type, sid, ts) for sid in signal_ids])

    def search_items(self, kind, term, term_type=None, published_since=None):
        q, args = "SELECT signal_id FROM search_hits WHERE kind=? AND term=?", [kind, term]
        if term_type:
            q += " AND term_type=?"
            args.append(term_type)
        rows = self.signals_by_ids([r[0] for r in self._q(q, args)])
        if published_since:
            rows = [r for r in rows if not r["published_at"] or r["published_at"] >= published_since]
        return sorted(rows, key=lambda r: r["published_at"] or "", reverse=True)

    def search_coverage(self):
        return [
            dict(r)
            for r in self._q(
                "SELECT kind, term_type, COUNT(*) AS terms, COUNT(last_ok_at) AS searched, MIN(last_ok_at) AS oldest_ok, "
                "COUNT(last_error) AS failing FROM search_terms GROUP BY kind, term_type"
            )
        ]

    # ------------------------------------------------------------ the tracked packages (scope)
    def add_scope_packages(self, packages, origin):
        """Add {package_manager, name, version} rows not tracked yet (origin: "seed" or "lookup"). -> how many."""
        rows = {}
        for p in packages:
            key = (p["package_manager"], p["name"].lower(), p.get("version") or "")
            rows.setdefault(key, p["name"])
        if not rows:
            return 0
        ts = now_iso()
        with self.tx(write=True) as c:
            have = {
                (r["package_manager"], r["name"], r["version"])
                for r in c.q("SELECT package_manager, name, version FROM scope_packages")
            }
            new = [(pm, n, v, rows[(pm, n, v)], origin, ts) for pm, n, v in rows if (pm, n, v) not in have]
            if new:
                c.many(upsert_sql("scope_packages", ignore=True), new)
        return len(new)

    def scope_packages(self, origin=None):
        """Tracked package versions, oldest first: {package_manager, name, version, display_name, origin, added_at}."""
        q, args = "SELECT * FROM scope_packages", ()
        if origin:
            q, args = q + " WHERE origin=?", (origin,)
        return [dict(r) for r in self._q(q + " ORDER BY added_at, name, version", args)]

    def trim_scope_packages(self, origin, keep):
        """Keep only the newest `keep` rows of one origin. -> how many were removed."""
        rows = self.scope_packages(origin)
        drop = rows[: max(0, len(rows) - keep)]
        with self.tx(write=True) as c:
            for r in drop:
                c.run(
                    "DELETE FROM scope_packages WHERE package_manager=? AND name=? AND version=?",
                    (r["package_manager"], r["name"], r["version"]),
                )
        return len(drop)

    # ------------------------------------------------------------ package evidence
    def put_evidence(self, ecosystem, name, vkey, resolved_version, evidence):
        with self.tx(write=True) as c:
            c.run(
                upsert_sql("package_evidence"),
                (ecosystem, name.lower(), vkey, resolved_version, dumps(evidence), now_iso()),
            )

    def get_evidence(self, ecosystem, name, vkey):
        r = self._one(
            "SELECT * FROM package_evidence WHERE ecosystem=? AND name=? AND version_key=?",
            (ecosystem, name.lower(), vkey),
        )
        return (
            {
                "resolved_version": r["resolved_version"],
                "evidence": json.loads(r["evidence"]),
                "collected_at": r["collected_at"],
            }
            if r
            else None
        )

    def drop_evidence(self, ecosystem, name):
        """Forget stored evidence for a package (a feed just reported something new): the next lookup fetches fresh."""
        with self.tx(write=True) as c:
            return c.run("DELETE FROM package_evidence WHERE ecosystem=? AND name=?", (ecosystem, name.lower()))

    def age_evidence(self, collected_at):
        """Set every stored evidence row's collection time (tests: make it look stale)."""
        with self.tx(write=True) as c:
            c.run("UPDATE package_evidence SET collected_at=?", (collected_at,))

    def evidence_packages(self):
        """(ecosystem, name) of every package with stored evidence: the scope plus everything looked up."""
        return {(r[0], r[1]) for r in self._q("SELECT DISTINCT ecosystem, name FROM package_evidence")}

    def evidence_stats(self):
        with self.tx() as c:
            return {
                "stored": c.one("SELECT COUNT(*) FROM package_evidence")[0],
                "oldest": c.one("SELECT MIN(collected_at) FROM package_evidence")[0],
            }

    # ------------------------------------------------------------ relevance + what's new
    def delete_signals(self, ids):
        """Remove records (and their item rows and search links), e.g. ones no longer about the scope."""
        ids = list(ids)
        with self.tx(write=True) as c:
            for i in range(0, len(ids), 500):
                chunk = ids[i : i + 500]
                ph = ",".join("?" * len(chunk))
                for t, col in (("items", "signal_id"), ("search_hits", "signal_id"), ("signals", "id")):
                    c.run(f"DELETE FROM {t} WHERE {col} IN ({ph})", chunk)
        return len(ids)

    def items_since(self, since, kinds=None, package=None, package_manager=None, limit=1000):
        """Item rows whose record was first stored after `since` (ISO time): what's new."""
        q = (
            "SELECT i.*, s.first_seen_at AS first_seen_at FROM items i JOIN signals s ON s.id = i.signal_id "
            "WHERE s.first_seen_at > ?"
        )
        args = [since]
        if kinds:
            q += f" AND i.kind IN ({','.join('?' * len(kinds))})"
            args += list(kinds)
        if package:
            q += " AND i.package = ?"
            args.append(package.lower())
        if package_manager:
            q += " AND i.package_manager = ?"
            args.append(package_manager)
        q += " ORDER BY s.first_seen_at DESC LIMIT ?"
        args.append(int(limit))
        return [{k: (v if v != "" else None) for k, v in r.items()} for r in self._q(q, args)]

    def stats(self):
        with self.tx() as c:
            return {
                "signals": c.one("SELECT COUNT(*) FROM signals")[0],
                "by_kind": {r[0]: r[1] for r in c.q("SELECT kind, COUNT(*) FROM signals GROUP BY kind")},
                "items": c.one("SELECT COUNT(*) FROM items")[0],
                "package_evidence": c.one("SELECT COUNT(*) FROM package_evidence")[0],
                "db": self.where,
                "backend": "postgres" if self.pg else "sqlite",
            }

    # ------------------------------------------------------------ scans (laptop scanner -> pipeline -> agents)
    SCAN_JSON = ("scope", "result")

    def _scan(self, r):
        return {k: (json.loads(v) if k in self.SCAN_JSON and v else v) for k, v in r.items()} if r else None

    # ------------------------------------------------------------ self-registered scan keys
    def add_scan_key(self, key_hash, device, device_name, client):
        with self.tx(write=True) as c:
            c.run(upsert_sql("scan_keys"), (key_hash, device, device_name, client, now_iso(), None))

    def scan_key_active(self, key_hash):
        return bool(self._one("SELECT 1 FROM scan_keys WHERE key_hash=? AND revoked_at IS NULL", (key_hash,)))

    def scan_keys_since(self, since, client=None):
        """How many keys were registered since `since` (ISO time), from one client or in all."""
        q, args = "SELECT COUNT(*) FROM scan_keys WHERE created_at >= ?", [since]
        if client is not None:
            q, args = q + " AND client = ?", [*args, client]
        return self._one(q, tuple(args))[0]

    def scan_keys(self):
        """Registered keys, newest first, without the hashes: {device, device_name, created_at, revoked_at}."""
        rows = self._q("SELECT device, device_name, created_at, revoked_at FROM scan_keys ORDER BY created_at DESC")
        return [dict(r) for r in rows]

    def revoke_scan_key(self, device):
        """Revoke the key a device registered (by the device id its scans show). -> how many keys."""
        with self.tx(write=True) as c:
            return c.run("UPDATE scan_keys SET revoked_at=? WHERE device=? AND revoked_at IS NULL", (now_iso(), device))

    def add_scan(self, scan):
        row = {c: scan.get(c) for c in COLUMNS["scans"]}
        for k in self.SCAN_JSON:
            row[k] = dumps(row[k]) if row[k] is not None else None
        with self.tx(write=True) as c:
            c.run(upsert_sql("scans"), tuple(row[c_] for c_ in COLUMNS["scans"]))

    def get_scan(self, sid):
        return self._scan(self._one("SELECT * FROM scans WHERE id=?", (sid,)))

    def update_scan(self, sid, **fields):
        fields["updated_at"] = now_iso()
        for k in self.SCAN_JSON:
            if k in fields and fields[k] is not None:
                fields[k] = dumps(fields[k])
        cols = [k for k in fields if k in COLUMNS["scans"] and k != "id"]
        with self.tx(write=True) as c:
            c.run(f"UPDATE scans SET {', '.join(f'{k}=?' for k in cols)} WHERE id=?", (*[fields[k] for k in cols], sid))

    def claim_scan(self, status, to_status, stale_status=None, stale_before=None):
        """Atomically take the oldest scan in `status` (or one stuck in `stale_status` since before `stale_before`)
        and move it to `to_status`. -> the scan, or None."""
        q, args = "SELECT id FROM scans WHERE status=?", [status]
        if stale_status and stale_before:
            q = "SELECT id FROM scans WHERE status=? OR (status=? AND claimed_at < ?)"
            args += [stale_status, stale_before]
        with self.tx(write=True) as c:
            r = c.one(q + " ORDER BY created_at LIMIT 1", args)
            if not r:
                return None
            ts = now_iso()
            c.run("UPDATE scans SET status=?, claimed_at=?, updated_at=? WHERE id=?", (to_status, ts, ts, r["id"]))
        return self.get_scan(r["id"])

    def previous_scan(self, device, folder, before, exclude=None):
        """The device's last scan of this folder that got an advisory, up to `before` (ISO time), other than `exclude`:
        "new" means new since the last advice the person actually received."""
        return self._scan(
            self._one(
                "SELECT * FROM scans WHERE device=? AND folder=? AND status='done' AND advice IS NOT NULL "
                "AND created_at <= ? "
                "AND id != ? ORDER BY created_at DESC, updated_at DESC LIMIT 1",
                (device, folder, before, exclude or ""),
            )
        )

    def advices(self, device, folder, limit=30):
        """The newest advisories the device got for this folder (text only), newest first."""
        rows = self._q(
            "SELECT advice FROM scans WHERE device=? AND folder=? AND advice IS NOT NULL "
            "ORDER BY created_at DESC LIMIT ?",
            (device, folder, int(limit)),
        )
        return [r["advice"] for r in rows]

    def list_scans(self, device=None, limit=20):
        q, args = "SELECT id, device_name, folder, status, advice_status, created_at, updated_at, error FROM scans", []
        if device:
            q += " WHERE device=?"
            args.append(device)
        return [dict(r) for r in self._q(q + " ORDER BY created_at DESC LIMIT ?", (*args, int(limit)))]

    def scans_waiting(self, status, before):
        """Ids of scans in `status` since before `before` (e.g. waiting too long for the agents)."""
        return [r["id"] for r in self._q("SELECT id FROM scans WHERE status=? AND updated_at < ?", (status, before))]

    # ------------------------------------------------------------ moving data between databases
    def copy_from(self, other, log=print):
        """Copy every row of another store into this one (rows already here are kept). E.g. SQLite -> Postgres."""
        total = {}
        for t in TABLES:
            cols = COLUMNS[t]
            rows = other._q(f"SELECT {', '.join(cols)} FROM {t}")
            for i in range(0, len(rows), 1000):
                with self.tx(write=True) as c:
                    c.many(upsert_sql(t, ignore=True), [tuple(r[k] for k in cols) for r in rows[i : i + 1000]])
            total[t] = len(rows)
            log(f"{t}: {len(rows)} row(s)")
        return total
