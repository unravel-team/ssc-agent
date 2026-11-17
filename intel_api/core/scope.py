"""What the sources API tracks.

Packages: the `scope_packages` table. intel_api/config/scope.json (override with SSC_INTEL_SCOPE) is its seed: when
the file changes, its packages are added to the table (rows already there are kept; removing a line from the file
does not untrack it). After that the table grows by itself: a package version looked up through the API (a laptop
scan, the gatekeeper, a single lookup) that the database had never seen is added (track()). The background jobs
read the table.

Vendors, stack and certificate authorities still come from the file, which is re-read on every job run.

    {
      "packages": [{"package_manager": "npm", "name": "axios", "versions": ["1.13.1"]}],   # versions: [] = latest
      "vendors": [{"name": "Railway", "aliases": ["Railway.app"]}],
      "stack": ["python", "node"],                                                         # base images / runtimes
      "certificate_authorities": ["eMudhra"]
    }
"""

import hashlib
import json
import os

from .._paths import CONFIG_DIR

SCOPE_PATH = os.environ.get("SSC_INTEL_SCOPE") or os.path.join(CONFIG_DIR, "scope.json")
PM_TO_ECO = {"npm": "npm", "pip": "PyPI", "pypi": "PyPI"}
ECO_TO_PM = {"npm": "npm", "PyPI": "pip"}


def scope_path():
    return os.environ.get("SSC_INTEL_SCOPE") or SCOPE_PATH


class Scope:
    def __init__(self, raw=None, path=None):
        path = path or scope_path()
        if raw is None:
            raw = {}
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    raw = json.load(f)
        self.raw, self.path = raw, path
        self.packages = {}  # (ecosystem, name_lower) -> {"name", "versions": [...]}
        self.discovered = 0  # package versions added from lookups (see track())
        self.searchable = None  # names to search on news/social sites (None: every package)
        self.add(raw.get("packages", []))
        self.vendors = [
            {"name": v["name"], "terms": list(dict.fromkeys([v["name"], *(v.get("aliases") or [])]))}
            for v in raw.get("vendors", [])
            if v.get("name")
        ]
        self.stack = [s for s in raw.get("stack", []) if s]
        self.cas = [c for c in raw.get("certificate_authorities", []) if c]

    def add(self, packages):
        for p in packages:
            eco = PM_TO_ECO.get(str(p.get("package_manager") or p.get("ecosystem") or "").lower())
            if eco and p.get("name"):
                e = self.packages.setdefault((eco, p["name"].lower()), {"name": p["name"], "versions": []})
                e["versions"] = sorted(set(e["versions"]) | {str(v) for v in p.get("versions") or [] if v})

    def search_packages(self):
        """{(ecosystem, name_lower): package} whose names the news and social searches look for."""
        if self.searchable is None:
            return dict(self.packages)
        return {k: p for k, p in self.packages.items() if k in self.searchable}

    def deps(self):
        """Package versions to keep evidence for: each listed version, or the latest when none is listed."""
        out = []
        for (eco, _), p in sorted(self.packages.items()):
            for v in p["versions"] or [None]:
                out.append({"ecosystem": eco, "name": p["name"], "version": v})
        return out

    def vendor_terms(self):
        return [t for v in self.vendors for t in v["terms"]]

    def summary(self):
        return {
            "file": self.path,
            "packages": len(self.packages),
            "package_versions": len(self.deps()),
            "vendors": len(self.vendors),
            "stack": len(self.stack),
            "certificate_authorities": len(self.cas),
            "discovered_package_versions": self.discovered,
            "searched_packages": len(self.search_packages()),
        }


# ---------------------------------------------------------------- the table: seeded from the file, grown by lookups
SEED_KEY = "scope_seed"  # the seed file's hash, kept as this pseudo-source's state, so the file is applied once
MAX_DISCOVERED = {"lookup": 2000, "lockfile": 5000}  # package versions per origin; the oldest are dropped first


def _file_packages(sc):
    return [
        {"package_manager": ECO_TO_PM[eco], "name": p["name"], "version": v}
        for (eco, _), p in sc.packages.items()
        for v in (p["versions"] or [None])
    ]


def seed(store, sc=None):
    """Add the file's packages to the table if the file changed since it was last applied. -> rows added."""
    sc = sc or Scope()
    digest = hashlib.sha256(json.dumps(sc.raw.get("packages", []), sort_keys=True).encode()).hexdigest()
    if ((store.source_state(SEED_KEY) or {}).get("state") or {}).get("hash") == digest:
        return 0
    added = store.add_scope_packages(_file_packages(sc), "seed")
    store.record_run(SEED_KEY, True, items=len(sc.packages), new_items=added, state={"hash": digest, "file": sc.path})
    return added


def discovered(store):
    """Package versions added by lookups, oldest first: [{package_manager, name, version, added_at}]."""
    return [
        {
            "package_manager": r["package_manager"],
            "name": r["display_name"],
            "version": r["version"] or None,
            "added_at": r["added_at"],
        }
        for r in store.scope_packages("lookup")
    ]


def track(store, deps, origin="lookup"):
    """Add package versions (dicts with ecosystem, name, version; version None = the latest) that aren't tracked
    yet. origin "lockfile": found only in a lockfile (a dependency of a dependency): kept current like the others,
    but not searched by name on news and social sites (names like "debug" or "send" would match everything).
    -> how many were added."""
    rows = [
        {"package_manager": ECO_TO_PM[d["ecosystem"]], "name": d["name"], "version": d.get("version")}
        for d in deps
        if d.get("ecosystem") in ECO_TO_PM and d.get("name")
    ]
    seed(store)  # so a package the file already lists counts as seeded, not discovered
    added = store.add_scope_packages(rows, origin)
    if added:
        store.trim_scope_packages(origin, MAX_DISCOVERED[origin])
    return added


def load(store=None):
    """The scope the jobs work on. With the store, packages come from the table (seeded from the file first if it
    changed); without one (tools, tests), from the file alone."""
    sc = Scope()
    if store is None:
        return sc
    seed(store, sc)
    rows = store.scope_packages()
    sc.packages = {}
    sc.add(
        [
            {
                "package_manager": r["package_manager"],
                "name": r["display_name"],
                "versions": [r["version"]] if r["version"] else [],
            }
            for r in rows
        ]
    )
    sc.discovered = sum(r["origin"] in ("lookup", "lockfile") for r in rows)
    sc.searchable = {(PM_TO_ECO[r["package_manager"]], r["name"]) for r in rows if r["origin"] != "lockfile"}
    return sc
