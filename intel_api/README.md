# Sources API (`intel_api`)

A database of supply-chain security information, built from **our scope** rather than everything on the internet, and an API to query it. It's a standalone service: the agents use it, but it doesn't depend on them and can serve any app.

```
config/scope.json ──seed──► scope_packages table ──► background jobs ──► database (only records about the scope)
                                      ▲                                    ▲   │
                                      └── new package version ─────────────┤   ▼
app reads its files ──► POST /v1/lookup ───────────────────────────────────┘
  (packages, vendors)     stored and fresh? return it
                          not there or stale? look it up from the sources now, store it, return it
                          never seen before? also add it to scope_packages, so the jobs keep it current
```

It uses only the Python standard library with SQLite (laptops, tests). On a server it uses Postgres (`SSC_INTEL_DB_URL`), which adds one pinned, hash-checked driver (`psycopg`). Dependencies are managed with Poetry (`pyproject.toml`, `poetry.lock`). Deployment with Docker, nginx and Postgres: [DEPLOY.md](DEPLOY.md).

## What it tracks: the `scope_packages` table, seeded from `config/scope.json`
```json
{
  "packages": [{"package_manager": "npm", "name": "axios", "versions": ["1.13.1"]},
               {"package_manager": "pip", "name": "litellm", "versions": ["1.107.0"]}],
  "vendors": [{"name": "Railway", "aliases": ["Railway.app"]}],
  "stack": ["python", "bun", "playwright"],
  "certificate_authorities": ["eMudhra Technologies Limited"]
}
```
- **Packages live in a table.** The jobs read the package versions to track from `scope_packages`. The file's packages are only a seed: when the file changes, its packages are added to the table (rows already there are kept, and removing a line doesn't untrack it).
- **It grows by itself.** A package version looked up through the API (a laptop scan, the gatekeeper, a single lookup) that the database had never seen is added with `origin = lookup`, so it is kept current from then on (at most 2,000 such rows; the oldest go first). Versions a scan only tries as possible fixes are not added.
- **Lockfiles count too.** The laptop scanner sends every package version a project's lockfiles pin (package-lock.json, bun.lock, uv.lock, requirements.lock), marked `section: "transitive"` when only a lockfile names it. Those are checked like direct dependencies and become action items ("upgrade the package that pulls it in, or override it"). They are tracked with `origin = lockfile` (at most 5,000): kept current by the evidence job, but not searched by name on news and social sites, where names like `debug` or `send` would match everything.
- **Vendors, stack and CAs** still come from the file, re-read on every job run.
- **The file** was filled on 2026-11-05 from acme-chat and fastapi-template: 85 packages, 8 vendors, 3 stack components, 1 CA. `versions: []` means the latest version.
- `GET /v1/scope` shows the current scope, including the packages added by lookups (`discovered`).

**What the jobs do with the scope:**
- Search news, social and NVD only for scope terms.
- Keep package evidence for scope packages.
- Store feed records only if they're about the scope. The feeds are read whole, and everything else is dropped on arrival.
- During daily maintenance, remove anything no longer about the scope, e.g. after you take something out of the file.

**Packages outside the scope** that an app looks up are stored too, and kept fresh on request. They aren't added to the file.

**What counts as "about the scope"** ([engine/relevance.py](engine/relevance.py)):

| Record | Kept when |
|---|---|
| Malware reports and advisories | the package is in the scope, or has been looked up |
| CISA KEV / NVD CVEs | the CVE is on a tracked package, the KEV vendor is one of our vendors, or the product is in our stack |
| News | it names a tracked package or vendor, by the same rules as the items table (ordinary words, publisher suffixes and extension IDs are guarded against), or a tracked CA together with "certificate" |
| Social posts | found by searching a tracked term, naming it and using a security word (the gatekeeper's own rule) |
| CA distrust | the CA is in the scope |
| Breach notices from the threat-intel agent | always |

## Lookups
`POST /v1/lookup` takes what an app found in the files it was pointed at:
```json
{"packages": [{"package_manager": "npm", "name": "axios", "version": "1.13.1"}], "vendors": ["Railway"]}
```
For each package the response includes:
- `error` instead of evidence, only when the package could not be looked up;
- `evidence`: registry facts, plus advisories and malware from OSV, OpenSSF, KEV, EPSS and VulnCheck;
- `items`: rows from every source for that version, plus rows that name no version.

Stored data older than `max_age_hours` (default 24) is looked up again. Vendors are searched on the spot if they never were.

The same "database first, sources on a miss" rule applies to `POST /v1/packages/check` (gatekeeper, install guardrail, pre-commit), `GET /v1/packages/{npm|pip}/{name}`, `GET /v1/search/{kind}` and `GET /v1/vendors/{name}/signals`.

Measured on this machine: a package not stored yet takes about 2 s (looked up and stored); the next call takes 0.07 s.

## Run it
```bash
docker compose up -d                         # in intel_api/: FastAPI + Postgres + nginx (DEPLOY.md); docs at /v1/docs
python3 -m intel_api serve                    # or directly: FastAPI on http://127.0.0.1:8787 (Python 3.11+, poetry install --with server)
python3 -m intel_api status                   # source and job health, search coverage, table sizes
python3 -m intel_api refresh all              # run every job once now
python3 -m intel_api push-notices FILE        # send the threat-intel agent's breach notices
python3 -m unittest discover -s tests         # from the repo root: the tests (standard library only)
ruff check intel_api tests && ruff format --check intel_api tests   # lint + format (settings in pyproject.toml)
```
Lookups, items, alerts and the scope are API endpoints (below).
**Clients** (agents, hooks, pre-commit, apps):
```bash
export SSC_INTEL_API=http://127.0.0.1:8787
export SSC_INTEL_API_KEY=<key>                # only if the server uses keys
```
**Keys.** Set `SSC_INTEL_API_KEYS="read:<k1>,write:<k2>,admin:<k3>"` on the server.
- **read:** lookups and queries.
- **write:** also imports breach notices.
- **admin:** also runs jobs on demand.

With no keys set, the server only listens on 127.0.0.1.

## Layout
```
intel_api/
  config/       sources.json (sources, ratings, feed speeds, collection settings) · scope.json (seed for what is tracked)
  data/         intel_api.sqlite (the local database; not in git). On a server: Postgres. No download cache.
  sources/      one file per source, found automatically            <- add new sources here (see below)
  lib/          connectors.py (HTTP, source functions) · packages.py (registry, typosquat, advisory lookups)
  core/         models.py (signal) · dates.py · scope.py · store.py
  engine/       jobs.py · scheduler.py · evidence.py (lookups) · relevance.py · index.py (records -> items) · queries.py
  api/          routes.py (handlers) · views.py (response shapes) · server.py · openapi.py
  client.py     used by the agents: API first, direct lookups when it can't be reached
  cli.py
  pyproject.toml, poetry.lock, poetry-tools.txt   dependencies (Poetry): none for laptops; the Postgres driver for the server
  Dockerfile, compose.yaml, .dockerignore, .env.example, nginx/   server deployment (see DEPLOY.md)
```
The agents import `lib/connectors.py` and `lib/packages.py`, so a direct lookup and an API lookup gather identical evidence. The dependency only runs one way: the API never imports agent code.

## Tables
| Table | Holds |
|---|---|
| `items` | the generic table: one row per item × package × version, with `signal_id, kind, package, version, package_manager, source, title, description, url, date, severity` |
| `signals` | the raw record per advisory, article or post, with its source rating (`reliability`, `may_block`) and details in `data` |
| `package_evidence` | registry facts and findings per package version (what the gatekeeper's rules read) |
| `search_terms`, `search_hits` | each scheduled or on-demand search, and what it found |
| `sources` | job health and feed cursors |

## Background jobs
| Job | Every | Does |
|---|---|---|
| feeds, at their speed: **urgent** (10 min) osv malware, oss_security · **regular** (1 h) news_rss, cisa_kev · **slow** (1 d) mozilla_ca_store | 10 min / 1 h / 1 d | read the feed; store only records about the scope; new malware for a stored package drops its evidence (the next lookup fetches fresh) |
| news_search, social_search | vendors 1 h, packages 6 h | per scope term, a limited number of terms per run; only results that name the term are kept |
| nvd_search | 6 h | CVEs for scope vendors and stack |
| package_evidence | 6 h | every scope package version |
| articles | 10 min | read security articles once, for versions in the body |
| index | 5 min | flatten records into items |
| maintenance | daily | fill missing dates, prune old news and social, remove records no longer about the scope |

Settings in `config/sources.json`: `"speeds"` (the three intervals) and each feed's `"speed"`; `"collection"` for the other jobs. Package searches stay at 6 h because the search sites rate-limit; other sources are asked on request, so they have no schedule.

## Endpoints
The OpenAPI 3 spec is served at `GET /v1/openapi.json` (no key needed) and rendered at `GET /v1/docs`.

| Method and path | Role | Use |
|---|---|---|
| `POST /v1/lookup` | read | packages and vendors an app found: database first, sources on a miss |
| `GET /v1/packages/{npm\|pip}/{name}?version=` | read | one package, same rule |
| `POST /v1/packages/check` | read | evidence for the gatekeeper's rules, same rule; anything that failed is in `missing` |
| `GET /v1/items`, `GET /v1/news` | read | query the items table |
| `GET /v1/alerts?since=` | read | what's new (rows first stored after `since`) |
| `GET /v1/scope` | read | what is tracked |
| `GET /v1/search/{news\|social\|nvd}?term=` | read | search results for a term (searched now if never searched) |
| `GET /v1/vendors/{name}/signals` | read | records about a vendor (searched now if never searched) |
| `GET /v1/signals`, `GET /v1/trust/ca-distrust`, `GET /v1/trust/mozilla-roots`, `GET /v1/sources` | read | raw records, trust store, health |
| `POST /v1/signals/breach-notices` | write | the threat-intel agent's notices: stored under the site they came from, capped at ★3 (HOLD at most) |
| `POST /v1/admin/refresh` `{job?}` | admin | run a job now |
| `GET /v1/health`, `GET /v1/openapi.json` | none | |

## Adding a source
1. Create `sources/<name>.py` with one class (files starting with `_` are not loaded):
   ```python
   from .base import FeedSource
   from .registry import register


   @register
   class MySource(FeedSource):
       key = "my_source"  # same key as its entry in config/sources.json
       requires_env = ()  # e.g. ("MY_SOURCE_API_KEY",)
       defaults = {"reliability": 3, "may_block": False, "speed": "regular"}  # used without a config entry

       def pull(self, state):
           data = self.fetch("https://example.org/feed.json") or []
           sigs = [
               self.signal(
                   "malicious",
                   f"Malicious package: {x['name']}",
                   key=f"{x['name']}@{x['version']}",
                   url=x.get("url", ""),
                   subject={"type": "package", "ecosystem": "npm", "name": x["name"]},
                   published_at=x.get("date"),
                   data={"versions": [x["version"]]},
               )
               for x in data
           ]
           return sigs, {"count": len(sigs)}
   ```
2. Pick what it can do (one or several base classes):
   - `FeedSource.pull(state)`: pulled on schedule; only records about the scope are stored.
   - `PackageSource.check(dep)`: asked during every package lookup; its findings join the evidence.
   - `SearchSource.search(term, query, days)`: news, social or NVD.
3. Add its entry, with a rating, to `config/sources.json`. Only sources rated ★5 with `may_block` can BLOCK.
4. Check it's picked up (`GET /v1/sources`, or `python3 -m intel_api status`), pull it once with `python3 -m intel_api refresh my_source`, and add an offline test.

## Limits
- One API process (it runs the background jobs too). For more load, move the jobs to their own worker before adding API replicas.
- A lookup that misses waits for the sources: about 2 s per package, done in parallel for a batch.
- Feeds are still downloaded whole (that's how RSS and KEV work); only the relevant records are kept.
- Google News links are redirects, so for those articles versions come from the headline only.
- Text matching is pattern-based and tuned against false matches, so some unusually phrased mentions are missed.
