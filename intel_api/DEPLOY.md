# Deploying the sources API on a company server

> Deploying on **Fly.io** instead of your own server: see [FLY.md](FLY.md).

```
laptop scanner ──HTTPS──▶ nginx (443) ──▶ api (FastAPI, 8787) ──────────▶ Postgres
agents, hooks, CI          TLS, allow list,  keys + roles, lookups,         internal network only
                           rate limits       the scan pipeline, background
                                             jobs ──▶ public sources
                                                ▲
                                                │ takes jobs, returns advisories (agent key)
                                             agents (headless Claude Code) ──▶ Anthropic API
```
Four containers from `compose.yaml`. The API is served by FastAPI (uvicorn); interactive docs at `/v1/docs`. Only nginx publishes ports. Postgres sits on an internal network with no route
out and no published port. The API runs as an unprivileged user on a read-only filesystem.

## Supply chain of the image
| Part | Pinned how |
|---|---|
| `python:3.13.18-slim`, `nginx:1.30.6-trixie`, `postgres:18.6-trixie` (all Debian 13 with glibc; nothing runs on Alpine/musl, and no image contains an SSH server) | by digest (a moved tag can't change what runs) |
| The server stack: FastAPI 0.162.0, uvicorn 0.54.0, Starlette 1.10.0, Pydantic 2.14.1, the Postgres driver psycopg 3.3.6, and their dependencies (16 packages) | declared in `pyproject.toml` (Poetry group `server`), locked with file hashes in `poetry.lock`; all 16 checked with the gatekeeper (ALLOW). Five are pinned below releases that were under a week old when locked |
| Poetry 2.5.1 and its 46 dependencies (build stage only, not in the final image) | exact versions + hashes in `poetry-tools.txt`, releases at least a week old, prebuilt wheels only; vetted with the gatekeeper (46 ALLOW, 1 HOLD: `requests` 2.34.2, social posts only) |
| `wamerican` (system word list, used to tell ordinary words from package names) | Debian package from the base image's signed repository |

To update one: check the new version with the gatekeeper, then change the digest, or the version in `pyproject.toml` and run `poetry lock` (in a throwaway container if Poetry isn't installed: see "Dependencies" below).

## How a scan works
1. A laptop scanner sends what it found in a folder to `POST /v1/scans` (package versions with file, line and the line's
   text, vendors, base images, CAs; never code or secrets) with its own `scan` key.
2. The API's scan worker looks everything up (database first, sources on a miss), applies the rules (ALLOW / HOLD /
   BLOCK), checks fix versions, plans the line edits, and compares with that device's last scan of the folder.
3. If something is new (or it is the first scan), the scan waits for the **agents** container. It takes the job
   (`POST /v1/agents/claim`), runs headless Claude Code with the advisor playbook (`agents/advisor.md`) on the job's
   files, and sends the advisory back. Nothing new: the last advisory is reused, at no cost.
4. The scanner polls `GET /v1/scans/{id}` and shows the advisory, the action plan and the diff.

The agents container can only read its job's files and write `ADVICE.md` (no shell, no web, nothing else on disk), has
no database access and none of `.env` except its own key and the Claude credentials, and is capped at
`SSC_AGENT_BUDGET_USD` per advisory. Claude Code is pinned (2.1.316) and checked against its published SHA-256 at build.
If the agents are down or have no credentials, scans still finish with their action plan (`advice_status`: failed or
unavailable).

## First deployment
On the server (Docker with the compose plugin; the server needs outbound HTTPS to the sources):
```bash
git clone <this repo> && cd <repo>/intel_api
cp .env.example .env && chmod 600 .env
#   POSTGRES_PASSWORD:   openssl rand -hex 24
#   SSC_INTEL_API_KEYS:  read:<openssl rand -hex 32>,write:<...>,admin:<...>,scan:<one per laptop>
#   SSC_AGENT_KEY:       openssl rand -hex 32 (the agents container's key)
#   Claude for the agents: ANTHROPIC_API_KEY (Console), or CLAUDE_CODE_OAUTH_TOKEN from `claude setup-token`
#   optional source tokens (GITHUB_TOKEN, NVD_API_KEY, ...)
# TLS: put the server's certificate (with chain) and key at nginx/certs/server.crt and server.key, issued by a CA the
#      laptops already trust (the company's internal CA, or a public one), so no client needs a certificate setting
# Network: edit the allow list in nginx/nginx.conf to your company ranges
docker compose up -d --build
docker compose ps                      # all three healthy
curl https://intel.yourcompany.internal/v1/health
```
The background jobs start right away and fill the database within a few hours (feeds in minutes, searches over hours).
To start with the data you already have on a laptop instead:
```bash
docker compose run --rm -v /path/to/folder-with-the-file:/import api python -m intel_api copy-db /import/intel_api.sqlite
```
(rows already in Postgres are kept; the folder must be writable, SQLite needs it for its journal).

## Pointing clients at it
| Client | Settings |
|---|---|
| Laptop scanner | `POST /v1/scans` with a **scan** key (one per laptop: each sees only its own scans) |
| Agents, hooks, gatekeeper, advisor scripts | `SSC_INTEL_API=https://intel.yourcompany.internal`, `SSC_INTEL_API_KEY=<read key>` |
| threat-intel agent (pushes breach notices) | the same with the **write** key |
| Python tools only, when the company CA isn't in the store Python reads (Python on macOS ignores the keychain) | `SSC_INTEL_API_CA=/path/to/ca.pem` |
| Tools on the server machine itself | `http://127.0.0.1:8787`: the API on the loopback only, no certificate involved |

Keys go in the `Authorization: Bearer <key>` header (or `X-API-Key`). Without a key only `/v1/health` answers.

## Running it
| Task | Command (in `intel_api/`) |
|---|---|
| Status of sources and jobs | `docker compose exec api python -m intel_api status` |
| Agents' log (each advisory: time, cost) | `docker compose logs -f agents` |
| Run all jobs now | `docker compose exec api python -m intel_api refresh all` |
| Logs | `docker compose logs -f api` (nginx logs paths and status codes only: no query strings, no keys) |
| Change what is tracked | edit `config/scope.json`: new packages are added to the `scope_packages` table on the next job run (no restart); vendors, stack and CAs are read from the file. Packages that lookups find are added to the table automatically |
| Change source settings | edit `config/sources.json`, then `docker compose restart api` |
| Rotate keys | edit `SSC_INTEL_API_KEYS` in `.env`, then `docker compose up -d api` (list old and new keys together during the switch) |
| Upgrade | `git pull && docker compose up -d --build` |
| Backup | `docker compose exec postgres pg_dump -U intel intel \| gzip > intel-$(date +%F).sql.gz` |
| Restore | `gunzip -c intel-<date>.sql.gz \| docker compose exec -T postgres psql -U intel intel` |

## Limits and notes
- **One API process.** It owns the background jobs and serialises its writes, so don't scale `api` to several replicas
  as it is. For more load, split the jobs into their own worker container first.
- **Losing the database is not a disaster.** Everything in it is collected from public sources and comes back within
  hours. Backups just save that wait and the lookup history.
- **Port 80 redirects to HTTPS** on the same host name (nginx on 443).
- **Docker Desktop** may show every client as its gateway address, so the allow list sees one address. On a Linux
  server nginx sees the real client addresses.
- **Tests against Postgres:** `docker compose run --rm --no-deps -v "$(cd .. && pwd):/repo:ro" -w /repo -e PYTHONPATH=/repo -e SSC_TEST_PG_URL=postgresql://intel:<password>@postgres:5432/intel -e SSC_INTEL_DB_URL= api python -m unittest tests.test_intel_api`
  (each test gets its own empty schema).

## Dependencies (Poetry)
| File | What |
|---|---|
| `pyproject.toml` | The API needs nothing beyond the standard library; the optional `server` group adds the Postgres driver. |
| `poetry.lock` | Exact versions and file hashes of everything in the groups. The image installs from it with `poetry install --only server`. |
| `poetry-tools.txt` | Poetry itself, hash-pinned, for the image's build stage. |

Laptops and tests need no install at all (`python3 -m intel_api ...` runs on the standard library with SQLite).
To change a dependency without installing Poetry on your machine, run it in a throwaway container from this folder:
```bash
docker run --rm -v "$PWD:/src" -w /src python:3.13.18-slim sh -c \
  "python -m venv /p && /p/bin/pip install -q --require-hashes --only-binary=:all: --no-deps -r poetry-tools.txt && /p/bin/poetry lock"
```
Vet any new or changed package with the gatekeeper before committing the new `poetry.lock`.
