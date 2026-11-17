# SSC Agent: supply-chain security advisor

Finds supply-chain risks in your projects and tells you what to do about them: malicious, typosquatted or vulnerable
dependencies, missing lockfiles, secrets in files, distrusted CA certificates, and breaches at vendors you rely on.

It has three parts:

| Part | Folder | What it does |
|---|---|---|
| **The API and agents** | [intel_api/](intel_api/) | A FastAPI server with Postgres. It collects advisories and news from public sources, checks every package against them and its rules, and runs AI agents that write the advisory for each scan. |

---

## Running the server

| Where | Guide |
|---|---|
| Fly.io (the live deployment: API and agents on one machine, Fly Managed Postgres) | [intel_api/FLY.md](intel_api/FLY.md) |
| Your own server with Docker Compose (API, agents, Postgres, nginx) | [intel_api/DEPLOY.md](intel_api/DEPLOY.md) |
| Locally for development | [intel_api/README.md](intel_api/README.md) |

Every setting and secret is in [intel_api/.env.example](intel_api/.env.example). Copy it to `intel_api/.env` (gitignored)
and fill it in. The agents need a Claude API key or a `claude setup-token` token.

What is tracked starts from [intel_api/config/scope.json](intel_api/config/scope.json) and grows as scans look up
new packages. Detection rules for the app are in [intel_api/config/scanner_rules.json](intel_api/config/scanner_rules.json)
(the app downloads them on each scan).

---

## Rules worth knowing
- A package version must be at least **48 hours old** before it's allowed (most malicious releases are caught sooner).
- Exact pins and a committed lockfile are expected. The advisory asks for both.
- Internal package names that also exist on the public registry are flagged (dependency confusion).
- News is matched to packages and vendors you use. Old events, other versions and unrelated products are left out.

## Development
```bash
python3 -m unittest discover -s tests                      # API and plugin tests (standard library only)
cd scanner && cargo test --release --locked                # app tests
ruff check intel_api tests claude-plugins && ruff format --check intel_api tests claude-plugins
python3 tests/e2e_generated.py --projects 3                # the whole pipeline, agents included (live server; costs agent time)
```

What each finding turns into, for every combination of facts, is in [intel_api/ACTION_RULES.md](intel_api/ACTION_RULES.md)
(generated from `tests/test_state_matrix.py`, which checks the code against it). Every finished scan is also checked
for contradictions ([engine/checks.py](intel_api/engine/checks.py)): problems are logged and returned with the scan
as `checks`, and `python3 -m intel_api checks` shows how often each rule failed over recent scans.

## Never commit
`.env` files, `intel_api/nginx/certs/*` (TLS keys) and `intel_api/data/` (local database). `.gitignore`
covers them.
