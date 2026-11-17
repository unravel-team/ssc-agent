# SSC Agent: supply-chain security advisor

Finds supply-chain risks in your projects and tells you what to do about them: malicious, typosquatted or vulnerable
dependencies, missing lockfiles, secrets in files, distrusted CA certificates, and breaches at vendors you rely on.

It has three parts:

| Part | Folder | What it does |
|---|---|---|
| **The app** (`ssc`) | [scanner/](scanner/) | A small Rust binary for developer laptops. It reads the folders you choose, sends only package names, versions and vendor names to the server, and shows the action items in a local browser app. |
| **The API and agents** | [intel_api/](intel_api/) | A FastAPI server with Postgres. It collects advisories and news from public sources, checks every package against them and its rules, and runs AI agents that write the advisory for each scan. |
| **The Claude Code plugin** | [claude-plugins/](claude-plugins/) | `/ssc-advisor:advise` in Claude Code: scans a folder, shows the action items, and applies the fixes you approve. |

The live server is **https://unravel-ssc-api.fly.dev** (Fly.io, see [intel_api/FLY.md](intel_api/FLY.md)).

---

## Using the app

### 1. Build the app
You need Rust (`brew install rustup && rustup-init`; the version is pinned in `scanner/rust-toolchain.toml`).

```bash
cd scanner
SSC_BUILD_API_URL=https://unravel-ssc-api.fly.dev cargo build --release --locked
cp target/release/ssc ~/.local/bin/ssc        # or anywhere on your PATH
```
`SSC_BUILD_API_URL` builds the server address into the app as its default.

<details><summary>One binary for both Intel and Apple Silicon Macs</summary>

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
for t in aarch64-apple-darwin x86_64-apple-darwin; do
  SSC_BUILD_API_URL=https://unravel-ssc-api.fly.dev cargo build --release --locked --target $t
done
lipo -create -output ssc target/aarch64-apple-darwin/release/ssc target/x86_64-apple-darwin/release/ssc
codesign --force --sign - ssc
```
</details>

### 2. Set it up
```bash
ssc init --api https://unravel-ssc-api.fly.dev --folder ~/code/my-project
```
Or just run `ssc ui` and add folders there.

### 3. Scan
```bash
ssc ui            # opens the app in your browser: add folders, press Scan, tick items as you fix them
ssc scan          # or from the terminal: scans every folder, waits for the advisory and saves it
ssc install --interval 15   # scan in the background (default every 60 minutes; ssc uninstall to stop)
ssc status        # settings, server, background scans, the last result per folder
```

The app shows, per folder:
- a **summary** of what needs doing, most urgent first;
- one table of **action items**, each with a criticality, the project, what to do, and a link to the source;
- a tick box per item. Tick what you've done. The next scan ticks items it no longer finds, and unticks a fix
  it still finds.

The app reads files only. It never installs or runs anything from your projects, and never sends code, secret values
or local paths. Everything it sends is listed by `ssc scope PATH` (nothing is sent). All commands:
[scanner/README.md](scanner/README.md).

---

## Using the Claude Code plugin

The plugin works on its own: it doesn't need the `ssc` app.

```bash
claude plugin marketplace add /path/to/ssc_agent/claude-plugins
claude plugin install ssc-advisor@ssc-local
```

Then, in Claude Code:
```
/ssc-advisor:advise ~/code/my-project
```
It scans the folder, shows the open action items, and asks which automatic fixes to apply (version changes in
manifests). It changes nothing until you answer, backs files up first and prints a restore command. It never installs
packages: reinstall when you choose to, then scan again to confirm. You can also tell it what you fixed by hand ("I
rotated the database key") and it ticks those items. With the app installed too, both show the same list and ticks.
Details: [claude-plugins/README.md](claude-plugins/README.md).

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
