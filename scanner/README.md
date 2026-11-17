# ssc: the laptop scanner (Rust; macOS, Linux, Windows)

One small binary for developer computers. It scans the folders you point it at, builds a scope (dependencies with
file and line, vendors, Docker base images, CA certificates), sends it to the company's sources API, and shows the
advisory and action plan the server's agents write. Everything else (lookups, the rules, verified fixes, the agents)
runs on the server: see [../intel_api/DEPLOY.md](../intel_api/DEPLOY.md).

It reads files only. Nothing from the projects is installed or run, and it never sends code, secrets or local paths:
only package names and versions, the dependency lines, vendor names, env-var **names**, base images and CA names, with
file paths relative to the scanned folder. Folders are named to the server as `~/...` (no user name).

## Run it
```bash
cd scanner
cp .env.example .env          # set SSC_API_URL and SSC_API_KEY; it stays private (gitignored)
cargo build --release --locked
target/release/ssc ui         # opens the app in your browser: add a folder, press Scan
```
The app reads its server settings from `scanner/.env` (or `~/.ssc/.env`, or `--env FILE`), so there is nothing to
enter in the app (the UI doesn't show them). Background scans read the same file; how often they run is chosen in the app.

| `.env` setting | What |
|---|---|
| `SSC_API_URL` | The company's sources API |
| `SSC_API_KEY` | Optional: a scan key you were given. Without one the app gets its own from the server |
| `SSC_FOLDERS` | Optional: folders to scan, comma separated (`~` = home). Folders can also be added in the app |

Without a `.env` file, `ssc init` or the app's Settings save the same things in `~/.ssc`.

## Commands (the same things without the browser)
| Command | What |
|---|---|
| `ssc ui [--port N] [--no-browser]` | The app in the browser (default port 8790) |
| `ssc init --api URL [--folder PATH ...] [--interval MIN]` | Settings; gets a scan key from the server if none is saved (`--key-stdin`: use one you were given) |
| `ssc folders [add\|remove PATH]` | The folders to scan |
| `ssc scan [--folder PATH]` | Scan, send, wait for the advisory, save it |
| `ssc open [PATH]` | Open the latest advisory |
| `ssc status` | Settings, server, background scans, last result per folder |
| `ssc install [--interval MIN]` / `ssc uninstall` | Background scans |
| `ssc scope PATH [--out FILE]` | Print the scope a scan would send (nothing is sent) |

Settings and results live in `~/.ssc` (`%USERPROFILE%\\.ssc` on Windows): `ssc.json`, `key` (readable only by you),
and `results/<folder>/<scan id>/` with `ADVICE.md`, `changes.diff`, `plan.json`, `result.json`. Applying the edits is up to you.

## The browser app is local only
`ssc ui` serves the page from this computer, on 127.0.0.1 only. The link it prints carries a random session token;
without it the page refuses to load. Every request must name 127.0.0.1 as its host (so another website can't reach it
by pointing a domain at your computer), and every API call must carry the token in a header that other websites can't
send. The page loads nothing from the internet, and the advisory is rendered with everything escaped (links only to http(s)).

## Small on purpose
- **Two crates** (19 in the tree, all checked against OSV and crates.io: no advisories, none yanked, all weeks old and
  widely used): `serde_json` and `regex`, pinned; `cargo build --locked` uses only `Cargo.lock`. No GUI toolkit, no web
  framework, no TLS library: the UI server is the standard library.
- **HTTPS through the system's `curl`** (built into macOS and Windows 10+; on Linux install the `curl` package). The key
  goes to curl on stdin, never on the command line. Certificates in projects are read by built-in code.
- **Detection rules are shared:** `intel_api/config/scanner_rules.json` is built in and refreshed from
  `GET /v1/scanner-rules` on each scan.

Tested on macOS (Apple Silicon) and Linux (aarch64, in a container); compiles for Windows (x86_64) and Linux (x86_64).
Not signed: build it on the computer that runs it, or sign it before handing it out.
