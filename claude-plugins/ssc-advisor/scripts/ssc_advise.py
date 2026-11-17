#!/usr/bin/env python3
"""A folder's supply-chain action items: scan it, list them, apply the approved ones, tick them off.

    ssc_advise.py setup   [--api URL]                 optional: use a key you were given (asked for; never echoed)
    ssc_advise.py status                              the server, whether it is reachable, whether a key is saved
    ssc_advise.py scan    FOLDER                      scan the folder, send it to the advisory API, save the result
    ssc_advise.py list    FOLDER                      the action items, numbered, with what can be applied automatically
    ssc_advise.py context FOLDER                      facts from the project's files about whether each item matters
    ssc_advise.py confirm FOLDER --project P --hops A B ...   check a claimed call path against the parsed code
    ssc_advise.py apply   FOLDER --ids 1,3            apply those items' edits (files are backed up first), tick them
    ssc_advise.py done    FOLDER --ids 2,5            mark items the user says they have done
    ssc_advise.py skip    FOLDER --ids 3 [--why TEXT] mark items the user says aren't relevant, or won't do
    ssc_advise.py pending FOLDER --ids 3              reopen items (neither done nor skipped)
    ssc_advise.py restore BACKUP_DIR FOLDER           put backed-up files back

No other program is needed: the scan is built here (ssc_scope.py: files are read, nothing is installed or run) and
sent to the API directly. Results and ticks live in ~/.ssc/results/<folder>/, the same place the ssc app uses, so the
app (if it is installed too) shows the same list and ticks. A rescan ticks what it no longer finds.

Settings, first found wins: the SSC_API_URL / SSC_API_KEY environment variables, then ~/.ssc/.env, then what `setup`
(or the app) saved in ~/.ssc/ssc.json and ~/.ssc/key. The server defaults to the company's deployment. With no key
saved, the first scan gets one from the server (POST /v1/register) and saves it: there is nothing to set up.

Edits name a file, a line and the exact text on it, so nothing is applied blindly: a line that changed since the scan
is left alone and reported. Only manifest lines change. Standard library only.
"""

import argparse
import getpass
import json
import os
import shutil
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ssc_scope

DEFAULT_API = "https://unravel-ssc-api.fly.dev"
HOME = Path(os.environ.get("SSC_HOME") or Path.home() / ".ssc")
WAIT_MINUTES = 25


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(1)


def out(obj):
    print(json.dumps(obj, indent=1, ensure_ascii=False))


def say(msg):
    print(msg, file=sys.stderr, flush=True)


def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def save_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_private(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(path, 0o600)  # a file that was already there keeps its old mode on open
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


# ---------------------------------------------------------------- settings
def env_file_settings():
    """SSC_* settings from $SSC_ENV or ~/.ssc/.env (KEY=VALUE lines; nothing in the file is executed)."""
    f = Path(os.environ["SSC_ENV"]) if os.environ.get("SSC_ENV") else HOME / ".env"
    vals = {}
    try:
        text = f.read_text(encoding="utf-8")
    except OSError:
        return vals
    for line in text.splitlines():
        line = line.strip().removeprefix("export ")
        k, sep, v = line.partition("=")
        k, v = k.strip(), v.strip().strip("\"'")
        if sep and k.startswith("SSC_") and v:
            vals[k] = v
    return vals


def settings():
    """-> (api URL, key or None, where the key came from)."""
    file_vals = env_file_settings()
    saved = load_json(HOME / "ssc.json", {})
    api = os.environ.get("SSC_API_URL") or file_vals.get("SSC_API_URL") or saved.get("api") or DEFAULT_API
    key, where = os.environ.get("SSC_API_KEY"), "the SSC_API_KEY environment variable"
    if not key and file_vals.get("SSC_API_KEY"):
        key, where = file_vals["SSC_API_KEY"], str(HOME / ".env")
    if not key:
        try:
            key, where = (HOME / "key").read_text(encoding="utf-8").strip() or None, str(HOME / "key")
        except OSError:
            key, where = None, None
    return api.rstrip("/"), key, where


def api_url_allowed(url):
    """HTTPS, or plain HTTP only to this computer (the local test stack): the key is never sent in the clear."""
    if url.startswith("https://"):
        return True
    if not url.startswith("http://"):
        return False
    authority = url[len("http://") :].split("/")[0].split("?")[0].split("#")[0]
    host = authority[1:].split("]")[0] if authority.startswith("[") else authority.split(":")[0]
    return "@" not in authority and host in ("127.0.0.1", "localhost", "::1")


class Api:
    def __init__(self, base, key):
        if not api_url_allowed(base):
            fail(f"the API must be https:// (plain http only for 127.0.0.1): {base}")
        self.base, self.key = base, key

    def call(self, method, path, body=None, timeout=90):
        """One request; `path` must be on this server (the poll link comes from the server, so it is checked)."""
        if not path.startswith("/") or path.startswith("//") or any(c.isspace() or ord(c) < 32 for c in path):
            raise RuntimeError(f"refusing an API path that isn't on {self.base}: {path!r}")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if self.key:
            req.add_header("Authorization", f"Bearer {self.key}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                status, text = r.status, r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"can't reach the advisory API at {self.base}: {getattr(e, 'reason', e)}") from e
        try:
            return status, json.loads(text)
        except ValueError:
            return status, {"error": text[:300]}


def register(base):
    """Get a scan key for this computer from the server (POST /v1/register) and save it, so there is no setup step.
    The key can only send scans and read this computer's own results."""
    try:
        status, r = Api(base, None).call("POST", "/v1/register", {"device_name": socket.gethostname()})
    except RuntimeError as e:
        fail(str(e))
    key = r.get("key") if status == 200 else None
    if not (isinstance(key, str) and len(key) >= 16 and key.isascii() and key.isalnum()):
        fail(
            f"no scan key saved, and the server didn't hand one out ({status}: {r.get('error', '')}). Ask the server "
            f"admin for a key, then run in a terminal: python3 {Path(__file__).resolve()} setup"
        )
    write_private(HOME / "key", key)
    say(f"this computer now has its own scan key from {base} (saved in {HOME / 'key'})")
    return key


def api_or_fail():
    base, key, _ = settings()
    if not api_url_allowed(base):
        fail(f"the API must be https:// (plain http only for 127.0.0.1): {base}")
    return Api(base, key or register(base))


# ---------------------------------------------------------------- where results live (same layout as the ssc app)
def folder_arg(raw):
    p = Path(os.path.abspath(os.path.expanduser(raw or ".")))
    if not p.is_dir():
        fail(f"not a folder: {p}")
    return p


def folder_label(folder):
    """How a folder is named to the server: "~/..." under the home folder (no user name)."""
    try:
        return "~/" + Path(folder).relative_to(Path.home()).as_posix()
    except ValueError:
        return Path(folder).as_posix()


def path_component(s, fallback):
    clean = "".join(c if c.isascii() and (c.isalnum() or c in "-.") else "_" for c in s)
    return fallback if set(clean) <= {"."} else clean


def folder_results(label):
    return HOME / "results" / path_component(path_component(label, "_").strip("_"), "_")


def advice_text(r):
    """The agents' advisory, or (when there is none) the action items from the rules."""
    if isinstance(r.get("advice"), str):
        return r["advice"]
    err = f": {r['error']}" if isinstance(r.get("error"), str) else ""
    s = (
        f"# Supply-chain check: {r.get('folder') or ''}\n\nNo written advisory ({r.get('advice_status') or 'none'}"
        f"{err}). Action items from the rules:\n\n"
        "| Priority | Project | Item | Where | Action |\n|---|---|---|---|---|\n"
    )

    def cell(v):
        return (v if isinstance(v, str) else "").replace("|", "/")

    for a in r.get("actions") or []:
        where = ", ".join(w for w in a.get("where") or [] if isinstance(w, str)).replace("|", "/")
        prio = "Fix now" if a.get("priority") == "block" else "Review"
        s += f"| {prio} | {cell(a.get('project'))} | {cell(a.get('item'))} | {where} | {cell(a.get('action'))} |\n"
    return s


def save_result(label, r):
    d = folder_results(label) / path_component(str(r.get("id") or "scan"), "scan")
    d.mkdir(parents=True, exist_ok=True)
    (d / "ADVICE.md").write_text(advice_text(r), encoding="utf-8")
    save_json(d / "plan.json", r.get("plan"))
    save_json(d / "result.json", r)
    return d


def latest(folder):
    """The folder's latest scan entry, from state.json."""
    state = load_json(HOME / "state.json", {})
    entry = state.get(folder_label(folder))
    if not isinstance(entry, dict):
        entry = next((v for v in state.values() if isinstance(v, dict) and v.get("folder") == str(folder)), None)
    if not entry or not entry.get("dir"):
        fail(f"no scan results for {folder}: run the scan step first")
    return entry


# ---------------------------------------------------------------- ticks (done.json, shared with the app)
def state_of(record):
    """An item's state from its done.json record: "pending" (no record), "skipped", or "done" (ticked by hand,
    applied by the plugin, or resolved: a later scan no longer found it)."""
    if not record:
        return "pending"
    return "skipped" if record.get("how") == "skipped" else "done"


def snapshot(row):
    return {
        k: row.get(k)
        for k in ("project", "item", "problem", "action", "where", "priority", "criticality", "kind", "sources")
    }


def after_scan(done_path, previous, current):
    """Tick what the previous scan listed and this one no longer finds (rule-based rows only); untick `resolved` and
    `applied` items it still finds. -> how many were newly ticked."""
    now_keys = {r.get("key") for r in current or []}
    done, changed = load_json(done_path, {}), 0
    for row in previous or []:
        k = row.get("key")
        # the agents' own rows ("other") are written fresh each time: one missing is no proof of a fix
        if not k or row.get("kind") == "other":
            continue
        if k not in now_keys and k not in done:
            done[k] = {"how": "resolved", "at": now(), "row": snapshot(row)}
            changed += 1
    back = [k for k, v in done.items() if v.get("how") in ("resolved", "applied") and k in now_keys]
    for k in back:
        del done[k]
    if changed or back:
        save_json(done_path, done)
    return changed


def load(folder):
    """-> (entry, result, done, done_path) for the folder's latest scan."""
    entry = latest(folder)
    result = load_json(Path(entry["dir"]) / "result.json", None)
    if not isinstance(result, dict):
        fail("cannot read the scan's result.json: run the scan step again")
    if "actions" not in result:
        fail("this scan is from an older version: run the scan step again")
    done_path = Path(entry["dir"]).parent / "done.json"
    return entry, result, load_json(done_path, {}), done_path


# ---------------------------------------------------------------- one scan at a time (with the app's scans too)
class ScanLock:
    def __init__(self):
        self.f = None

    def acquire(self):
        try:
            import fcntl
        except ImportError:  # Windows: no lock
            return True
        HOME.mkdir(parents=True, exist_ok=True)
        self.f = open(HOME / "scan.lock", "a")  # noqa: SIM115 (held until the scan ends)
        try:
            fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            self.f.close()
            self.f = None
            return False


# ---------------------------------------------------------------- commands
def cmd_setup(args):
    base = (args.api or settings()[0]).rstrip("/")
    if not api_url_allowed(base):
        fail(f"the API must be https:// (plain http only for 127.0.0.1): {base}")
    read = (lambda: getpass.getpass("Scan key (input hidden): ")) if sys.stdin.isatty() else sys.stdin.readline
    key = read().strip()
    if not key:
        fail("no key given")
    status, body = Api(base, key).call("GET", "/v1/scanner-rules")
    if status in (401, 403):
        fail(f"the server at {base} refused this key ({status}): check it with the server admin")
    if status != 200:
        fail(f"the server at {base} answered {status}: {body.get('error', '')}")
    write_private(HOME / "key", key)
    saved = load_json(HOME / "ssc.json", {})
    saved["api"] = base
    save_json(HOME / "ssc.json", saved)
    out({"saved": True, "server": base, "key_file": str(HOME / "key")})


def cmd_status(_args):
    base, key, where = settings()
    try:
        status, _ = Api(base, None).call("GET", "/v1/health", timeout=20)
        up = "up" if status == 200 else f"answered {status}"
    except RuntimeError as e:
        up = str(e)
    out({"server": base, "reachable": up, "key": f"saved ({where})" if key else "none yet: the first scan gets one"})


PROGRESS = {
    "queued": "waiting for the server",
    "assessing": "checking every package against the database and the rules",
    "advising": "the agents are writing the advisory (about a minute)",
    "agent_running": "the agents are writing the advisory (about a minute)",
}


def _wait_for_lock(minutes=30):
    """One scan at a time, with the ssc app's scans too: wait while another one runs."""
    lock, deadline = ScanLock(), time.time() + minutes * 60
    while not lock.acquire():
        if time.time() > deadline:
            fail(f"another scan (probably the ssc app's) is still running after {minutes} minutes; try again later")
        say("another scan is running; waiting for it to finish")
        time.sleep(15)
    return lock  # held until the process ends


def _closed_items(done_path):
    """The items the developer closed, as the server takes them with a scan (states, kinds and reasons, no values)."""
    return [
        {"key": k, **{f: (v.get("row") or {}).get(f) for f in ("project", "item", "action", "kind")},
         "state": state_of(v), **({"why": v["why"]} if v.get("why") else {})}
        for k, v in load_json(done_path, {}).items()
    ]  # fmt: skip


def _submit_and_wait(api, body):
    """Send a scan and wait for the server's result. -> the result."""
    try:
        status, r = api.call("POST", "/v1/scans", body, timeout=300)
        if status != 200:
            fail(f"the server refused the scan ({status}): {r.get('error', '')}")
        scan_id, poll, last = r.get("id", ""), r.get("poll", ""), ""
        end = time.time() + WAIT_MINUTES * 60
        while True:
            time.sleep(2)
            status, s = api.call("GET", poll)
            if status != 200:
                fail(f"checking scan {scan_id} failed ({status}): {s.get('error', '')}")
            what = PROGRESS.get(s.get("status"), "")
            if what and what != last:
                say(what)
                last = what
            if s.get("status") in ("done", "failed"):
                break
            if time.time() > end:
                fail(f"no result after {WAIT_MINUTES} minutes (scan {scan_id}); run list later or scan again")
    except RuntimeError as e:
        fail(str(e))
    if s.get("status") == "failed":
        fail(f"the server could not assess the scan: {s.get('error', '')}")
    return s


def _record(folder, label, s, done_path):
    """Save a scan's result where the ssc app keeps its own, tick what it no longer finds, and update state.json.
    -> (the result's folder, how many items it ticked as fixed, state.json's entry)."""
    state = load_json(HOME / "state.json", {})
    prev_dir = (state.get(label) or {}).get("dir")
    previous = load_json(Path(prev_dir) / "result.json", {}).get("actions") if prev_dir else None
    saved = save_result(label, s)
    fixed = after_scan(done_path, previous, s.get("actions")) if isinstance(previous, list) else 0
    changes = s.get("changes") or {}
    state[label] = {
        "folder": str(folder),
        "scan_id": s.get("id"),
        "at": now(),
        "summary": s.get("summary"),
        "advice_status": s.get("advice_status"),
        "dir": str(saved),
        "advice": str(saved / "ADVICE.md"),
        "new": len(changes.get("new") or []),
        "resolved": len(changes.get("resolved") or []),
        "first_scan": changes.get("first_scan"),
    }
    save_json(HOME / "state.json", state)
    return saved, fixed, state[label]


def cmd_scan(args):
    folder = folder_arg(args.folder)
    api = api_or_fail()
    _lock = _wait_for_lock()
    try:
        status, fetched = api.call("GET", "/v1/scanner-rules")
    except RuntimeError as e:
        fail(str(e))
    rules = ssc_scope.load_rules(fetched if status == 200 else None, HOME / "scanner_rules.json")

    label, t0 = folder_label(folder), time.time()
    scope, projects = ssc_scope.scan(folder, rules)
    scope.pop("base_dir", None)  # the server gets no local paths
    scope.pop("$comment", None)
    scope["projects"] = projects
    say(f"{len(scope['packages'])} package(s) found in {time.time() - t0:.1f}s; sending to {api.base}")

    done_path = folder_results(label) / "done.json"
    body = {"folder": label, "device_name": socket.gethostname(), "scope": scope, "done": _closed_items(done_path)}
    s = _submit_and_wait(api, body)
    saved, fixed, entry = _record(folder, label, s, done_path)

    closed = load_json(done_path, {})
    n_open = sum(1 for a in s.get("actions") or [] if a.get("key") not in closed)
    sm = s.get("summary") or {}
    line = (
        f"BLOCK {sm.get('BLOCK')} · HOLD {sm.get('HOLD')} · ALLOW {sm.get('ALLOW')} · {n_open} action item(s) open"
        + (f", {fixed} fixed since the last scan" if fixed else "")
        + f" · advice {s.get('advice_status')}"
    )
    out(
        {
            "scan_id": s.get("id"),
            "at": entry["at"],
            "summary": sm,
            "advice_status": s.get("advice_status"),
            "dir": str(saved),
            "result": line,
            "server": api.base,
        }
    )


def target(folder, rel):
    """Edit paths are relative to the scanned folder's parent; refuse anything that leaves the folder."""
    p = (folder.parent / rel).resolve()
    real = folder.resolve()
    return p if p == real or real in p.parents else None


SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next"}


def internal_names(folder):
    """Package names the folder declares as its own (internal-packages.txt anywhere in it). Their manifest lines are
    never edited here, whatever the server proposes: removing one, or pointing it at a public version, is exactly the
    dependency-confusion mistake."""
    names = set()
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if "internal-packages.txt" in files:
            with open(os.path.join(root, "internal-packages.txt"), encoding="utf-8", errors="replace") as f:
                names |= {ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}
    return names


def touches_internal(edits, internal):
    return any(str(e.get("package") or "").lower() in internal for e in edits)


def read_lines(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read().splitlines(keepends=True)


def check(folder, edit):
    """One edit against the file as it is now: ready, moved (same text on another line), done, conflict, outside."""
    path = target(folder, edit.get("file", ""))
    if path is None:
        return "outside", None, None
    if not path.is_file():
        return "conflict", path, None
    text = [x.rstrip("\r\n") for x in read_lines(path)]
    old, new, n = edit.get("old"), edit.get("new"), edit.get("line") or 0
    if 0 < n <= len(text) and text[n - 1] == old:
        return "ready", path, n
    if text.count(old) == 1:
        return "moved", path, text.index(old) + 1
    if (new is not None and new in text) or (new is None and old not in text):
        return "done", path, None
    return "conflict", path, None


def ids_arg(raw, count):
    try:
        ids = sorted({int(x) for x in raw.split(",") if x.strip()})
    except ValueError:
        fail("--ids must be numbers from `list`, like 1,3,4")
    bad = [i for i in ids if not 1 <= i <= count]
    if bad:
        fail(f"no action item number {bad[0]} (there are {count})")
    return ids


def cmd_list(args):
    folder = folder_arg(args.folder)
    entry, result, done, _ = load(folder)
    edits = (result.get("plan") or {}).get("edits") or []
    internal = internal_names(folder)
    rows = []
    for i, a in enumerate(result["actions"], 1):
        mine = [edits[j] for j in a.get("edits") or [] if j < len(edits)]
        auto = [] if touches_internal(mine, internal) else [check(folder, e)[0] for e in mine]
        rows.append(
            {
                "id": i,
                "state": state_of(done.get(a["key"])),
                "how": (done.get(a["key"]) or {}).get("how"),
                "why": (done.get(a["key"]) or {}).get("why"),
                "priority": "fix now" if a.get("priority") == "block" else "review",
                "criticality": a.get("criticality"),
                "project": a.get("project"),
                "item": a.get("item"),
                "problem": a.get("problem"),
                "where": a.get("where"),
                "action": a.get("action"),
                "can_apply": bool(auto) and any(s in ("ready", "moved") for s in auto),
                "edit_status": auto or None,
                # every link behind the item (advisories, the registry page, news), to cite next to it
                "sources": [
                    {k: s[k] for k in ("text", "url", "title") if s.get(k)}
                    for s in a.get("sources") or []
                    if isinstance(s, dict) and s.get("url")
                ],
            }
        )
    keys = {a["key"] for a in result["actions"]}
    fixed = [
        {"item": (d.get("row") or {}).get("item"), "project": (d.get("row") or {}).get("project"), "at": d.get("at")}
        for k, d in done.items()
        if k not in keys and d.get("how") == "resolved"
    ]
    out(
        {
            "scan": entry.get("scan_id"),
            "summary": result.get("advice_summary"),
            "open": sum(r["state"] == "pending" for r in rows),
            "skipped": sum(r["state"] == "skipped" for r in rows),
            "actions": rows,
            "fixed_since_earlier_scans": fixed,
        }
    )


def cmd_apply(args):
    folder = folder_arg(args.folder)
    entry, result, done, done_path = load(folder)
    actions, edits = result["actions"], (result.get("plan") or {}).get("edits") or []
    ids = ids_arg(args.ids, len(actions))
    internal = internal_names(folder)

    per_file, report, applied_ids = {}, [], set()
    for i in ids:
        a = actions[i - 1]
        mine = [edits[j] for j in a.get("edits") or [] if j < len(edits)]
        if touches_internal(mine, internal):
            report.append({"id": i, "status": "skipped", "why": "internal package: never edited automatically"})
            continue
        if not mine:
            report.append({"id": i, "status": "skipped", "why": "no automatic edit: do it by hand, then tick it"})
            continue
        for e in mine:
            status, path, line = check(folder, e)
            if status in ("ready", "moved") and e.get("verified"):
                per_file.setdefault(path, []).append((line, i, e))
            elif status == "done":
                applied_ids.add(i)
            else:
                report.append(
                    {"id": i, "status": "skipped", "why": "unverified" if status in ("ready", "moved") else status}
                )

    backup = Path(entry["dir"]) / ("backup-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    real = folder.resolve()
    for path, items in per_file.items():
        dest = backup / path.relative_to(real.parent)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(path.read_bytes())
        lines = read_lines(path)
        for line, _i, e in sorted(items, key=lambda t: t[0], reverse=True):  # bottom-up: removals don't shift lines
            ending = lines[line - 1][len(lines[line - 1].rstrip("\r\n")) :]
            if e.get("new") is None:
                del lines[line - 1]
            else:
                lines[line - 1] = e["new"] + ending
        text = "".join(lines)
        if path.suffix == ".json":
            try:
                json.loads(text)
            except ValueError as err:  # e.g. a removal left a trailing comma: leave the file alone
                report += [
                    {"id": i, "status": "skipped", "why": f"{path.name} would not be valid JSON ({err})"}
                    for _, i, _ in items
                ]
                continue
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        applied_ids |= {i for _, i, _ in items}

    # an item counts as applied when none of its edits was skipped
    skipped = {r["id"] for r in report}
    ticked = sorted(applied_ids - skipped)
    for i in ticked:
        a = actions[i - 1]
        done[a["key"]] = {"how": "applied", "at": now(), "row": snapshot(a)}
    if ticked:
        save_json(done_path, done)
    out(
        {
            "applied_and_ticked": ticked,
            "skipped": sorted(report, key=lambda r: r["id"]),
            "backup": str(backup) if per_file else None,
            "restore": f"python3 {Path(__file__).resolve()} restore {backup} {folder}" if per_file else None,
            "note": "Manifests only: nothing was installed. Reinstall dependencies yourself, then rescan to confirm.",
        }
    )


def cmd_done(args):
    """done: the user did it. skip: not relevant to them, or they won't do it (with their reason). pending: reopen."""
    folder = folder_arg(args.folder)
    _, result, done, done_path = load(folder)
    actions = result["actions"]
    ids = ids_arg(args.ids, len(actions))
    state = "pending" if args.cmd == "pending" or getattr(args, "undo", False) else args.cmd
    for i in ids:
        a = actions[i - 1]
        if state == "pending":
            done.pop(a["key"], None)
        elif state == "skip":
            why = (args.why or "").strip()[:200]
            done[a["key"]] = {"how": "skipped", "at": now(), "row": snapshot(a), **({"why": why} if why else {})}
        else:
            done[a["key"]] = {"how": "ticked", "at": now(), "row": snapshot(a)}
    save_json(done_path, done)
    out({{"done": "done", "skip": "skipped", "pending": "pending"}[state]: ids})


def cmd_context(args):
    """Facts from the project's own files about whether each pending item matters here (relevance.py)."""
    import relevance

    folder = folder_arg(args.folder)
    _, result, done, _ = load(folder)
    rules = ssc_scope.load_rules(None, HOME / "scanner_rules.json")
    out({"items": relevance.facts(folder, result, done, rules)})


def cmd_confirm(args):
    """Check a call path, hop by hop, against the parsed Python code of one project (code_index.py): the gate a
    claimed path must pass before it is shown as evidence."""
    import code_index
    import relevance

    folder = folder_arg(args.folder)
    rules = ssc_scope.load_rules(None, HOME / "scanner_rules.json")
    projects = {p.name: p for p in ssc_scope.projects_in(folder, rules)}
    if args.project not in projects:
        fail(f"no project {args.project!r} under {folder} (projects: {', '.join(sorted(projects)) or 'none'})")
    project = projects[args.project]
    index = code_index.Index(project, ssc_scope.files_in(project, rules), lambda rel: relevance.category(rel) == "test")
    out({"hops": args.hops, **index.confirm(args.hops)})


def cmd_restore(args):
    backup, folder = Path(args.backup).resolve(), folder_arg(args.folder)
    if not backup.is_dir():
        fail(f"no backup at {backup}")
    restored = []
    for src in backup.rglob("*"):
        if src.is_file():
            dest = target(folder, src.relative_to(backup))
            if dest is not None:
                shutil.copy2(src, dest)
                restored.append(str(dest))
    out({"restored": restored, "note": "Applied items stay ticked until the next scan, which unticks what is back."})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup").add_argument("--api", help=f"the advisory API (default: {DEFAULT_API})")
    sub.add_parser("status")
    for name in ("scan", "list", "context"):
        sub.add_parser(name).add_argument("folder")
    a = sub.add_parser("apply")
    a.add_argument("folder")
    a.add_argument("--ids", required=True, help="action item numbers from `list`, e.g. 1,3,4")
    for name, what in (("done", "the user did it"), ("skip", "not relevant to the user, or they won't do it"),
                       ("pending", "reopen: neither done nor skipped")):  # fmt: skip
        d = sub.add_parser(name, help=what)
        d.add_argument("folder")
        d.add_argument("--ids", required=True)
        if name == "done":
            d.add_argument("--undo", action="store_true", help="the same as pending")
        if name == "skip":
            d.add_argument("--why", help="the user's reason, in their words (helps rank such items lower)")
    c = sub.add_parser("confirm", help="check a claimed call path against the parsed code")
    c.add_argument("folder")
    c.add_argument("--project", required=True)
    c.add_argument("--hops", nargs="+", required=True, help="qualified names, e.g. app.views.upload yaml.load")
    r = sub.add_parser("restore")
    r.add_argument("backup")
    r.add_argument("folder")
    args = ap.parse_args()
    commands = {
        "setup": cmd_setup,
        "status": cmd_status,
        "scan": cmd_scan,
        "list": cmd_list,
        "context": cmd_context,
        "confirm": cmd_confirm,
        "apply": cmd_apply,
        "done": cmd_done,
        "skip": cmd_done,
        "pending": cmd_done,
        "restore": cmd_restore,
    }
    commands[args.cmd](args)


if __name__ == "__main__":
    main()
