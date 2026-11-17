"""Scans sent by the laptop scanner: the scope in, an advisory and action plan out.

  POST /v1/scans      the scanner sends what it found in a folder (scope: packages with file/line/text, vendors, ...)
     status queued
  worker (here)       1. look every package version and vendor up (database first, sources on a miss)
     status assessing 2. the rules (lib/rules.py): ALLOW / HOLD / BLOCK, verified fix versions, line edits (engine/assess.py)
                      3. compare with this device's last advised scan of the folder: only NEW problems need fresh advice
     status advising  4a. something new (or the first scan): wait for the agents container to write the advisory
     status done      4b. nothing new: the last advisory is reused (no AI cost)
  agents container    claims advising scans (POST /v1/agents/claim), runs headless Claude Code on the files below,
     status done      sends the advisory back (POST /v1/agents/jobs/{id}/result)
  GET /v1/scans/{id}  the scanner polls; when done it shows the advisory and the action plan

A scan whose advisory doesn't arrive (no agents container, or it failed) still finishes: the rules' result and
the action plan are complete without it, and advice_status says what happened.
"""

import faulthandler
import hashlib
import json
import re
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone

from ..core.models import now_iso
from . import actions, checks
from . import advice as advice_mod
from . import assess as A
from .scheduler import log

MAX_PACKAGES = 10000  # package versions per scan (lockfiles list dependencies of dependencies too)
PLAYBOOK_KEY = "agents"  # where the agents' current playbook version is kept (sources table)
AGENT_WAIT_MINUTES = 30  # after this, a scan stops waiting for its advisory
AGENT_LEASE_MINUTES = 20  # an agent job not answered in this time can be claimed again
STRONG_SEV = {"HIGH", "CRITICAL"}
MAX_SECRETS = 500
STUCK_MINUTES = 10  # a scan assessing this long is reported with every thread's stack (report_stuck)
# what a laptop may say about a secret it found: where and what kind, never the value (anything else is dropped)
SECRET_FIELDS = {
    "project": str,
    "file": str,
    "line": int,
    "kind": str,
    "severity": str,
    "placeholder": bool,
    "in_source_code": bool,
    "env_file": bool,
    "tracked": bool,
    "ignored": bool,
}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ---------------------------------------------------------------- input
def validate(body):
    """-> (folder, device_name, scope) or raises ValueError with a message for the scanner."""
    scope = body.get("scope")
    if not isinstance(scope, dict):
        raise ValueError("scope: a JSON object (packages, vendors, ...) is required")
    folder = str(body.get("folder") or "").strip()
    if not folder or len(folder) > 200:
        raise ValueError("folder: the scanned folder's name (1-200 characters) is required")
    pkgs = scope.get("packages") or []
    if not isinstance(pkgs, list):
        raise ValueError("scope.packages must be a list")
    n = 0
    for p in pkgs:
        if (
            not isinstance(p, dict)
            or p.get("package_manager") not in ("npm", "pip")
            or not str(p.get("name") or "").strip()
        ):
            raise ValueError(f"bad package entry (needs package_manager npm|pip and name): {str(p)[:120]}")
        versions, found_in = p.get("versions") or [], p.get("found_in") or []
        if not isinstance(versions, list) or not all(isinstance(v, str) for v in versions):
            raise ValueError(f"versions of {str(p.get('name'))[:80]}: a list of version strings")
        if not isinstance(found_in, list) or not all(isinstance(f, dict) for f in found_in):
            raise ValueError(f"found_in of {str(p.get('name'))[:80]}: a list of objects")
        n += max(1, len(versions))
        for f in found_in:
            if str(f.get("file") or "").startswith("/"):
                raise ValueError("found_in.file must be relative to the scanned folder")
            if len(str(f.get("text") or "")) > 1000:
                raise ValueError("found_in.text: at most 1000 characters (one manifest line)")
    if n > MAX_PACKAGES:
        raise ValueError(f"at most {MAX_PACKAGES} package versions per scan")
    vendors = scope.get("vendors") or []
    if not isinstance(vendors, list) or len(vendors) > 50:
        raise ValueError("vendors: a list of at most 50 entries")
    # each certificate authority may be searched for in the news once: a short list of names
    for key in ("certificate_authorities", "internal_packages", "stack"):
        scope[key] = _names(scope.get(key), key)
    projects = scope.get("projects") or []
    if not isinstance(projects, list) or len(projects) > MAX_SECRETS:
        raise ValueError(f"projects: a list of at most {MAX_SECRETS} entries")
    scope["projects"] = [x for x in projects if isinstance(x, dict)]
    scope["secrets"] = clean_secrets(scope.get("secrets"))
    files = scope.get("certificate_files") or []
    if not isinstance(files, list) or len(files) > MAX_SECRETS:
        raise ValueError("certificate_files: a list of at most 500 entries")
    scope["certificate_files"] = [
        {k: str(f.get(k) or "")[:300] for k in ("project", "file", "ca")} for f in files if isinstance(f, dict)
    ]
    return folder, str(body.get("device_name") or "")[:100], scope


def _names(items, key, limit=MAX_SECRETS):
    """A list of names (CAs, internal packages, stack): strings only, each at most 200 characters."""
    if items is None:
        return []
    if not isinstance(items, list) or len(items) > limit:
        raise ValueError(f"{key}: a list of at most {limit} names")
    return [x.strip()[:200] for x in items if isinstance(x, str) and x.strip()]


def clean_secrets(items):
    """Keep only the allowed facts about each secret the laptop found (never a value), with checked types."""
    if items is None:
        return []
    if not isinstance(items, list) or len(items) > MAX_SECRETS:
        raise ValueError(f"secrets: a list of at most {MAX_SECRETS} entries")
    out = []
    for s in items:
        if not isinstance(s, dict):
            continue
        row = {}
        for k, typ in SECRET_FIELDS.items():
            v = s.get(k)
            if isinstance(v, typ) and not (typ is int and isinstance(v, bool)):
                row[k] = v[:200] if isinstance(v, str) else v
        if str(row.get("file", "")).startswith("/"):
            raise ValueError("secrets: file must be relative to the scanned folder")
        if row.get("severity") not in SEVERITIES:
            row["severity"] = "HIGH"
        if row.get("kind") and row.get("file"):
            out.append(row)
    return out


def secret_exposure(s):
    """Where a real secret stands, from the laptop's facts (git's view of the file):
    - "committed": git tracks the file, so the value is in the history: rotate it;
    - "in_code": in a source file, not committed: move it to the environment (rotate only if the code was shared);
    - "not_ignored": in a .env file git would pick up on the next `git add`: ignore the file, nothing to rotate;
    - "ok": in a .env file that git ignores (or a folder outside git): where secrets belong, nothing to do."""
    if s.get("tracked"):
        return "committed"
    if s.get("in_source_code") and not s.get("env_file"):
        return "in_code"
    if s.get("ignored") is False and s.get("tracked") is False:
        return "not_ignored"
    return "ok"


def secret_findings(secrets):
    """What to do about each secret (rules only). Only `committed` ones call for rotation; `ok` ones need nothing."""
    out = []
    for s in secrets:
        base = s["file"].rsplit("/", 1)[-1]
        if s.get("placeholder"):
            exposure, action = "example", "Looks like an example value: no action unless it is a real key."
        else:
            exposure = secret_exposure(s)
            action = {
                "committed": f"Rotate this {s['kind']} with its provider now (create a new one, revoke this one): it is "
                "committed to git, so remove it from the history too"
                + ("; then read it from an environment variable or a secret manager" if s.get("in_source_code") else "")
                + ".",
                "in_code": "Move it out of the code into an environment variable or a secret manager (an ignored .env "
                "file); rotate it if this code was ever shared or committed.",
                "not_ignored": f"Add {base} to .gitignore so it is never committed. No need to rotate: it isn't in git.",
                "ok": None,
            }[exposure]
        out.append({**s, "exposure": exposure, "action": action})
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(
        out, key=lambda s: (s.get("placeholder", False), rank.get(s.get("severity"), 9), s["file"], s.get("line") or 0)
    )


STATES = ("done", "skipped")  # an item with no record is pending


def done_keys(scope):
    """The keys of the action items the developer had closed (done or skipped) when the scan was sent."""
    return [d["key"] for d in (scope or {}).get("done_actions") or [] if isinstance(d, dict) and d.get("key")]


def done_items(body):
    """The action items the developer has closed on the laptop, for the advisory to leave out:
    [{key, project, item, action, kind, state, why}]. state: "done", or "skipped" (not relevant to them, or they
    won't do it; why: their reason, if they gave one). An older scanner sends only the keys, or no state (done)."""
    raw = body.get("done") or []
    if not isinstance(raw, list):
        raise ValueError("done: a list of action items")
    out = {}
    for d in raw[:500]:
        d = {"key": d} if isinstance(d, str) else d
        if not isinstance(d, dict) or not isinstance(d.get("key"), str) or not 0 < len(d["key"]) <= 300:
            continue
        row = {k: str(d.get(k) or "")[:300] for k in ("key", "project", "item", "action", "kind")}
        row["state"] = d.get("state") if d.get("state") in STATES else "done"
        row["why"] = str(d.get("why") or "")[:200]
        out[d["key"]] = row
    return [out[k] for k in sorted(out)]


def new_scan(device, folder, device_name, scope):
    ts = now_iso()
    return {
        "id": "scan_" + uuid.uuid4().hex[:16],
        "device": device,
        "device_name": device_name,
        "folder": folder,
        "status": "queued",
        "created_at": ts,
        "updated_at": ts,
        "scope": scope,
        "advice_status": "pending",
    }


# ---------------------------------------------------------------- what counts as new
def fingerprint(assessment, done=None):
    """{key: one-line description} of the problems that should trigger fresh advice. News/social counts are left
    out: they change every cycle and are weak signals on their own."""
    out = {}
    for p in assessment.get("packages", []):
        if p.get("verdict") not in ("BLOCK", "HOLD"):
            continue
        pkg = f"{p['package_manager']}:{p['package']}@{p.get('version') or 'latest'}"
        where = ", ".join(sorted({f.get("project") or "?" for f in p.get("found_in") or []})) or "?"
        out[f"verdict:{pkg}:{p['verdict']}"] = f"{p['verdict']} {pkg} in {where}: {(p.get('reasons') or [''])[0]}"
        for mid in p.get("malicious") or []:
            out[f"malicious:{pkg}:{mid}"] = f"Malicious report {mid} for {pkg}"
        for a in p.get("advisories") or []:
            if str(a.get("severity") or "").upper() in STRONG_SEV:
                out[f"advisory:{pkg}:{a['id']}"] = (
                    f"{a['severity']} advisory {a['id']} for {pkg}: {(a.get('summary') or '')[:120]}"
                )
        for r in p.get("reasons") or []:
            m = re.search(r"Breach notice '([^']+)'", r)
            if m:
                out[f"breach:{pkg}:{m.group(1)}"] = f"Breach notice for {pkg}: {r[:160]}"
    for c in assessment.get("certificates", []):
        if c["status"] in ("distrusted", "reported"):
            out[f"ca:{c['ca']}:{c['status']}"] = (
                f"Certificate authority {c['ca']} is {c['status']}: {(c.get('reasons') or [''])[0]}"
            )
    for s in assessment.get("secrets", []):
        if not s.get("placeholder") and s.get("exposure", "committed") != "ok":
            out[f"secret:{s.get('project')}:{s['file']}:{s.get('line')}:{s['kind']}"] = (
                f"Exposed {s['kind']} in {s['file']}:{s.get('line')}"
            )
    for v in assessment.get("vendors", []):
        for r in v.get("records") or []:
            if r.get("kind") == "breach":
                out[f"vendor-breach:{v['vendor']}:{r.get('url') or r.get('title')}"] = (
                    f"Breach report for vendor {v['vendor']}: {(r.get('title') or '')[:140]}"
                )
    for row in actions._lockfiles(assessment):
        out[row["key"]] = f"{row['item']} in {row['project']}"
    for k in done or []:  # a new tick changes what the advisory should say
        out[f"done:{k}"] = f"Marked done by the developer: {k}"
    return out


def current_playbook(store):
    """The version of the advisor playbook the agents run now (reported each time they ask for work)."""
    return ((store.source_state(PLAYBOOK_KEY) or {}).get("state") or {}).get("playbook")


# ---------------------------------------------------------------- the pipeline
def lookup_body(scope):
    """-> (packages, vendors) to look up. A package version found only in lockfiles is marked transitive: it is
    looked up without the per-package social search."""

    def transitive(p, v):
        locs = [f for f in p.get("found_in") or [] if f.get("version") == v]
        return bool(locs) and all(f.get("section") == "transitive" for f in locs)

    packages = [
        {"package_manager": p["package_manager"], "name": p["name"], "version": v, "transitive": transitive(p, v)}
        for p in scope.get("packages", [])
        for v in (p.get("versions") or [None])
    ]
    vendors = [v["name"] if isinstance(v, dict) else str(v) for v in scope.get("vendors") or []]
    return packages, [v for v in vendors if v]


def run(store, scan, lookup, releases=None, trust=None):
    """Assess one scan. `lookup(packages, vendors, social)` -> the /v1/lookup response (routes.lookup_for_scans);
    `releases(pm, name, version)` -> earlier releases to try as fixes (default: from the registry);
    `trust(scope)` -> the certificate-authority check (engine/trust.py), or None to skip it."""
    scope = scan["scope"]
    packages, vendors = lookup_body(scope)
    results = lookup(packages, vendors, True) if (packages or vendors) else {"packages": [], "vendors": []}

    def check(cands):
        return lookup([{"package_manager": pm, "name": n, "version": v} for pm, n, v in cands], [], False)["packages"]

    assessment = A.assess(scope, results, check, releases=releases or A.releases_before)
    assessment["certificates"] = trust(scope) if trust and scope.get("certificate_authorities") else []
    assessment["secrets"] = secret_findings(scope.get("secrets") or [])
    # each project's manifests and lockfiles (for the "no lockfile" action item)
    assessment["projects"] = [
        {k: p.get(k) for k in ("project", "manifests", "lockfiles")}
        for p in scope.get("projects") or []
        if isinstance(p, dict)
    ]
    prev = store.previous_scan(scan["device"], scan["folder"], scan["created_at"], exclude=scan["id"])
    done = done_keys(scope)
    now, before = fingerprint(assessment, done), ((prev or {}).get("result") or {}).get("fingerprint") or {}
    new = [v for k, v in now.items() if k not in before]
    resolved = [v for k, v in before.items() if k not in now]
    result = {
        "summary": assessment["summary"],
        "assessment": assessment,
        "fingerprint": now,
        "changes": {"first_scan": prev is None, "new": new, "resolved": resolved, "previous_scan": prev and prev["id"]},
        "diff": A.diff_text(assessment["edits"]),
    }
    # reuse the last advisory only if nothing changed AND it was written by the playbook the agents run now
    current = current_playbook(store)
    same_playbook = not current or ((prev or {}).get("result") or {}).get("playbook") == current
    # nor one that broke a rule (something was left out of it): the agents get another go
    clean = not (((prev or {}).get("result") or {}).get("advice_problems") or {}).get("dropped")
    if prev and not new and not resolved and prev.get("advice") and same_playbook and clean:
        kept = {
            k: prev["result"][k]
            for k in ("advice_data", "advice_problems", "playbook")
            if k in (prev.get("result") or {})
        }
        store.update_scan(
            scan["id"],
            status="done",
            result={**result, **kept},
            advice=prev["advice"],
            advice_status="reused",
            previous_id=prev["id"],
        )
        checks.report(store, scan["id"], log)
        return "done"
    store.update_scan(
        scan["id"], status="advising", result=result, advice_status="pending", previous_id=prev and prev["id"]
    )
    return "advising"


def agent_files(scan, previous=None, history=()):
    """What the agents get for one scan (written to their working folder): the facts, nothing to execute.
    `previous`: the last advised scan of the folder; its "Other actions" rows are passed on so the agent names the
    same item the same way (the laptop keeps the developer's ticks by that name)."""
    res, scope = scan["result"], scan["scope"]
    prev_advice, prev_data = (previous or {}).get("advice"), ((previous or {}).get("result") or {}).get("advice_data")
    earlier = [
        {k: r[k] for k in ("project", "item", "criticality", "action")}
        for r in actions.build({}, prev_advice, prev_data)
        if r["kind"] == "other"
    ]
    # a ticked item may come with its key only (an older scanner): name it from this scan's rows or earlier advisories
    known = {r["key"]: r for r in actions.build(res["assessment"], prev_advice, prev_data)}
    for advice in history:
        for r in actions.build({}, advice):
            known.setdefault(r["key"], r)
    done = []
    for d in scope.get("done_actions") or []:
        if not isinstance(d, dict):
            continue
        row = d if d.get("item") else known.get(d.get("key"))
        if row:
            done.append({**{k: row.get(k) for k in ("project", "item", "action")},
                         "state": d.get("state") or "done", **({"why": d["why"]} if d.get("why") else {})})  # fmt: skip
    return {
        **advice_mod.agent_files(
            res["assessment"], done_keys(scope)
        ),  # items.json, evidence.json: what advice.json refers to
        "done_actions.json": json.dumps(done, indent=2),
        "previous_other_actions.json": json.dumps(earlier, indent=2),
        "assessment.json": json.dumps(res["assessment"], indent=2),
        "changes.json": json.dumps(res["changes"], indent=2),
        "changes.diff": res["diff"],
        "scan.json": json.dumps(
            {
                "folder": scan["folder"],
                "device_name": scan.get("device_name"),
                "scanned_at": scan["created_at"],
                "projects": scope.get("projects") or [],
                "stack": scope.get("stack") or [],
                "certificate_authorities": scope.get("certificate_authorities") or [],
                "internal_packages": scope.get("internal_packages") or [],
                "vendors": scope.get("vendors") or [],
            },
            indent=2,
        ),
    }


def project_summary(assessment, scope):
    """BLOCK / HOLD / ALLOW counts per project (a package used in two projects counts in both)."""
    out = {
        p.get("project"): {"project": p.get("project"), "BLOCK": 0, "HOLD": 0, "ALLOW": 0, "UNKNOWN": 0}
        for p in (scope or {}).get("projects") or []
        if p.get("project")
    }
    for pkg in assessment.get("packages", []):
        for name in sorted({f.get("project") for f in pkg.get("found_in") or [] if f.get("project")}):
            row = out.setdefault(name, {"project": name, "BLOCK": 0, "HOLD": 0, "ALLOW": 0, "UNKNOWN": 0})
            row[pkg.get("verdict", "UNKNOWN") if pkg.get("verdict") in row else "UNKNOWN"] += 1
    return sorted(out.values(), key=lambda r: (-r["BLOCK"], -r["HOLD"], r["project"]))


def view(scan, full=True):
    """What the scanner gets back."""
    res = scan.get("result") or {}
    out = {
        "id": scan["id"],
        "status": scan["status"],
        "folder": scan["folder"],
        "device_name": scan.get("device_name"),
        "created_at": scan["created_at"],
        "updated_at": scan["updated_at"],
        "advice_status": scan.get("advice_status"),
        "summary": res.get("summary"),
        "changes": res.get("changes"),
        "projects": project_summary(res.get("assessment") or {}, scan.get("scope")) if res else [],
    }
    if scan.get("error"):
        out["error"] = scan["error"]
    if full and res:
        a = res.get("assessment") or {}
        out.update(
            actions=actions.build(a, scan.get("advice"), res.get("advice_data")),
            advice_summary=actions.summary(scan.get("advice")),
            advice=scan.get("advice"),
            plan={"edits": a.get("edits", []), "manual": a.get("manual", [])},
            diff=res.get("diff", ""),
            findings=[p for p in a.get("packages", []) if p.get("verdict") != "ALLOW"],
            vendors=a.get("vendors", []),
            certificates=a.get("certificates", []),
            secrets=a.get("secrets", []),
            advice_data=res.get("advice_data"),  # the advisory with its references (engine/advice.py)
            advice_problems=res.get("advice_problems"),
        )
        out["checks"] = checks.check(
            out, done_keys(scan.get("scope"))
        )  # engine/checks.py: what this result contradicts, if anything
    return out


def key_hash(key):
    """What is stored of a self-registered scan key (core/store.py scan_keys)."""
    return hashlib.sha256(key.encode("utf-8", "surrogateescape")).hexdigest()


def device_id(key):
    """A stable id for the key a scanner uses (each laptop gets its own key); the key itself is never stored."""
    return "dev_" + hashlib.sha256(key.encode()).hexdigest()[:16] if key else "local"


# ---------------------------------------------------------------- worker
class ScanWorker:
    """Runs queued scans in the API process (a few at a time) and stops scans waiting too long for their advisory."""

    def __init__(self, store, lookup, threads=2, poll=2.0, trust=None):
        self.store, self.lookup, self.threads, self.poll, self.trust = store, lookup, threads, poll, trust
        self.stop = threading.Event()

    def start(self):
        # this process owns the database: a scan still "assessing" was cut off by a restart, so it is run again
        for sid in self.store.scans_waiting("assessing", now_iso()):
            self.store.update_scan(sid, status="queued")
            log(f"scan {sid}: assessment was interrupted (restart); queued again")
        for i in range(self.threads):
            threading.Thread(target=self.loop, name=f"scan-worker-{i}", daemon=True).start()
        threading.Thread(target=self.expire_loop, name="scan-expiry", daemon=True).start()

    def loop(self):
        while not self.stop.is_set():
            scan = None
            try:
                scan = self.store.claim_scan("queued", "assessing")
                if not scan:
                    self.stop.wait(self.poll)
                    continue
                t0 = time.time()
                state = run(self.store, scan, self.lookup, trust=self.trust)
                log(f"scan {scan['id']} ({scan['folder']}): assessed in {time.time() - t0:.1f}s -> {state}")
            except Exception as e:  # noqa: BLE001 - one bad scan (or a database hiccup) must not stop the worker
                traceback.print_exc(limit=4)
                if scan:
                    try:
                        self.store.update_scan(
                            scan["id"], status="failed", error=f"{type(e).__name__}: {e}"[:300], advice_status="none"
                        )
                    except Exception:  # noqa: BLE001 - the database is down: the scan stays "assessing" until restart
                        traceback.print_exc(limit=2)
                self.stop.wait(self.poll)  # don't spin while the database is unavailable

    def expire_loop(self):
        reported = set()
        while not self.stop.wait(60):
            try:
                expire_waiting(self.store)
                report_stuck(self.store, reported)
            except Exception:  # noqa: BLE001 - logged; tried again next minute
                traceback.print_exc(limit=2)


def report_stuck(store, reported, minutes=STUCK_MINUTES, out=None):
    """A scan still being assessed after `minutes` is almost certainly stuck: log where every thread is (Python
    stacks), once per scan, so the cause shows in the server log. -> the ids reported now."""
    cut = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    new = [sid for sid in store.scans_waiting("assessing", cut) if sid not in reported]
    for sid in new:
        reported.add(sid)
        log(f"scan {sid}: still assessing after {minutes} minutes; where every thread is:")
        faulthandler.dump_traceback(file=out or sys.stderr, all_threads=True)
    return new


def expire_waiting(store, minutes=AGENT_WAIT_MINUTES):
    """Scans whose advisory hasn't arrived in time finish without one (the rules' result and plan are complete)."""
    cut = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    for status in ("advising", "agent_running"):
        for sid in store.scans_waiting(status, cut):
            store.update_scan(
                sid,
                status="done",
                advice_status="unavailable",
                error=f"no advisory from the agents within {minutes} minutes; the action plan is complete without it",
            )
            checks.report(store, sid, log)
