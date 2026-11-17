"""python3 -m intel_api <command>

  serve [--host H] [--port P] [--no-scheduler]   run the API (FastAPI, Python 3.11+) + the background jobs
  refresh [JOB ...]                               run background jobs now (default: everything due); 'all' runs every job
  status                                          source and job health, coverage and store size
  push-notices FILE                               send a breach_notices.live.json to the API (AI-extracted: HOLD at most)
  copy-db SQLITE_FILE                             copy an existing SQLite database into the configured one (e.g. Postgres)
  keys [revoke DEVICE]                            scan keys laptops registered for themselves; revoke one by device id
  checks [--limit N]                              how often finished scans broke each consistency rule (engine/checks.py)

Everything else (lookups, items, alerts, scope, sources) is an API endpoint: see /v1/openapi.json.
"""

import argparse
import json
import os
import sys

from ._paths import API_DIR


def _load_env():
    """The API's settings and source credentials: intel_api/.env, the same file Docker uses (variables already set win)."""
    p = os.path.join(API_DIR, ".env")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def main():
    _load_env()
    ap = argparse.ArgumentParser(
        prog="python3 -m intel_api", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default=os.environ.get("SSC_INTEL_API_HOST", "127.0.0.1"))
    s.add_argument("--port", type=int, default=int(os.environ.get("SSC_INTEL_API_PORT", "8787")))
    s.add_argument("--no-scheduler", action="store_true")
    r = sub.add_parser("refresh")
    r.add_argument("sources", nargs="*")
    sub.add_parser("status")
    p = sub.add_parser("push-notices")
    p.add_argument("file")
    cp = sub.add_parser("copy-db")
    cp.add_argument("sqlite_file")
    k = sub.add_parser("keys")
    k.add_argument("action", nargs="?", choices=["revoke"])
    k.add_argument("device", nargs="?", help="the device id (dev_...) shown with each key and on its scans")
    ck = sub.add_parser("checks")
    ck.add_argument("--limit", type=int, default=200, help="how many of the newest scans to check")
    args = ap.parse_args()

    if args.cmd in ("serve", "refresh", "status", "keys", "checks"):
        from .core.store import Store

        store = Store()
    if args.cmd == "serve":
        from .api import serve

        serve(store, args.host, args.port, scheduler=not args.no_scheduler)
    elif args.cmd == "refresh":
        from .engine import jobs, scheduler

        keys = [j.key for j in jobs.all_jobs() if j.enabled] if args.sources == ["all"] else args.sources
        res = [scheduler.run(store, k) for k in keys] if keys else scheduler.run_due(store)
        print(json.dumps(res, indent=1))
    elif args.cmd == "status":
        from .api import App
        from .api.routes import h_sources

        out = h_sources(App(store), {}, {}, None)
        for k, v in out["sources"].items():
            if v["mode"] == "not connected":
                continue
            state = (
                "off"
                if not v["enabled"]
                else (
                    "on request"
                    if v["mode"] == "lookup"
                    else "never run"
                    if not v["last_run_at"]
                    else ("ok" if not v["last_error"] else "ERROR")
                )
            )
            speed = f"{v['speed']} ({v['every_seconds'] // 60} min)" if v.get("speed") else ""
            print(
                f"{k:24s} {v['mode']:7s} {speed:18s} {state:9s} last ok {v['last_ok_at'] or '-':26s} items {v['items'] if v['items'] is not None else '-':>5} "
                f"new {v['new_items'] if v['new_items'] is not None else '-':>4}  {v['last_error'] or v['disabled_reason'] or ''}"[
                    :200
                ]
            )
        print("\njobs (the only code that contacts sources):")
        for k, v in out["jobs"].items():
            state = (
                "off"
                if not v["enabled"]
                else ("never run" if not v["last_run_at"] else ("ok" if not v["last_error"] else "ERROR"))
            )
            print(
                f"  {k:22s} every {v['every_seconds']:>6}s  {state:9s} last ok {v['last_ok_at'] or '-':26s} {v['last_error'] or ''}"[
                    :200
                ]
            )
        print("\nsearch coverage:", json.dumps(out["search_coverage"]))
        print("package evidence:", json.dumps(out["package_evidence"]))
        print("items:", json.dumps(out["items"]))
        print(json.dumps(out["store"]))
    elif args.cmd == "keys":
        if args.action == "revoke":
            if not args.device:
                sys.exit("keys revoke DEVICE (a dev_... id from `keys`)")
            n = store.revoke_scan_key(args.device)
            print(f"revoked {n} key(s) of {args.device}" if n else f"no active key for {args.device}")
        else:
            for r in store.scan_keys():
                state = f"revoked {r['revoked_at']}" if r["revoked_at"] else "active"
                print(f"{r['device']}  {r['created_at']}  {state:30s}  {r['device_name'] or ''}")
    elif args.cmd == "checks":
        from .engine import checks

        print(json.dumps(checks.summarize(store, args.limit), indent=1))
    elif args.cmd == "copy-db":
        from .core.store import Store

        if not os.path.exists(args.sqlite_file):
            sys.exit(f"not found: {args.sqlite_file}")
        target = Store()
        print(f"copying {args.sqlite_file} -> {target.where}")
        target.copy_from(Store(args.sqlite_file))
    elif args.cmd == "push-notices":
        from . import client

        if not client.enabled():
            sys.exit("SSC_INTEL_API is not set or the API is not reachable")
        with open(args.file, encoding="utf-8") as f:
            notices = json.load(f)
        print(json.dumps(client.push_breach_notices(notices)))


if __name__ == "__main__":
    main()
