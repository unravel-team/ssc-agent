"""Auth, request dispatch (App) and the entry point (serve) for the routes in routes.py.

serve() runs the API with FastAPI + uvicorn (fastapi_app.py). App.dispatch is the request logic FastAPI calls for
every route (keys, roles, body parsing, handler, JSON errors); the tests also call it directly, without HTTP.

Auth: keys in SSC_INTEL_API_KEYS as "role:key,role:key" (roles: read < write < admin), sent as
"Authorization: Bearer <key>" or "X-API-Key: <key>". With no keys set the server only runs on
127.0.0.1 and treats every local caller as admin (development mode).

Laptops can also get a scan key for themselves (POST /v1/register, see routes.h_register): those are kept in the
database as hashes and only ever have the "scan" role. SSC_SELF_REGISTER=0 turns registration off.
"""

import faulthandler
import hmac
import json
import os
import re
import signal
import sys
import threading
import time
import traceback

from ..engine.scans import ScanWorker, device_id, key_hash
from ..engine.scheduler import Scheduler, log
from .routes import ROLES, ROUTES, ApiError


def load_keys(spec=None):
    keys = {}
    for part in (spec if spec is not None else os.environ.get("SSC_INTEL_API_KEYS", "")).split(","):
        role, _, key = part.strip().partition(":")
        if key and role in ROLES:
            keys[key] = role
    return keys


def client_of(headers):
    """The caller's address as the proxy in front reports it (Fly.io sets Fly-Client-IP), for registration limits."""
    for h in ("Fly-Client-IP", "X-Forwarded-For", "X-Real-IP"):
        v = (headers.get(h) or "").split(",")[0].strip()
        if v:
            return v
    return "unknown"


class App:
    KEY_CACHE_SECONDS = 300  # a revoked self-registered key stops working within this long

    def __init__(self, store, keys=None, scheduler=None, scan_worker=None, self_register=None):
        self.store, self.keys, self.scheduler, self.scan_worker = store, keys or {}, scheduler, scan_worker
        self.self_register = os.environ.get("SSC_SELF_REGISTER", "1") != "0" if self_register is None else self_register
        self._ctx = threading.local()  # the caller of the request this thread is handling
        self._known = {}  # key hash -> when it was last confirmed in the database

    def _registered(self, tok):
        """Whether `tok` is an active self-registered scan key (checked in the database, cached for a few minutes)."""
        h = key_hash(tok)
        seen = self._known.get(h)
        if seen and time.monotonic() - seen < self.KEY_CACHE_SECONDS:
            return True
        if self.store.scan_key_active(h):
            if len(self._known) > 10000:
                self._known.clear()
            self._known[h] = time.monotonic()
            return True
        self._known.pop(h, None)
        return False

    def _key_and_role(self, headers):
        tok = (
            re.sub(r"^Bearer\s+", "", headers.get("Authorization") or "").strip()
            or (headers.get("X-API-Key") or "").strip()
        )
        if not self.keys:
            return "", "admin"  # dev mode: localhost only (enforced in serve())
        if not tok:
            return None, None
        # compare as bytes (compare_digest refuses non-ASCII str) and against every key, so the time taken says
        # nothing about which key, or how much of one, matched
        got, found = tok.encode("utf-8", "surrogateescape"), (None, None)
        for k, role in self.keys.items():
            if hmac.compare_digest(got, k.encode("utf-8", "surrogateescape")):
                found = (k, role)
        if found[1] is None and self._registered(tok):
            found = (tok, "scan")
        return found

    def client(self):
        return getattr(self._ctx, "client", "unknown")

    def caller(self):
        """Who is calling: a stable id derived from their key (each laptop has its own key)."""
        return device_id(getattr(self._ctx, "key", ""))

    def caller_role(self):
        return getattr(self._ctx, "role", None)

    def dispatch(self, method, path, query, headers, body_bytes):
        """-> (status, json-able). Pure function of the request, used by the FastAPI routes and the tests.

        The caller's key and role are kept in a thread-local for the handler (app.caller()): FastAPI runs each request
        start to end in one worker thread, and they are cleared when the request ends so a thread never carries one
        request's caller into the next."""
        try:
            for meth, pat, need, fn in ROUTES:
                mt = re.fullmatch(pat, path)
                if not mt or meth != method:
                    continue
                self._ctx.key, self._ctx.role = "", None
                self._ctx.client = client_of(headers)
                if need:
                    key, role = self._key_and_role(headers)
                    if role is None:
                        raise ApiError(401, "missing or unknown API key")
                    if need not in ROLES[role]:
                        raise ApiError(403, f"needs a {need} key")
                    self._ctx.key, self._ctx.role = key, role
                body = {}
                if body_bytes:
                    try:
                        body = json.loads(body_bytes)
                    except ValueError:  # includes UnicodeDecodeError
                        raise ApiError(400, "body must be JSON") from None
                    except RecursionError:
                        raise ApiError(400, "body is nested too deeply") from None
                    if not isinstance(body, dict):
                        raise ApiError(400, "body must be a JSON object")
                return 200, fn(self, query, body, mt)
            if any(re.fullmatch(p, path) for _, p, _, _ in ROUTES):
                raise ApiError(405, "method not allowed")
            raise ApiError(404, "not found")
        except ApiError as e:
            return e.status, {"error": str(e), **getattr(e, "extra", {})}
        except Exception as e:  # noqa: BLE001 - the request boundary: log it, answer 500, keep serving
            traceback.print_exc(limit=4, file=sys.stderr)
            # the details (SQL, hosts, paths) go to the log, not to the caller
            return 500, {"error": f"internal error ({type(e).__name__}); see the server log"}
        finally:
            self._ctx.key, self._ctx.role = "", None


def serve(store, host="127.0.0.1", port=8787, scheduler=True, keys=None):
    """Run the API with FastAPI + uvicorn (fastapi_app.py), with the background jobs."""
    # `kill -USR1 <pid>` prints every thread's Python stack to the log (to see where a stuck request or scan is)
    if hasattr(signal, "SIGUSR1"):
        faulthandler.register(signal.SIGUSR1, all_threads=True)
    keys = load_keys() if keys is None else keys
    if not keys and host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("Refusing to listen on a non-local address without API keys (set SSC_INTEL_API_KEYS).")
    try:
        from .fastapi_app import run
    except ImportError as e:
        raise SystemExit(
            "The API needs FastAPI and uvicorn (Python 3.11+). Run it with Docker (cd intel_api && "
            "docker compose up -d), or on Python 3.11+: cd intel_api && poetry install --with server"
        ) from e
    from .routes import lookup_for_scans, trust_for_scans

    app = App(
        store,
        keys,
        Scheduler(store) if scheduler else None,
        ScanWorker(store, lookup_for_scans(store), trust=trust_for_scans(store)),
    )
    log(
        f"FastAPI on http://{host}:{port}  docs /v1/docs  auth: {'API keys' if keys else 'dev mode (localhost, no keys)'}  db: {store.where}"
    )
    run(app, host, port, access_log=bool(os.environ.get("SSC_INTEL_API_ACCESS_LOG")))
