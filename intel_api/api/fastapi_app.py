"""The API's web server: FastAPI + uvicorn, for the routes in routes.py.

Every route in routes.ROUTES is registered with FastAPI under its own path, so /v1/docs (Swagger UI) lists them.
Each request goes through App.dispatch (server.py): key check, roles, body parsing, the handler, JSON errors.
The handlers do blocking network and database work, so they run in FastAPI's worker threads.

Needs Python 3.11+ (Starlette) and the server dependencies in pyproject.toml (poetry install --with server).
"""

import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from .openapi import spec
from .routes import MAX_BODY, ROUTES, VERSION

# FastAPI paths for the routes whose patterns capture parts of the path (the handlers read the regex match)
PATHS = {
    r"/v1/packages/([^/]+)/(@[^/]+/[^/]+|[^/]+)": "/v1/packages/{package_manager}/{name:path}",
    r"/v1/search/([^/]+)": "/v1/search/{kind}",
    r"/v1/vendors/([^/]+)/signals": "/v1/vendors/{name}/signals",
    r"/v1/scans/([^/]+)": "/v1/scans/{scan_id}",
    r"/v1/agents/jobs/([^/]+)/result": "/v1/agents/jobs/{scan_id}/result",
}
OPENAPI_PATH = "/v1/openapi.json"


def _json(status, out):
    return Response(json.dumps(out, default=str), status_code=status, media_type="application/json")


def create_app(core):
    """core: an App (store, keys, scheduler, scan worker) from server.py; they start with the app."""

    @asynccontextmanager
    async def lifespan(_):
        if core.scheduler:
            core.scheduler.start()
        if core.scan_worker:
            core.scan_worker.start()
        yield
        # shutting down: let the background loops finish what they are doing and stop
        if core.scheduler:
            core.scheduler.stop.set()
            core.scheduler.wake.set()
        if core.scan_worker:
            core.scan_worker.stop.set()

    api = FastAPI(
        title="SSC sources API",
        version=VERSION,
        lifespan=lifespan,
        openapi_url=OPENAPI_PATH,
        docs_url="/v1/docs",
        redoc_url=None,
    )
    api.openapi = spec  # the hand-written spec: tests check it describes every route

    def endpoint(method):
        async def handle(request: Request):
            try:
                size = int(request.headers.get("content-length") or 0)
            except ValueError:
                return _json(400, {"error": "bad Content-Length"})
            if size > MAX_BODY:
                return _json(413, {"error": "body too large"})
            body = b""
            if method != "GET":
                # read in chunks and stop at the limit: a chunked upload has no Content-Length to check up front
                chunks, total = [], 0
                async for chunk in request.stream():
                    total += len(chunk)
                    if total > MAX_BODY:
                        return _json(413, {"error": "body too large"})
                    chunks.append(chunk)
                body = b"".join(chunks)
            # the raw (still percent-encoded) path, as the handlers expect: they decode names themselves
            path = request.scope.get("raw_path", b"").decode("latin-1").split("?", 1)[0].rstrip("/") or "/"
            query = dict(request.query_params)
            status, out = await run_in_threadpool(core.dispatch, method, path, query, request.headers, body)
            return _json(status, out)

        return handle

    for method, pattern, _role, _fn in ROUTES:
        path = PATHS.get(pattern) or pattern.replace("\\.", ".")
        if path == OPENAPI_PATH:
            continue  # FastAPI serves the spec itself (api.openapi above)
        api.add_api_route(path, endpoint(method), methods=[method], include_in_schema=False)

    @api.exception_handler(StarletteHTTPException)
    async def http_error(_request, exc):  # unknown paths and methods: the same JSON errors as the API's own
        msg = {404: "not found", 405: "method not allowed"}.get(exc.status_code, str(exc.detail))
        return _json(exc.status_code, {"error": msg})

    return api


def _dual_stack_socket(port):
    """One socket on every IPv6 and IPv4 address. uvicorn (asyncio) binding "::" accepts IPv6 only; hosts like Fly.io
    reach the app over both (the private network is IPv6, the proxy and health checks may use IPv4)."""
    import socket

    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", port))
    sock.set_inheritable(True)
    return sock


def run(core, host, port, access_log=False):
    import uvicorn

    config = uvicorn.Config(
        create_app(core),
        host=host,
        port=port,
        access_log=access_log,
        server_header=False,
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_level="info",
        backlog=2048,
        timeout_keep_alive=5,
    )
    server = uvicorn.Server(config)
    if host == "::":  # every address, IPv6 and IPv4
        server.run(sockets=[_dual_stack_socket(port)])
    else:
        server.run()
