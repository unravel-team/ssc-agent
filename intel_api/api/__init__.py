"""HTTP API: routes.py (handlers + route table), server.py (auth, dispatch, serve), fastapi_app.py (FastAPI server)."""

from .server import App, load_keys, serve  # noqa: F401
