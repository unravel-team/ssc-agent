"""SSC sources API: collects supply-chain signals from the configured sources, stores them, and serves them.

    python3 -m intel_api serve            # API + background scheduler (see intel_api/README.md)
    python3 -m intel_api refresh [name]   # pull feed sources once
    python3 -m intel_api status

The core is standard library only; serving it uses FastAPI + uvicorn and Postgres (pyproject.toml, Poetry group `server`).
"""
