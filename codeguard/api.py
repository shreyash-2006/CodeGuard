"""
api.py — spec-canonical ASGI entry point.

    uvicorn codeguard.api:app --host 0.0.0.0 --port 8000 --workers 1

(The FastAPI application itself is defined in codeguard.app; this module exists
so both `codeguard.api:app` and `codeguard.app:app` work.)
"""
from codeguard.app import app  # noqa: F401

__all__ = ["app"]
