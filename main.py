"""
main.py — single-file entrypoint for CodeGuard, matching the deployment guide.

    uvicorn main:app --host 0.0.0.0 --port 8000
    # or simply:
    python main.py

This re-exports the real CodeGuard FastAPI application (codeguard.api:app) so
there is exactly one service — no duplicated logic. See ENDPOINT.md for the
ngrok walkthrough.

Judged endpoint : POST /check        (fixed schema, never 4xx/5xx)
Also available  : /batch  /batch/csv  /analyze  /health  /ui  /docs
"""
from __future__ import annotations

import os

import uvicorn

from codeguard.api import app  # noqa: F401  (uvicorn loads `main:app`)

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
        workers=1,  # single worker: the ML model is loaded exactly once
    )
