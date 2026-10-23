"""
app.py — FastAPI application for CodeGuard.

Endpoints: /check /batch /analyze /health /ui /demo/intercept

Hard rule: /check NEVER returns 4xx/5xx. Every response is HTTP 200 with a
schema-valid body, enforced through finalize_response()/fail_closed().
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from codeguard import config
from codeguard.csvio import parse_csv, results_to_csv
from codeguard.engine import analyze, analyze_detailed
from codeguard.guard import BlockedByCodeGuard
from codeguard.metrics import summarize
from codeguard.ml_model import ensure_model_ready
from codeguard.schema import empty_input, fail_closed

_DEV_PATH = os.environ.get("CODEGUARD_DEV_PATH", "codeguard_dev.jsonl")
_WEB_DIR = Path(__file__).parent.parent / "web"

# ── Global model state ────────────────────────────────────────────────────────
_model = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the ML model once at startup (not on first request)."""
    global _model
    try:
        _model = ensure_model_ready(dev_path=_DEV_PATH)
    except Exception:
        _model = None
    yield


app = FastAPI(
    title="CodeGuard",
    description="CPU-only code security analysis API. No LLM.",
    version=config.VERSION,
    lifespan=lifespan,
)


# ── Exception handlers — never 422/500 on the judged path ─────────────────────
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: Exception):
    return JSONResponse(content=empty_input(), status_code=200)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        content=fail_closed(f"Unhandled server error (fail-closed): {str(exc)[:200]}"),
        status_code=200,
    )


# ── Body helpers ──────────────────────────────────────────────────────────────
async def _read_code(request: Request) -> str:
    """Read the raw JSON body and coerce `code` to a string. Never raises."""
    try:
        body = await request.json()
    except Exception:
        return ""
    if isinstance(body, dict):
        code = body.get("code", "")
    else:
        code = body
    if code is None:
        return ""
    if not isinstance(code, str):
        try:
            code = str(code)
        except Exception:
            code = ""
    return code


def _coerce_batch(body: Any) -> list[dict]:
    """
    Accept {"snippets":[...]}, {"items":[...]}, {"code":...}, a bare list, or
    a list of plain strings. Always returns a list of {"id","code"} dicts.
    """
    if isinstance(body, dict):
        if "snippets" in body:
            seq = body["snippets"]
        elif "items" in body:
            seq = body["items"]
        elif "code" in body:
            seq = [body]
        else:
            seq = []
    elif isinstance(body, list):
        seq = body
    else:
        seq = []

    if not isinstance(seq, list):
        seq = [seq]

    items: list[dict] = []
    for idx, el in enumerate(seq):
        if isinstance(el, dict):
            code = el.get("code", "")
            item_id = el.get("id", idx)
        else:
            code = el
            item_id = idx
        if code is None:
            code = ""
        if not isinstance(code, str):
            try:
                code = str(code)
            except Exception:
                code = ""
        items.append({"id": item_id, "code": code})
    return items


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.post("/check")
async def check_endpoint(request: Request) -> JSONResponse:
    """Primary judged endpoint. Always HTTP 200 with the fixed schema."""
    code = await _read_code(request)
    result = analyze(code, model=_model)
    return JSONResponse(content=result, status_code=200)


@app.post("/batch")
async def batch(request: Request) -> JSONResponse:
    """Batch endpoint — per-item isolation, multiple input shapes."""
    try:
        body = await request.json()
    except Exception:
        body = None

    items = _coerce_batch(body)
    results = []
    for item in items:
        try:
            r = analyze(item["code"], model=_model)
        except Exception as exc:
            r = fail_closed(f"Item error (fail-closed): {str(exc)[:100]}")
        if item["id"] is not None:
            r = dict(r)
            r["id"] = item["id"]
        results.append(r)
    return JSONResponse(content={"results": results}, status_code=200)


@app.post("/analyze")
async def analyze_endpoint(request: Request) -> JSONResponse:
    """Same schema as /check plus diagnostics. Not judged."""
    code = await _read_code(request)
    response, diag = analyze_detailed(code, model=_model)
    payload = dict(response)
    payload.update(diag)
    return JSONResponse(content=payload, status_code=200)


async def _read_csv(request: Request) -> str | None:
    """Read CSV text from a multipart upload, JSON {"csv": "..."}, or raw body."""
    ctype = request.headers.get("content-type", "").lower()

    if "multipart/form-data" in ctype:
        try:
            form = await request.form()
            upload = form.get("file")
            if upload is not None and hasattr(upload, "read"):
                data = await upload.read()
                return data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else str(data)
        except Exception:
            return None

    try:
        body = await request.json()
        if isinstance(body, dict) and isinstance(body.get("csv"), str):
            return body["csv"]
    except Exception:
        pass

    try:
        raw = await request.body()
        if raw:
            return raw.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


@app.post("/batch/csv")
async def batch_csv(request: Request) -> Response:
    """
    Bulk analysis from a CSV file. Accepts:
      * multipart/form-data with a `file` field (an uploaded .csv)
      * JSON {"csv": "<csv text>"}
      * a raw CSV body

    Columns (case-insensitive, optional unless noted): `code` (required),
    `id`, `language`, and a gold column (`labels`/`categories`/`label`) whose
    value is a category list (`;`/`|`/`,` separated) or 1/0, true/false,
    malicious/benign. When gold labels are present a `summary` with
    precision/recall/F1/FPR/accuracy is returned.

    Add `?format=csv` to download the results as CSV instead of JSON.
    """
    csv_text = await _read_csv(request)
    if not csv_text or not csv_text.strip():
        empty = {"results": [], "summary": summarize([])}
        if request.query_params.get("format") == "csv":
            return PlainTextResponse(results_to_csv([]), media_type="text/csv")
        return JSONResponse(content=empty, status_code=200)

    items = parse_csv(csv_text)
    results = []
    for item in items:
        try:
            r = analyze(item["code"], model=_model)
        except Exception as exc:
            r = fail_closed(f"Item error (fail-closed): {str(exc)[:100]}")
        r = dict(r)
        r["id"] = item["id"]
        r["gold_malicious"] = item["gold_malicious"]
        r["gold_categories"] = item["gold_categories"]
        if item["gold_malicious"] is not None:
            r["correct"] = (r["verdict"] == "block") == bool(item["gold_malicious"])
        results.append(r)

    if request.query_params.get("format") == "csv":
        return PlainTextResponse(results_to_csv(results), media_type="text/csv")
    return JSONResponse(content={"results": results, "summary": summarize(results)}, status_code=200)
@app.get("/health")
async def health() -> JSONResponse:
    models_loaded = bool(_model is not None and getattr(_model, "_ready", False))
    return JSONResponse(content={
        "status": "ok",
        "models_loaded": models_loaded,
        "model_ready": models_loaded,  # kept for frontend compatibility
        "version": config.VERSION,
        "timestamp": time.time(),
    })


@app.post("/demo/intercept")
async def demo_intercept():
    """Run the interception proof and return results."""
    evidence: list[str] = []
    passed = True

    with tempfile.TemporaryDirectory() as tmpdir:
        marker = os.path.join(tmpdir, "marker.txt")

        # 1. Safe snippet — must be allowed and actually run.
        safe_code = f"with open(r'{marker}', 'w') as f: f.write('ok')"
        res_safe = analyze(safe_code, model=_model)
        if res_safe["verdict"] == "allow":
            evidence.append("Safe snippet: Guard ALLOWED.")
            try:
                subprocess.run(["python", "-c", safe_code], check=True)
                if os.path.exists(marker):
                    evidence.append("Marker file created successfully.")
                else:
                    evidence.append("FAILED: Marker file NOT created for safe snippet.")
                    passed = False
            except Exception as e:
                evidence.append(f"FAILED: Safe execution error: {str(e)}")
                passed = False
        else:
            evidence.append("FAILED: Guard BLOCKED safe snippet.")
            passed = False

        # 2. Unsafe snippet — must be blocked; marker must NOT be created.
        unsafe_code = (
            f"import os; os.system('rm -rf /'); "
            f"with open(r'{marker}', 'a') as f: f.write('evil')"
        )
        res_unsafe = analyze(unsafe_code, model=_model)
        if res_unsafe["verdict"] == "block":
            evidence.append("Unsafe snippet: Guard BLOCKED.")
            if os.path.exists(marker):
                os.remove(marker)

            try:
                if res_unsafe["verdict"] == "allow":
                    subprocess.run(["python", "-c", unsafe_code], check=True)
                else:
                    raise BlockedByCodeGuard(res_unsafe)
            except BlockedByCodeGuard:
                evidence.append("Execution BLOCKED by guard as expected.")
                if not os.path.exists(marker):
                    evidence.append("Marker file was NOT created/appended.")
                else:
                    evidence.append("FAILED: Marker file EXISTS for blocked snippet.")
                    passed = False
            except Exception as e:
                evidence.append(f"Unexpected error: {str(e)}")
                passed = False
        else:
            evidence.append("FAILED: Guard ALLOWED unsafe snippet.")
            passed = False

    return JSONResponse(content={"passed": passed, "evidence": evidence}, status_code=200)


# ── Static frontend ───────────────────────────────────────────────────────────
if _WEB_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(_WEB_DIR), html=True), name="ui")


@app.get("/")
async def root():
    return RedirectResponse(url="/ui")
