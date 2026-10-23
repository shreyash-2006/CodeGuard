"""
guard.py — CodeGuard interception layer.

Public API:
    BlockedByCodeGuard   exception carrying the blocking result
    check(code)          in-process analysis, never raises (fail-closed)
    guarded(fn)          decorator: runs fn(code, ...) only if allowed
    safe_exec(code, ...) runs a runner only after an `allow` verdict

The check happens synchronously BEFORE the runner is invoked.
`block` (and any guard error/timeout) raises BlockedByCodeGuard — fail-closed.
"""
from __future__ import annotations

import functools
import json
import subprocess
import sys
import urllib.request
from typing import Any, Callable, Optional

from codeguard.engine import analyze
from codeguard.schema import fail_closed

_MODEL = None


def _get_model():
    """Lazily load the shared ML model (rules-only if unavailable)."""
    global _MODEL
    if _MODEL is None:
        try:
            from codeguard.ml_model import ensure_model_ready
            _MODEL = ensure_model_ready()
        except Exception:
            _MODEL = None
    return _MODEL


class BlockedByCodeGuard(Exception):
    """Raised when CodeGuard blocks a snippet (or the guard itself fails)."""

    def __init__(self, result: dict):
        self.result = result or {}
        cats = ", ".join(self.result.get("categories", [])) or "unknown"
        super().__init__(
            f"Blocked by CodeGuard: {cats} "
            f"(risk {self.result.get('risk_score')})"
        )


def check(code: str, language: Optional[str] = None) -> dict:
    """In-process analysis. Never raises; fails closed on any error."""
    try:
        return analyze(code, model=_get_model())
    except Exception as exc:  # defence in depth — analyze() should not raise
        return fail_closed(f"Guard error (fail-closed): {str(exc)[:200]}")


def check_http(
    code: str,
    url: str = "http://127.0.0.1:8000/check",
    timeout: float = 1.0,
) -> dict:
    """Analyze via a running /check endpoint. Fail-closed on any error."""
    try:
        body = json.dumps({"code": code}).encode()
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        return fail_closed(f"Guard HTTP error (fail-closed): {str(exc)[:200]}")


def guarded(fn: Callable) -> Callable:
    """
    Decorator: fn(code, *a, **k) runs only if CodeGuard allows `code`.
    Fail-closed — any guard error/timeout raises BlockedByCodeGuard.
    """

    @functools.wraps(fn)
    def wrapper(code, *args, **kwargs):
        result = check(code)
        if result.get("verdict") != "allow":
            raise BlockedByCodeGuard(result)
        return fn(code, *args, **kwargs)

    return wrapper


def _default_runner(language: Optional[str]) -> Callable[..., subprocess.CompletedProcess]:
    """Default runner: subprocess python -c / bash -c by detected language."""

    def runner(code: str, timeout: float = 10.0, **_: Any):
        if language == "bash":
            cmd = ["bash", "-c", code]
        else:
            cmd = [sys.executable, "-c", code]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    return runner


def safe_exec(
    code: str,
    runner: Optional[Callable] = None,
    language: Optional[str] = None,
    mode: str = "local",
    **kw: Any,
):
    """
    Run `runner(code)` (default: subprocess python -c / bash -c by language)
    only after an `allow` verdict. Blocks by raising BlockedByCodeGuard.
    """
    result = check_http(code) if mode == "http" else check(code, language)
    if result.get("verdict") != "allow":
        raise BlockedByCodeGuard(result)
    if runner is None:
        runner = _default_runner(result.get("code_language"))
    return runner(code, **kw)
