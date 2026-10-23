"""Backward-compatible shim — detectors now live in codeguard.detectors."""
from __future__ import annotations

from codeguard.detectors import (  # noqa: F401
    Evidence,
    run_all_detectors,
    run_all_detectors_compat,
)
from codeguard.detectors.base import Context

# Legacy name used by older callers.
def run_all_detectors_legacy(code: str, deob_code: str = ""):
    return run_all_detectors_compat(code, deob_code)


__all__ = ["Evidence", "Context", "run_all_detectors", "run_all_detectors_compat"]
