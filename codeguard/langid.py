"""Backward-compatible shim — see codeguard.pipeline.langid."""
from codeguard.pipeline.langid import (  # noqa: F401
    detect_language,
    detect_language_scored,
)

__all__ = ["detect_language", "detect_language_scored"]
