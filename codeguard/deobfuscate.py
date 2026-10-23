"""Backward-compatible shim — see codeguard.pipeline.deobfuscate."""
from codeguard.pipeline.deobfuscate import (  # noqa: F401
    Layer,
    deobfuscate,
    deobfuscate_layers,
    deobfuscate_with_meta,
    describe_layers,
    resolve_line,
)

__all__ = [
    "Layer",
    "deobfuscate",
    "deobfuscate_layers",
    "deobfuscate_with_meta",
    "describe_layers",
    "resolve_line",
]
