"""
detectors/base.py — Evidence, Context and shared helpers.

Every detector is a pure callable: detect(ctx: Context) -> list[Evidence].
The engine wraps each call in try/except so no detector can crash a request.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from codeguard.pipeline.deobfuscate import Layer
from codeguard.pipeline.segment import Segment


@dataclass
class Evidence:
    category: str
    confidence: float          # 0..1
    lines: list[int] = field(default_factory=list)
    reason: str = ""
    rule_id: str = ""
    snippet: str = ""
    layer: int = 0
    hard_block: bool = False

    @property
    def line(self) -> int:
        return self.lines[0] if self.lines else 1

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "rule_id": self.rule_id or self.category.upper(),
            "confidence": round(float(self.confidence), 4),
            "line": self.line,
            "lines": list(self.lines),
            "snippet": (self.snippet or self.reason)[:120],
            "description": self.reason,
            "layer": self.layer,
            "hard_block": bool(self.hard_block),
        }


@dataclass
class Context:
    code: str
    deob_code: str = ""
    language: str = "unknown"
    segments: list[Segment] = field(default_factory=list)
    parsed: dict[str, Any] = field(default_factory=dict)
    layers: list[Layer] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def text_of(self, *kinds: str) -> str:
        return "\n".join(s.text for s in self.segments if s.kind in kinds)


Detector = Callable[[Context], list[Evidence]]


# ── Helpers ──────────────────────────────────────────────────────────────────
def lines_matching(pattern: re.Pattern, text: str) -> list[int]:
    return [i + 1 for i, ln in enumerate(text.splitlines()) if pattern.search(ln)]


def line_of(text: str, idx: int) -> int:
    return text[:idx].count("\n") + 1


def any_match(pattern: re.Pattern, text: str) -> bool:
    return bool(pattern.search(text))
