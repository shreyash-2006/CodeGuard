"""
explain.py — build the human-readable `reason` and `vulnerable_lines`.

Separated from fusion so the decision (scores/thresholds) and the explanation
are independently testable.
"""
from __future__ import annotations

import re

from codeguard import config
from codeguard.detectors.base import Evidence

_MASK_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA****"),
    (re.compile(r"xox[bpoa]-[A-Za-z0-9-]{8,}"), "xox****"),
    (re.compile(r"(aws_secret_access_key\s*=\s*['\"])[^'\"]+(['\"])", re.IGNORECASE), r"\1****\2"),
    (re.compile(r"(password\s*=\s*['\"])[^'\"]+(['\"])", re.IGNORECASE), r"\1****\2"),
]


def mask(text: str) -> str:
    """Never emit raw credentials in a reason string."""
    for pattern, repl in _MASK_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def collect_vulnerable_lines(
    evidence: list[Evidence],
    categories,
    max_lines: int = config.MAX_VULNERABLE_LINES,
) -> list[int]:
    """Unique original line numbers of top evidence for the flagged categories."""
    cats = set(categories)
    lines: set[int] = set()
    for ev in sorted(evidence, key=lambda e: (-e.confidence, e.line)):
        if ev.category in cats and ev.confidence > 0.1:
            lines.update(ln for ln in ev.lines if ln > 0)
    return sorted(lines)[:max_lines]


def build_reason(
    categories,
    evidence: list[Evidence],
    risk: float,
    lang: str,
    ml_max: float = 0.0,
    obfuscation: str = "",
) -> str:
    """
    Blocked: <cat> — <desc> (line N); … [Obfuscation detected: base64 → eval.] Risk 0.93.
    Allowed: no malicious patterns detected (checked <lang>, ML score 0.03).
    """
    if categories:
        parts: list[str] = []
        for cat in sorted(categories):
            best = max((e for e in evidence if e.category == cat),
                       key=lambda e: e.confidence, default=None)
            if best is not None and best.reason:
                parts.append(f"{cat} — {best.reason} (line {best.line})")
            else:
                parts.append(cat)
        reason = f"Blocked: {'; '.join(parts)}."
        if obfuscation:
            reason += f" [Obfuscation detected: {obfuscation}.]"
        reason += f" Risk {risk:.2f}."
    else:
        reason = f"Allowed: no malicious patterns detected (checked {lang}, ML score {ml_max:.2f})."
    return mask(reason)[:400]
