"""
fusion.py — Combine rule evidence and ML probabilities into a final verdict.

rule_p[c] = 1 - Π(1 - conf_i)                     (noisy-OR over that category)
p[c]      = 1 - (1 - rule_p[c]) * (1 - w_ml*ml_p[c]) * dampers[c]
hard_block / conf ≥ 0.97 ⇒ p[c] = max(p[c], 0.97)
verdict   = block if any p[c] ≥ T[c] else allow
"""
from __future__ import annotations

import json
from pathlib import Path

from codeguard import config
from codeguard.explain import build_reason, collect_vulnerable_lines
from codeguard.rules import Evidence
from codeguard.schema import VALID_CATEGORIES

# ── Per-category thresholds (fallback; overridden by data/thresholds.json) ────
_DEFAULT_THRESHOLDS: dict[str, float] = {
    "secret_access": 0.45,
    "data_exfiltration": 0.45,
    "destructive_command": 0.40,
    "obfuscated_execution": 0.45,
    "persistence_or_privesc": 0.40,
    "resource_exhaustion": 0.45,
    "ssrf_network_exfil": 0.45,
    "dependency_risk": 0.45,
    "ai_targeted_instructions": 0.50,
}

_THRESHOLDS_PATH = Path(__file__).parent / "data" / "thresholds.json"
_THRESHOLDS_CACHE: dict[str, float] | None = None

# Secret masking now lives in explain.py.

def load_thresholds() -> dict[str, float]:
    """Load per-category thresholds from data/thresholds.json (cached)."""
    global _THRESHOLDS_CACHE
    if _THRESHOLDS_CACHE is not None:
        return _THRESHOLDS_CACHE
    thresholds = dict(_DEFAULT_THRESHOLDS)
    try:
        if _THRESHOLDS_PATH.exists():
            with open(_THRESHOLDS_PATH, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                for key, val in data.items():
                    if key in VALID_CATEGORIES:
                        try:
                            thresholds[key] = float(val)
                        except (TypeError, ValueError):
                            pass
    except Exception:
        pass
    _THRESHOLDS_CACHE = thresholds
    return thresholds


def thresholds_used() -> dict[str, float]:
    return dict(load_thresholds())


def fuse(
    evidence: list[Evidence],
    ml_proba: dict[str, float],
    dampers: dict[str, float],
) -> dict[str, float]:
    """Compute fused probability per category. Returns dict[category → p_fused]."""
    fused: dict[str, float] = {}

    for cat in VALID_CATEGORIES:
        # ── 1. Noisy-OR over this category's rule evidence ────────────────────
        prod = 1.0
        for ev in evidence:
            if ev.category != cat:
                continue
            c = ev.confidence
            if c <= 0.0:
                continue
            c = min(1.0, max(0.0, c))
            prod *= (1.0 - c)
        rule_p = 1.0 - prod

        # ── 2. Hard override ─────────────────────────────────────────────────
        hard = rule_p >= config.HARD_OVERRIDE or any(
            ev.category == cat and getattr(ev, "hard_block", False) and ev.confidence >= config.HARD_OVERRIDE
            for ev in evidence
        )
        if hard:
            fused[cat] = max(rule_p, config.HARD_OVERRIDE)
            continue

        # ── 3. Combine with ML + dampers ─────────────────────────────────────
        ml_p = ml_proba.get(cat, 0.0) if ml_proba else 0.0
        p = 1.0 - (1.0 - rule_p) * (1.0 - config.W_ML * ml_p)
        p *= dampers.get(cat, 1.0)
        fused[cat] = min(1.0, max(0.0, p))

    return fused


def decide(
    fused: dict[str, float],
    evidence: list[Evidence],
    lang: str = "unknown",
    ml_max: float = 0.0,
    obfuscation: str = "",
) -> tuple[list[str], float, list[int], str]:
    """
    Apply thresholds to fused probabilities.
    Returns (categories, risk_score, vulnerable_lines, reason).
    """
    thresholds = load_thresholds()

    triggered: list[str] = sorted(
        cat for cat, p in fused.items()
        if p >= thresholds.get(cat, config.BLOCK_THRESHOLD)
    )

    vuln_lines = collect_vulnerable_lines(evidence, triggered)

    # ── risk_score ───────────────────────────────────────────────────────────
    if triggered:
        prod = 1.0
        for cat in triggered:
            prod *= (1.0 - fused.get(cat, 0.0))
        risk = 1.0 - prod
        risk = max(risk, config.BLOCK_THRESHOLD)
    else:
        risk = min(max(fused.values(), default=0.0), config.BLOCK_THRESHOLD - 0.0001)

    reason = build_reason(triggered, evidence, risk, lang, ml_max, obfuscation)

    return triggered, risk, sorted(vuln_lines), reason
