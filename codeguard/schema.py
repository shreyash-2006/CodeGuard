"""
schema.py — CodeGuard schema constants and the ONLY place that builds the response dict.
All verdicts must pass through finalize_response().
"""
from __future__ import annotations

from typing import Any

from codeguard import config

# ── Allowed category labels ──────────────────────────────────────────────────
VALID_CATEGORIES = {
    "secret_access",
    "data_exfiltration",
    "destructive_command",
    "obfuscated_execution",
    "persistence_or_privesc",
    "resource_exhaustion",
    "ssrf_network_exfil",
    "ai_targeted_instructions",
    "dependency_risk",
}

VALID_LANGUAGES = {"python", "bash", "javascript", "sql", "yaml", "markdown", "unknown"}

# Spec vocabulary aliases
CATEGORIES = VALID_CATEGORIES
ALLOWED_LANGUAGES = VALID_LANGUAGES

_RISK_DP = 4  # decimal places for risk_score


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def finalize_response(
    *,
    verdict: str,
    risk_score: float,
    categories: list[str],
    code_language: str,
    reason: str = "",
    vulnerable_lines: list[int] | None = None,
    total_lines: int | None = None,
) -> dict[str, Any]:
    """
    Build and enforce the response schema. This is the ONLY place schema invariants live.

    Invariants:
      - verdict ∈ {"block", "allow"}
      - verdict=="block" ⟺ categories non-empty ⟺ risk_score ≥ 0.5
      - categories: sorted, de-duped, all from VALID_CATEGORIES
      - risk_score: float clamped [0,1], rounded to 4 dp
      - code_language: from VALID_LANGUAGES (default "unknown")
      - reason: str (truncated to 400 chars)
      - vulnerable_lines: sorted, unique, 1-based ints, each ≤ total_lines, cap 20
      - allow ⇒ categories == [] and vulnerable_lines == []
    """
    if vulnerable_lines is None:
        vulnerable_lines = []

    # Clean categories
    clean_cats = sorted(
        {c for c in categories if c in VALID_CATEGORIES}
    )

    # Clean language
    lang = code_language if code_language in VALID_LANGUAGES else "unknown"

    # Clean + validate vulnerable lines
    clean_lines: set[int] = set()
    for ln in vulnerable_lines:
        try:
            n = int(ln)
        except (TypeError, ValueError):
            continue
        if n < 1:
            continue
        if total_lines is not None and n > total_lines:
            continue
        clean_lines.add(n)
    vuln = sorted(clean_lines)[: config.MAX_VULNERABLE_LINES]

    # Enforce tri-state consistency
    has_cats = bool(clean_cats)
    try:
        rs = round(_clamp(float(risk_score)), _RISK_DP)
    except (TypeError, ValueError):
        rs = 0.0

    if has_cats:
        v = "block"
        if rs < config.BLOCK_THRESHOLD:
            rs = config.BLOCK_THRESHOLD
    else:
        v = "allow"
        if rs >= config.BLOCK_THRESHOLD:
            rs = round(config.BLOCK_THRESHOLD - 0.0001, _RISK_DP)
        vuln = []

    reason = str(reason)[:400] if reason else ("Blocked by CodeGuard." if v == "block" else "Allowed: no malicious patterns detected.")

    return {
        "verdict": v,
        "risk_score": rs,
        "categories": clean_cats,
        "code_language": lang,
        "reason": reason,
        "vulnerable_lines": vuln,
    }


def fail_closed(reason: str = "Analysis failed; failing closed.") -> dict[str, Any]:
    """A guaranteed-valid BLOCK response for error/timeout paths. Never raises."""
    try:
        return finalize_response(
            verdict="block",
            risk_score=config.BLOCK_THRESHOLD,
            categories=["destructive_command"],
            code_language="unknown",
            reason=reason,
            vulnerable_lines=[],
        )
    except Exception:
        return {
            "verdict": "block",
            "risk_score": 0.5,
            "categories": ["destructive_command"],
            "code_language": "unknown",
            "reason": reason[:400],
            "vulnerable_lines": [],
        }


def empty_input() -> dict[str, Any]:
    """A guaranteed-valid ALLOW response for empty/malformed input. Never raises."""
    try:
        return finalize_response(
            verdict="allow",
            risk_score=0.0,
            categories=[],
            code_language="unknown",
            reason="Empty input",
            vulnerable_lines=[],
        )
    except Exception:
        return {
            "verdict": "allow",
            "risk_score": 0.0,
            "categories": [],
            "code_language": "unknown",
            "reason": "Empty input",
            "vulnerable_lines": [],
        }


def is_valid_response(obj: Any) -> bool:
    """Validate a response against every §2.3 invariant. Used by tests/selfcheck."""
    if not isinstance(obj, dict):
        return False
    required = {"verdict", "risk_score", "categories", "code_language"}
    if not required.issubset(obj.keys()):
        return False

    verdict = obj.get("verdict")
    if verdict not in ("block", "allow"):
        return False

    rs = obj.get("risk_score")
    if not isinstance(rs, (int, float)) or isinstance(rs, bool):
        return False
    if not (0.0 <= float(rs) <= 1.0):
        return False
    if round(float(rs), _RISK_DP) != float(rs):
        return False

    cats = obj.get("categories")
    if not isinstance(cats, list) or any(c not in VALID_CATEGORIES for c in cats):
        return False
    if cats != sorted(set(cats)):
        return False

    lang = obj.get("code_language")
    if not isinstance(lang, str):
        return False

    vuln = obj.get("vulnerable_lines", [])
    if not isinstance(vuln, list):
        return False
    if any((not isinstance(x, int)) or isinstance(x, bool) or x < 1 for x in vuln):
        return False
    if vuln != sorted(set(vuln)):
        return False
    if len(vuln) > config.MAX_VULNERABLE_LINES:
        return False

    # Tri-state consistency
    if verdict == "block":
        if not cats or float(rs) < config.BLOCK_THRESHOLD:
            return False
    else:
        if cats or float(rs) >= config.BLOCK_THRESHOLD or vuln:
            return False

    return True
