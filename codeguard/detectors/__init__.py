"""
detectors — the detector registry and orchestrator.

Every detector is a pure callable `detect(ctx) -> list[Evidence]`; each call is
wrapped in try/except so a single failure can never crash a request.
"""
from __future__ import annotations

from codeguard.detectors.base import Context, Evidence, Detector
from codeguard.detectors.dampers import apply_dampers
from codeguard.detectors.dependency import detect_dependency_risk
from codeguard.detectors.injection import detect_ai_targeted_instructions
from codeguard.detectors.markdown_pack import detect_markdown_pack
from codeguard.detectors.network import detect_ssrf_network_exfil
from codeguard.detectors.resource import detect_resource_exhaustion
from codeguard.detectors.sql_pack import detect_sql_pack
from codeguard.detectors.taint import detect_taint
from codeguard.detectors.universal import (
    detect_data_exfiltration,
    detect_destructive_command,
    detect_obfuscated_execution,
    detect_persistence_or_privesc,
    detect_secret_access,
)
from codeguard.detectors.bash_pack import detect_bash_pack
from codeguard.detectors.js_pack import detect_js_pack
from codeguard.detectors.python_pack import detect_python_pack
from codeguard.detectors.yaml_pack import detect_yaml_pack

# Order matters only for readability; evidence is aggregated per category.
_DETECTORS: list[Detector] = [
    # universal (all languages)
    detect_secret_access,
    detect_data_exfiltration,
    detect_destructive_command,
    detect_obfuscated_execution,
    detect_persistence_or_privesc,
    detect_resource_exhaustion,
    detect_ssrf_network_exfil,
    detect_dependency_risk,
    detect_ai_targeted_instructions,
    # language packs / analyzers
    detect_python_pack,
    detect_bash_pack,
    detect_js_pack,
    detect_sql_pack,
    detect_yaml_pack,
    detect_markdown_pack,
    detect_taint,
]

CATEGORY_DETECTORS = {
    "secret_access": [detect_secret_access],
    "data_exfiltration": [detect_data_exfiltration],
    "destructive_command": [detect_destructive_command],
    "obfuscated_execution": [detect_obfuscated_execution],
    "persistence_or_privesc": [detect_persistence_or_privesc],
    "resource_exhaustion": [detect_resource_exhaustion],
    "ssrf_network_exfil": [detect_ssrf_network_exfil],
    "dependency_risk": [detect_dependency_risk],
    "ai_targeted_instructions": [detect_ai_targeted_instructions],
}


def run_all_detectors(ctx: Context) -> tuple[list[Evidence], dict[str, float]]:
    """Run every detector and return (evidence, dampers)."""
    dampers = apply_dampers(ctx.code)
    all_evidence: list[Evidence] = []

    for detector in _DETECTORS:
        try:
            evidence = detector(ctx) or []
        except Exception:
            continue
        damper = dampers.get("__global__", 1.0)
        for ev in evidence:
            ev.confidence *= dampers.get(ev.category, 1.0) * damper
        all_evidence.extend(evidence)

    return all_evidence, dampers


def run_all_detectors_compat(code: str, deob_code: str = "") -> tuple[list[Evidence], dict[str, float]]:
    """Convenience wrapper for callers that only have raw strings."""
    from codeguard.pipeline.langid import detect_language
    ctx = Context(code=code, deob_code=deob_code or code, language=detect_language(code))
    return run_all_detectors(ctx)


__all__ = [
    "Context",
    "Evidence",
    "Detector",
    "run_all_detectors",
    "run_all_detectors_compat",
    "CATEGORY_DETECTORS",
]
