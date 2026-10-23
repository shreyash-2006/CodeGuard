"""
detectors/js_pack.py — JavaScript/Node-specific execution and exfiltration.
"""
from __future__ import annotations

import re

from codeguard.detectors.base import Context, Evidence, lines_matching

_CHILD_PROCESS = re.compile(
    r"(child_process|require\(['\"]child_process['\"]\))[^\n]{0,80}(exec|execSync|spawn|spawnSync|fork)\s*\(",
    re.IGNORECASE,
)
_DYNAMIC_EVAL = re.compile(r"(new\s+Function\s*\(|\beval\s*\(|Function\s*\(\s*['\"]return)", re.IGNORECASE)
_ENV_EXFIL = re.compile(
    r"(process\.env[\s\S]{0,120}(fetch|axios|http\.request|https\.request|XMLHttpRequest|sendBeacon))"
    r"|((fetch|axios|sendBeacon)[\s\S]{0,120}process\.env)",
    re.IGNORECASE,
)
_COOKIE_EXFIL = re.compile(
    r"document\.cookie[\s\S]{0,120}(fetch|XMLHttpRequest|sendBeacon|Image\(\)\.src|axios)"
    r"|((fetch|sendBeacon)[\s\S]{0,120}document\.cookie)",
    re.IGNORECASE,
)
_UNSAFE_DESERIALIZE = re.compile(r"(node-serialize|serialize\.unserialize\s*\(|vm\.runInNewContext\s*\()", re.IGNORECASE)


def detect_js_pack(ctx: Context) -> list[Evidence]:
    if ctx.language not in ("javascript", "unknown"):
        return []
    code = ctx.code
    results: list[Evidence] = []

    if _CHILD_PROCESS.search(code):
        results.append(Evidence("destructive_command", 0.85, lines_matching(_CHILD_PROCESS, code),
                                "Node child_process execution (T1059.007)",
                                rule_id="JS_CHILD_PROCESS"))
    if _DYNAMIC_EVAL.search(code):
        results.append(Evidence("obfuscated_execution", 0.8, lines_matching(_DYNAMIC_EVAL, code),
                                "Dynamic code evaluation (eval / new Function) (T1059.007)",
                                rule_id="JS_DYNAMIC_EVAL"))
    if _ENV_EXFIL.search(code):
        results.append(Evidence("data_exfiltration", 0.85, lines_matching(_ENV_EXFIL, code),
                                "process.env sent to a network sink (T1048)",
                                rule_id="JS_ENV_EXFIL"))
    if _COOKIE_EXFIL.search(code):
        results.append(Evidence("data_exfiltration", 0.85, lines_matching(_COOKIE_EXFIL, code),
                                "document.cookie sent to a network sink (T1539)",
                                rule_id="JS_COOKIE_EXFIL"))
    if _UNSAFE_DESERIALIZE.search(code):
        results.append(Evidence("obfuscated_execution", 0.85, lines_matching(_UNSAFE_DESERIALIZE, code),
                                "Unsafe JS deserialization / vm escape (T1059.007)",
                                rule_id="JS_UNSAFE_DESERIALIZE"))
    return results
