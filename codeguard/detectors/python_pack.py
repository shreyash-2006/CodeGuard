"""
detectors/python_pack.py — Python-specific sandbox-escape / dynamic-execution.
"""
from __future__ import annotations

import re

from codeguard.detectors.base import Context, Evidence, lines_matching

_GETATTR_COMPUTED = re.compile(
    r"""getattr\s*\(\s*[^,]+,\s*(?:['"][^'"]*['"]\s*\+|['"][^'"]*['"]\s*%|f['"]|chr\(|['"]\w+['"]\s*\+)""",
    re.IGNORECASE,
)
_DUNDER_ESCAPE = re.compile(
    r"(__globals__|__subclasses__|__builtins__|__mro__|__class__\.__base__|"
    r"__import__\s*\(\s*['\"]os['\"]\s*\)\s*\.\s*__dict__)",
    re.IGNORECASE,
)
_COMPILE_DYN = re.compile(r"compile\s*\(\s*[^,)]+,\s*[^,)]+,\s*['\"](exec|eval)['\"]", re.IGNORECASE)


def detect_python_pack(ctx: Context) -> list[Evidence]:
    if ctx.language not in ("python", "unknown"):
        return []
    code = ctx.code
    results: list[Evidence] = []

    if _GETATTR_COMPUTED.search(code):
        results.append(Evidence("obfuscated_execution", 0.9, lines_matching(_GETATTR_COMPUTED, code),
                                "getattr with a computed attribute name (dynamic dispatch) (T1059.006)",
                                rule_id="PY_GETATTR_COMPUTED"))
    if _DUNDER_ESCAPE.search(code):
        results.append(Evidence("obfuscated_execution", 0.9, lines_matching(_DUNDER_ESCAPE, code),
                                "Python sandbox-escape attribute access (T1059.006)",
                                rule_id="PY_DUNDER_ESCAPE"))
    if _COMPILE_DYN.search(code):
        results.append(Evidence("obfuscated_execution", 0.9, lines_matching(_COMPILE_DYN, code),
                                "compile() with exec/eval mode (T1059.006)",
                                rule_id="PY_COMPILE_DYN"))
    return results
