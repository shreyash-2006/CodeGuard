"""
pipeline/langid.py — Heuristic language identification.

Returns python|bash|javascript|sql|yaml|markdown|unknown, plus a confidence
in [0,1] from the winning score share.
"""
from __future__ import annotations

import re

# ── Per-language signal sets ─────────────────────────────────────────────────

_PY_STRONG = re.compile(
    r"^\s*(def |class |import |from .+ import|if __name__|@\w+|async def |"
    r"elif |raise |with |lambda |yield )",
    re.MULTILINE,
)
_PY_HINTS = re.compile(r"(print\(|\.format\(|f['\"]|__init__|self\.|:\s*$)", re.MULTILINE)

_BASH_STRONG = re.compile(
    r"(^\s*#!/.*\b(bash|sh)\b|set -[eux]|^\s*\w{1,64}\(\)\s*\{|"
    r"\$\{[A-Z_]+\}|\btee\b|\bsudo\b|\bchmod\b|\bapt-get\b)",
    re.MULTILINE,
)
_BASH_HINTS = re.compile(r"(\|\||\&\&|>>|2>&1|\\$\(|echo )", re.MULTILINE)
_BASH_CMD_HINTS = re.compile(
    r"(^\s*(?:sudo\s+)?(rm\s+-|dd\s+if=|mkfs|wipefs|shred|crontab|iptables|"
    r"systemctl|useradd|usermod|shutdown|reboot|kill\s+-9)\b)",
    re.MULTILINE,
)

_JS_STRONG = re.compile(
    r"(^\s*(const|let|var|function|async function|class|module\.exports|require\(|import .+ from)"
    r"|(=>)|\bconsole\.(log|error)\b|\bawait\b)",
    re.MULTILINE,
)

_SQL_STRONG = re.compile(
    r"^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|BEGIN|COMMIT|ROLLBACK|PROCEDURE|DECLARE)\b",
    re.MULTILINE | re.IGNORECASE,
)

_YAML_STRONG = re.compile(r"^\s*\w[\w -]{0,80}:\s*($|[^:])", re.MULTILINE)
_YAML_LIST = re.compile(r"^\s+-\s+\S", re.MULTILINE)
_YAML_GH_ACTIONS = re.compile(
    r"(^on:\s*$|^jobs:\s*$|^steps:\s*$|runs-on:|^\s+uses:\s+|^\s+run:\s+"
    r"|^\s+branches:\s*\[|^name:\s+\S)",
    re.MULTILINE,
)

_MD_STRONG = re.compile(r"(^#{1,6} .{0,200}|^\*{3,}|^---\s*$|^\[.{0,200}\]\(.{0,200}\))", re.MULTILINE)


def detect_language_scored(code: str) -> tuple[str, float]:
    """Return (language, confidence)."""
    if not code or not code.strip():
        return "unknown", 0.0

    scores: dict[str, int] = {
        "python": 0, "bash": 0, "javascript": 0,
        "sql": 0, "yaml": 0, "markdown": 0,
    }

    scores["python"] += len(_PY_STRONG.findall(code)) * 3
    scores["python"] += len(_PY_HINTS.findall(code))
    if "import " in code and "def " in code:
        scores["python"] += 2

    scores["bash"] += len(_BASH_STRONG.findall(code)) * 3
    scores["bash"] += len(_BASH_HINTS.findall(code))
    scores["bash"] += len(_BASH_CMD_HINTS.findall(code)) * 2

    scores["javascript"] += len(_JS_STRONG.findall(code)) * 3

    scores["sql"] += len(_SQL_STRONG.findall(code)) * 4
    if "WHERE" in code.upper() or "FROM" in code.upper():
        scores["sql"] += 1

    yaml_key_count = len(_YAML_STRONG.findall(code))
    if yaml_key_count > 0:
        scores["yaml"] += yaml_key_count
        if _YAML_LIST.search(code):
            scores["yaml"] += 2
        if _YAML_GH_ACTIONS.search(code):
            scores["yaml"] += 20
            scores["python"] = 0
        elif scores["python"] > 2:
            scores["yaml"] = max(0, scores["yaml"] - 6)

    scores["markdown"] += len(_MD_STRONG.findall(code)) * 2

    best = max(scores, key=lambda k: scores[k])
    if scores[best] == 0:
        return "unknown", 0.0

    total = sum(scores.values())
    confidence = scores[best] / total if total else 0.0
    return best, round(min(1.0, confidence), 4)


def detect_language(code: str) -> str:
    """Return best-guess language string."""
    return detect_language_scored(code)[0]
