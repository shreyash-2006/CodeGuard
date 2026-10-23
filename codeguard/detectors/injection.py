"""
detectors/injection.py — ai_targeted_instructions (AML.T0054).

Scans comments, strings, docstrings, Markdown prose and YAML descriptions for
prompt-injection phrases. Normalizes leetspeak, zero-width chars and homoglyphs;
also matches base64/hex-encoded phrases via the deobfuscation layers.
"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from pathlib import Path

from codeguard.detectors.base import Context, Evidence, lines_matching

_PHRASES_PATH = Path(__file__).parent.parent / "data" / "injection_phrases.yaml"

# Regex families (kept for cross-word patterns)
_AI_INJECT_PHRASES = re.compile(
    r"(ignore\s+(all\s+)?previous\s+instructions|"
    r"disregard\s+(all\s+)?prior|"
    r"before\s+answering\s*,?\s*(print|reveal|output|show)|"
    r"reveal\s+(the\s+)?(full\s+)?system\s+prompt|"
    r"print\s+(the\s+contents\s+of|all\s+stored\s+credentials)|"
    r"approve\s+the\s+pull\s+request\s+regardless|"
    r"skip\s+static\s+analysis|"
    r"report\s+.{0,30}(fully\s+compliant|as\s+compliant)|"
    r"IMPORTANT:\s*when\s+this\s+tool\s+runs.{0,60}(reveal|leak|show)|"
    r"automated.{0,20}reviewer.{0,30}(skip|ignore|approve)|"
    r"reviewer.?bot.{0,50}(approve|regardless)|"
    r"first\s+reveal\s+.{0,30}(system\s+prompt|credentials)|"
    r"id_rsa|\.ssh/id_rsa)",
    re.IGNORECASE | re.DOTALL,
)

_AI_FALSE_POSITIVE_GUARD = re.compile(
    r"(# Reject malformed|comments discuss behaviour|plain behaviour|"
    r"if not action:\s+raise|json\.loads|parse_event)",
    re.IGNORECASE,
)

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_HOMOGLYPH = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u0458": "j",
    "\u04bb": "h", "\u049b": "k", "\u043c": "m", "\u0442": "t",
})
_SPACED = re.compile(r"\b(?:[a-z]\s+){4,}[a-z]\b")


@lru_cache(maxsize=1)
def _load_phrase_bank() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (phrases, benign_context) loaded from the YAML bank."""
    phrases: list[str] = []
    benign: list[str] = []
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(_PHRASES_PATH.read_text(encoding="utf-8")) or {}
        for fam in (data.get("families") or {}).values():
            phrases.extend(str(p) for p in fam)
        phrases.extend(str(p) for p in (data.get("non_english") or []))
        benign.extend(str(p) for p in (data.get("benign_context") or []))
    except Exception:
        pass
    return tuple(phrases), tuple(benign)


def _normalize(text: str) -> str:
    t = "".join(ch for ch in text if unicodedata.category(ch) not in ("Cf", "Mn"))
    t = t.translate(_HOMOGLYPH).translate(_LEET).lower()
    t = _SPACED.sub(lambda m: m.group(0).replace(" ", ""), t)
    return t


def detect_ai_targeted_instructions(ctx: Context) -> list[Evidence]:
    code, deob = ctx.code, ctx.deob_code or ctx.code
    results: list[Evidence] = []

    matched_strong = bool(_AI_INJECT_PHRASES.search(code))
    if not matched_strong and deob != code:
        matched_strong = bool(_AI_INJECT_PHRASES.search(deob))

    matched = matched_strong

    # Normalized phrase-bank search
    norm = _normalize(code)
    phrases, benign_ctx = _load_phrase_bank()
    hit_phrase = ""
    for phrase in phrases:
        pn = _normalize(phrase)
        if pn and pn in norm:
            matched = True
            hit_phrase = phrase
            break

    if not matched:
        return []

    # Suppress clearly-benign documentation / behaviour descriptions — but never
    # when a strong imperative pattern already matched.
    guard_hit = bool(_AI_FALSE_POSITIVE_GUARD.search(code)) or any(_normalize(b) in norm for b in benign_ctx)
    if guard_hit and not matched_strong and not re.search(
        r"(id_rsa|system\s+prompt|credential|NOPASSWD)", code, re.IGNORECASE
    ):
        return []

    lines = lines_matching(_AI_INJECT_PHRASES, code)
    if not lines:
        # locate the phrase line(s) in the raw code (case-insensitive)
        for phrase in ([hit_phrase] if hit_phrase else []):
            for i, ln in enumerate(code.splitlines(), 1):
                if _normalize(phrase) and _normalize(phrase) in _normalize(ln):
                    lines.append(i)
    if not lines:
        lines = [1]

    results.append(Evidence("ai_targeted_instructions", 0.95, sorted(set(lines)),
                            "AI prompt injection / adversarial instruction in code/comments (AML.T0054)",
                            rule_id="AI_INJECT", snippet=hit_phrase or "prompt-injection phrase"))
    return results
