"""
pipeline/preprocess.py — normalize an input snippet.

  * strip BOM
  * replace NUL with space (and flag it)
  * size guard: > MAX_INPUT_BYTES → keep head + tail (flag oversized)
  * drop zero-width / bidi format chars
  * normalize line endings (\\r\\n, \\r → \\n)

Returns (normalized_code, meta). meta carries `original_lines` for line mapping.
"""
from __future__ import annotations

import unicodedata
from typing import Any

from codeguard import config


def preprocess(code: str) -> tuple[str, dict[str, Any]]:
    meta: dict[str, Any] = {
        "oversized": False,
        "had_nul": False,
        "had_zero_width": False,
        "had_bidi": False,
    }

    if not isinstance(code, str):
        code = str(code)

    code = code.lstrip("\ufeff")

    if "\x00" in code:
        meta["had_nul"] = True
        code = code.replace("\x00", " ")

    # Size guard: keep head + tail if the payload is too large.
    raw = code.encode("utf-8", errors="replace")
    if len(raw) > config.MAX_INPUT_BYTES or len(code) > config.ANALYSIS_MAX_CHARS:
        meta["oversized"] = True
        head = raw[: config.TRUNCATE_HEAD_BYTES].decode("utf-8", errors="replace")
        tail = raw[-config.TRUNCATE_TAIL_BYTES:].decode("utf-8", errors="replace")
        code = head + "\n# … [truncated] …\n" + tail

    # Detect + remove zero-width / bidi format chars (keep tabs/newlines).
    kept: list[str] = []
    for ch in code:
        if unicodedata.category(ch) == "Cf" and ch not in ("\t", "\n", "\r"):
            meta["had_zero_width"] = True
            if ch in ("\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"):
                meta["had_bidi"] = True
            continue
        kept.append(ch)
    code = "".join(kept)

    # Normalize line endings.
    code = code.replace("\r\n", "\n").replace("\r", "\n")

    # Defensive: cap pathological single-line length (bounds per-line regex cost).
    _MAX_LINE = 20000
    if any(len(line) > _MAX_LINE for line in code.split("\n")):
        code = "\n".join(
            line if len(line) <= _MAX_LINE
            else line[:_MAX_LINE // 2] + "…" + line[-_MAX_LINE // 2:]
            for line in code.split("\n")
        )

    meta["original_lines"] = code.split("\n")
    return code, meta
