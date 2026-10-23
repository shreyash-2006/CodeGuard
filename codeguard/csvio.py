"""
csvio.py — read/write CSV for bulk evaluation.

No FastAPI dependency so it can be used by the CLI, the server and tests.

Accepted input columns (case-insensitive, first match wins; a substring match is
used as a fallback):
  code:  code | snippet | text | content | input | source
  id:    id | index | idx | name | key
  gold:  labels | label | categories | category | gold | expected | truth | y | target
  lang:  language | lang

`gold` accepts a category list (separated by ; | or ,) or a plain label
(1/0, true/false, malicious/benign, block/allow, unsafe/safe).

Rows with quoted, multi-line code cells are handled by the stdlib csv module.
"""
from __future__ import annotations

import csv
import io
import re

from codeguard.schema import VALID_CATEGORIES

_CODE_COLS = ("code", "snippet", "text", "content", "input", "source")
_ID_COLS = ("id", "index", "idx", "name", "key")
_GOLD_COLS = ("labels", "label", "categories", "category", "gold", "expected", "truth", "y", "target")
_LANG_COLS = ("language", "lang")

_MALICIOUS = {"1", "true", "yes", "y", "malicious", "block", "blocked", "unsafe", "bad", "positive"}
_BENIGN = {"0", "false", "no", "n", "benign", "allow", "allowed", "safe", "good", "negative"}


def _pick(header_map: dict[str, str], names: tuple[str, ...]) -> str | None:
    for n in names:
        if n in header_map:
            return header_map[n]
    for n in names:
        for key, original in header_map.items():
            if n in key:
                return original
    return None


def parse_gold(cell) -> tuple[bool | None, list[str]]:
    """Return (gold_malicious, gold_categories)."""
    if cell is None:
        return None, []
    s = str(cell).strip()
    if not s:
        return None, []
    low = s.lower()
    if low in _MALICIOUS:
        return True, []
    if low in _BENIGN:
        return False, []
    cats = sorted({p.strip() for p in re.split(r"[;,|]", s) if p.strip() in VALID_CATEGORIES})
    if cats:
        return True, cats
    return None, []


def parse_csv(text: str) -> list[dict]:
    """Parse CSV text into [{id, code, language, gold_malicious, gold_categories}]."""
    if not text or not text.strip():
        return []
    text = text.lstrip("\ufeff")

    reader = csv.DictReader(io.StringIO(text))
    fields = [f for f in (reader.fieldnames or []) if f is not None]
    header_map = {str(f).strip().lower(): f for f in fields}
    code_col = _pick(header_map, _CODE_COLS)

    # ── headerless fallback: first cell of each row is the code ───────────────
    if code_col is None:
        items: list[dict] = []
        for i, row in enumerate(csv.reader(io.StringIO(text))):
            if not row or not "".join(row).strip():
                continue
            items.append({
                "id": i,
                "code": row[0],
                "language": (row[1] if len(row) > 1 else "") or "",
                "gold_malicious": None,
                "gold_categories": [],
            })
        return items

    id_col = _pick(header_map, _ID_COLS)
    gold_col = _pick(header_map, _GOLD_COLS)
    lang_col = _pick(header_map, _LANG_COLS)

    items = []
    for i, row in enumerate(reader):
        code = row.get(code_col) or ""
        raw_id = row.get(id_col) if id_col else None
        item_id = raw_id if raw_id not in (None, "") else i
        lang = (row.get(lang_col) if lang_col else "") or ""
        gold_mal, gold_cats = parse_gold(row.get(gold_col) if gold_col else None)
        items.append({
            "id": item_id,
            "code": code,
            "language": lang,
            "gold_malicious": gold_mal,
            "gold_categories": gold_cats,
        })
    return items


_RESULT_COLUMNS = [
    "id", "verdict", "risk_score", "categories", "code_language",
    "reason", "vulnerable_lines", "gold_malicious", "gold_categories", "correct",
]


def results_to_csv(results: list[dict]) -> str:
    """Serialise result dicts back to CSV (for download / reporting)."""
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(_RESULT_COLUMNS)
    for r in results:
        writer.writerow([
            r.get("id", ""),
            r.get("verdict", ""),
            r.get("risk_score", ""),
            ";".join(r.get("categories", []) or []),
            r.get("code_language", ""),
            r.get("reason", ""),
            ";".join(str(x) for x in (r.get("vulnerable_lines", []) or [])),
            "" if r.get("gold_malicious") is None else int(bool(r.get("gold_malicious"))),
            ";".join(r.get("gold_categories", []) or []),
            "" if r.get("correct") is None else int(bool(r.get("correct"))),
        ])
    return buf.getvalue()
