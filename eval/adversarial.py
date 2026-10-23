"""
eval/adversarial.py — robustness under mutation.

Applies benign-preserving mutation operators to malicious snippets that the
engine correctly blocks, and reports the survival rate (fraction that STILL
block after mutation). Target: ≥ 90%.

Mutators only change formatting / identifiers / comments / wrapping — they do
not remove the malicious intent.

Run:
    python eval/adversarial.py
"""
from __future__ import annotations

import json
import random
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard.engine import analyze
from codeguard.ml_model import ensure_model_ready
from codeguard.schema import VALID_CATEGORIES

_ROOT = Path(__file__).parent.parent
_DEV = _ROOT / "codeguard_dev.jsonl"

_RNG = random.Random(2026)


# ── Mutators (formatting-preserving) ─────────────────────────────────────────
def m_pad_comments(code: str) -> str:
    pad = "# " + "lorem ipsum dolor sit amet " * _RNG.randint(1, 3) + "\n"
    return pad + code


def m_extra_blank_lines(code: str) -> str:
    return "\n".join(line + ("\n" if _RNG.random() < 0.3 else "") for line in code.split("\n"))


def m_rename_vars(code: str) -> str:
    for name in ["payload", "data", "path", "cmd", "result", "tmp", "value"]:
        if name in code:
            code = re.sub(rf"\b{name}\b", f"{name}_x", code)
    return code


def m_wrap_function(code: str) -> str:
    indented = "\n".join("    " + ln for ln in code.split("\n"))
    return f"def _mutated():\n{indented}\n"


def m_trailing_comment(code: str) -> str:
    lines = code.split("\n")
    return "\n".join(ln + ("  # note" if _RNG.random() < 0.4 else "") for ln in lines)


def m_whitespace(code: str) -> str:
    return code.replace("  ", " ").replace(" ,", ",")


MUTATORS = [m_pad_comments, m_extra_blank_lines, m_rename_vars,
            m_wrap_function, m_trailing_comment, m_whitespace]


def load_malicious() -> list[dict]:
    items = []
    if not _DEV.exists():
        return items
    for line in _DEV.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("label", 0) == 1:
            items.append(obj)
    return items


def main() -> int:
    model = ensure_model_ready(dev_path=str(_DEV))
    items = load_malicious()
    if not items:
        print("No malicious dev snippets found; nothing to mutate.")
        return 0

    survived = 0
    total = 0
    per_cat_total: dict[str, int] = defaultdict(int)
    per_cat_survived: dict[str, int] = defaultdict(int)

    for obj in items:
        base = analyze(obj["code"], model=model)
        if base["verdict"] != "block":
            continue  # only mutate correctly-blocked positives
        cats = [c for c in str(obj.get("category", "")).split(",") if c in VALID_CATEGORIES]

        for mut in MUTATORS:
            mutated = mut(obj["code"])
            total += 1
            result = analyze(mutated, model=model)
            for c in cats:
                per_cat_total[c] += 1
            if result["verdict"] == "block":
                survived += 1
                for c in cats:
                    per_cat_survived[c] += 1

    rate = (survived / total) if total else 1.0
    print("=" * 56)
    print("  CODEGUARD ADVERSARIAL ROBUSTNESS")
    print("=" * 56)
    print(f"  mutations evaluated : {total}")
    print(f"  still blocked       : {survived}")
    print(f"  survival rate       : {rate:.3f}   (target ≥ 0.90)")
    print("\n  per-category survival:")
    for cat in sorted(per_cat_total):
        r = per_cat_survived[cat] / per_cat_total[cat] if per_cat_total[cat] else 0.0
        print(f"    {cat:<30s} {r:.3f}  ({per_cat_survived[cat]}/{per_cat_total[cat]})")
    print("=" * 56)

    ok = rate >= 0.90
    print("  RESULT:", "PASS" if ok else "FAIL (survival < 90%)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
