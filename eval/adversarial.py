"""
eval/adversarial.py — robustness under mutation, with honest verdict metrics.

Applies benign-preserving mutation operators to:
  * malicious snippets that the engine correctly blocks  -> survival / recall
  * benign snippets                                      -> false positives
then reports the combined verdict-level precision / recall / F1 / FPR.

Mutators only change formatting / identifiers / comments / wrapping — they do not
remove the malicious intent.

Run:
    python eval/adversarial.py
"""
from __future__ import annotations

import json
import random
import re
import sys
import time
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


def _load(label: int) -> list[dict]:
    items = []
    if not _DEV.exists():
        return items
    for line in _DEV.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("label", 0) == label:
            items.append(obj)
    return items


def main() -> int:
    model = ensure_model_ready(dev_path=str(_DEV))
    malicious = _load(1)
    benign = _load(0)
    if not malicious:
        print("No malicious dev snippets found; nothing to mutate.")
        return 0

    # ── malicious suite: survival (recall) + per-category ────────────────────
    survived = 0
    mal_total = 0
    lat_mal: list[float] = []
    per_cat_total: dict[str, int] = defaultdict(int)
    per_cat_survived: dict[str, int] = defaultdict(int)

    for obj in malicious:
        if analyze(obj["code"], model=model)["verdict"] != "block":
            continue  # only mutate correctly-blocked positives
        cats = [c for c in str(obj.get("category", "")).split(",") if c in VALID_CATEGORIES]
        for mut in MUTATORS:
            mutated = mut(obj["code"])
            mal_total += 1
            t0 = time.perf_counter()
            result = analyze(mutated, model=model)
            lat_mal.append((time.perf_counter() - t0) * 1000.0)
            for c in cats:
                per_cat_total[c] += 1
            if result["verdict"] == "block":
                survived += 1
                for c in cats:
                    per_cat_survived[c] += 1

    # ── benign suite: false positives under mutation ─────────────────────────
    ben_total = 0
    ben_blocked = 0
    lat_ben: list[float] = []
    for obj in benign:
        for mut in MUTATORS:
            mutated = mut(obj["code"])
            ben_total += 1
            t0 = time.perf_counter()
            result = analyze(mutated, model=model)
            lat_ben.append((time.perf_counter() - t0) * 1000.0)
            if result["verdict"] == "block":
                ben_blocked += 1

    # ── combined verdict metrics (mutated suite = positives + negatives) ─────
    tp, fn = survived, mal_total - survived
    fp, tn = ben_blocked, ben_total - ben_blocked
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    rate = recall  # survival rate == recall on the malicious suite

    def p95(vals: list[float]) -> float:
        if not vals:
            return 0.0
        s = sorted(vals)
        return s[min(len(s) - 1, int(len(s) * 0.95))]

    print("=" * 60)
    print("  CODEGUARD ADVERSARIAL ROBUSTNESS")
    print("=" * 60)
    print(f"  malicious mutations : {mal_total}   still blocked: {survived}")
    print(f"  benign mutations    : {ben_total}   blocked (FP): {ben_blocked}")
    print(f"  mutation survival   : {rate:.3f}   (target ≥ 0.90)")
    print()
    print(f"  combined verdict metrics : TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"    Precision : {precision:.4f}")
    print(f"    Recall    : {recall:.4f}")
    print(f"    F1        : {f1:.4f}")
    print(f"    FPR       : {fpr:.4f}")
    print(f"    p95 latency (mal / benign): {p95(lat_mal):.1f} ms / {p95(lat_ben):.1f} ms")
    print("\n  per-category survival:")
    for cat in sorted(per_cat_total):
        r = per_cat_survived[cat] / per_cat_total[cat] if per_cat_total[cat] else 0.0
        print(f"    {cat:<30s} {r:.3f}  ({per_cat_survived[cat]}/{per_cat_total[cat]})")
    print("=" * 60)

    ok = rate >= 0.90
    print("  RESULT:", "PASS" if ok else "FAIL (survival < 90%)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
