"""
metrics.py — verdict- and category-level metrics for a list of results.

Each result should provide:
  verdict          : "block" | "allow"
  gold_malicious   : bool | None      (None → no gold label)
  categories       : list[str]        (predicted)
  gold_categories  : list[str]        (optional, for per-category metrics)
"""
from __future__ import annotations

from codeguard.schema import VALID_CATEGORIES


def summarize(results: list[dict]) -> dict:
    total = len(results)
    blocked = sum(1 for r in results if r.get("verdict") == "block")
    allowed = total - blocked

    labeled = [r for r in results if r.get("gold_malicious") is not None]
    summary: dict = {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "labeled": len(labeled),
    }

    if not labeled:
        return summary

    tp = fp = tn = fn = 0
    for r in labeled:
        gold_mal = bool(r["gold_malicious"])
        pred_blk = r.get("verdict") == "block"
        if gold_mal and pred_blk:
            tp += 1
        elif gold_mal and not pred_blk:
            fn += 1
        elif not gold_mal and pred_blk:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(labeled)

    summary["confusion"] = {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
    summary["verdict"] = {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "accuracy": round(accuracy, 4),
    }

    # Per-category (only for malicious rows that carry category labels)
    per_cat: dict[str, dict] = {}
    for c in VALID_CATEGORIES:
        per_cat[c] = {"tp": 0, "fp": 0, "fn": 0}
    for r in labeled:
        gold_cats = set(r.get("gold_categories") or [])
        if not gold_cats:
            continue
        pred_cats = set(r.get("categories") or [])
        for c in gold_cats:
            per_cat[c]["tp" if c in pred_cats else "fn"] += 1
        for c in pred_cats - gold_cats:
            per_cat[c]["fp"] += 1

    for c, d in per_cat.items():
        p = d["tp"] / (d["tp"] + d["fp"]) if (d["tp"] + d["fp"]) else 0.0
        rc = d["tp"] / (d["tp"] + d["fn"]) if (d["tp"] + d["fn"]) else 0.0
        f = 2 * p * rc / (p + rc) if (p + rc) else 0.0
        d.update({"precision": round(p, 3), "recall": round(rc, 3), "f1": round(f, 3)})
    summary["per_category"] = per_cat

    return summary
