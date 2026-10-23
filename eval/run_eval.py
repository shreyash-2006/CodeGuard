"""
eval/run_eval.py — Evaluate CodeGuard on the dev sample.
Reports: verdict P/R/F1/FPR, per-category F1, per-language breakdown.
Can run in offline mode (calls engine directly) or via HTTP endpoint.
"""
from __future__ import annotations

import json
import sys
import os
from collections import defaultdict
from pathlib import Path

# Add parent to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard.engine import analyze
from codeguard.ml_model import ensure_model_ready
from codeguard.schema import VALID_CATEGORIES

_DEV_PATH = os.environ.get("CODEGUARD_DEV_PATH", str(Path(__file__).parent.parent / "codeguard_dev.jsonl"))


def load_dev(path: str) -> list[dict]:
    items = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def evaluate(items: list[dict], model) -> dict:
    # Verdict-level metrics
    tp = fp = tn = fn = 0
    # Per-category
    cat_tp: dict[str, int] = defaultdict(int)
    cat_fp: dict[str, int] = defaultdict(int)
    cat_fn: dict[str, int] = defaultdict(int)
    # Per-language
    lang_correct: dict[str, int] = defaultdict(int)
    lang_total: dict[str, int] = defaultdict(int)

    results = []
    for item in items:
        code = item["code"]
        gold_label = item.get("label", 0)
        gold_cat_str = item.get("category", "benign")
        gold_cats = set(
            c.strip() for c in gold_cat_str.split(",")
            if c.strip() in VALID_CATEGORIES
        )
        gold_lang = item.get("language", "unknown")
        item_id = item.get("id", "?")

        pred = analyze(code, model=model)
        pred_verdict = pred["verdict"]  # "block" or "allow"
        pred_cats = set(pred.get("categories", []))
        pred_lang = pred.get("code_language", "unknown")

        # Verdict accuracy
        is_malicious = gold_label == 1
        pred_blocked = pred_verdict == "block"

        if is_malicious and pred_blocked:
            tp += 1
        elif is_malicious and not pred_blocked:
            fn += 1
        elif not is_malicious and pred_blocked:
            fp += 1
        else:
            tn += 1

        # Per-category (only for malicious items)
        if is_malicious:
            for cat in gold_cats:
                if cat in pred_cats:
                    cat_tp[cat] += 1
                else:
                    cat_fn[cat] += 1
            for cat in pred_cats:
                if cat not in gold_cats:
                    cat_fp[cat] += 1

        # Language
        lang_total[gold_lang] += 1
        if pred_lang == gold_lang:
            lang_correct[gold_lang] += 1

        results.append({
            "id": item_id,
            "gold_verdict": "block" if is_malicious else "allow",
            "pred_verdict": pred_verdict,
            "gold_cats": sorted(gold_cats),
            "pred_cats": sorted(pred_cats),
            "gold_lang": gold_lang,
            "pred_lang": pred_lang,
            "risk_score": pred.get("risk_score"),
            "correct": (pred_blocked == is_malicious),
        })

    total = len(items)
    n_malicious = tp + fn
    n_benign = tn + fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    # Per-category F1
    cat_f1: dict[str, dict] = {}
    for cat in VALID_CATEGORIES:
        p = cat_tp[cat] / (cat_tp[cat] + cat_fp[cat]) if (cat_tp[cat] + cat_fp[cat]) > 0 else 0.0
        r = cat_tp[cat] / (cat_tp[cat] + cat_fn[cat]) if (cat_tp[cat] + cat_fn[cat]) > 0 else 0.0
        f = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        cat_f1[cat] = {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3),
                       "tp": cat_tp[cat], "fp": cat_fp[cat], "fn": cat_fn[cat]}

    # Language accuracy
    lang_acc = {
        lang: round(lang_correct[lang] / lang_total[lang], 3)
        for lang in lang_total
    }

    return {
        "total": total,
        "n_malicious": n_malicious,
        "n_benign": n_benign,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "verdict": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "accuracy": round(accuracy, 4),
        },
        "per_category": cat_f1,
        "language_accuracy": lang_acc,
        "per_item": results,
    }


def print_report(report: dict) -> None:
    v = report["verdict"]
    print("\n" + "=" * 60)
    print("  CODEGUARD DEV-SAMPLE EVALUATION REPORT")
    print("=" * 60)
    print(f"  Total snippets : {report['total']}")
    print(f"  Malicious      : {report['n_malicious']}")
    print(f"  Benign         : {report['n_benign']}")
    print(f"\n  Verdict-level metrics:")
    print(f"    TP={report['tp']}  FP={report['fp']}  TN={report['tn']}  FN={report['fn']}")
    print(f"    Precision : {v['precision']:.4f}")
    print(f"    Recall    : {v['recall']:.4f}")
    print(f"    F1        : {v['f1']:.4f}")
    print(f"    FPR       : {v['fpr']:.4f}  (benign false-positive rate)")
    print(f"    Accuracy  : {v['accuracy']:.4f}")

    print(f"\n  Per-category F1:")
    for cat, m in sorted(report["per_category"].items(), key=lambda x: -x[1]["f1"]):
        bar = "#" * int(m["f1"] * 20)
        print(f"    {cat:<35s} F1={m['f1']:.3f} P={m['precision']:.3f} R={m['recall']:.3f} "
              f"(TP={m['tp']} FP={m['fp']} FN={m['fn']}) {bar}")

    print(f"\n  Language detection accuracy:")
    for lang, acc in sorted(report["language_accuracy"].items(), key=lambda x: -x[1]):
        print(f"    {lang:<15s} {acc:.3f}")

    print(f"\n  Per-item misclassifications:")
    for item in report["per_item"]:
        if not item["correct"]:
            status = "FP" if item["pred_verdict"] == "block" and item["gold_verdict"] == "allow" else "FN"
            print(f"    [{status}] {item['id']}")
            print(f"         gold={item['gold_cats']}  pred={item['pred_cats']}")
    print("=" * 60)


if __name__ == "__main__":
    dev_path = sys.argv[1] if len(sys.argv) > 1 else _DEV_PATH
    print(f"Loading dev sample from: {dev_path}")

    model = ensure_model_ready(dev_path=dev_path)
    items = load_dev(dev_path)
    report = evaluate(items, model)
    print_report(report)

    # Write JSON report
    out_path = Path(__file__).parent / "eval_report.json"
    with open(out_path, "w") as fh:
        # Remove per_item from JSON to keep it clean
        summary = {k: v for k, v in report.items() if k != "per_item"}
        json.dump(summary, fh, indent=2)
    print(f"\nJSON report written to: {out_path}")
