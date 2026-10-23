"""
ml/train.py — train, calibrate and threshold-tune the CodeGuard model.

    python -m codeguard.ml.train --data datagen/out --out models/

Steps:
  1. load train/val/test JSONL
  2. fit FeatureBuilder on train (no leakage)
  3. fit OneVsRest(CalibratedClassifierCV(LogReg)) + ai sub-model
  4. tune per-category thresholds on val (best F1, benign FPR ≤ 4%)
  5. evaluate on the held-out test split; write models/metrics.json
  6. write codeguard/data/thresholds.json and models/ml.joblib
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from codeguard import config
from codeguard.ml.model import CATEGORIES, MultiLabelModel
from codeguard.schema import VALID_CATEGORIES
from codeguard.pipeline.segment import segment


def _load_jsonl(path: Path) -> list[dict]:
    out = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def _cats(rec: dict) -> list[str]:
    if isinstance(rec.get("categories"), list):
        return [c for c in rec["categories"] if c in VALID_CATEGORIES]
    if rec.get("label", 0) == 1:
        return [c.strip() for c in str(rec.get("category", "")).split(",") if c.strip() in VALID_CATEGORIES]
    return []


def _ai_text(rec: dict) -> str:
    try:
        segs = segment(rec.get("code", ""))
        return "\n".join(s.text for s in segs if s.kind in ("comment", "docstring", "string", "prose"))
    except Exception:
        return ""


def _scores_via_engine(records, model, thresholds=None):
    """Run the full engine on each record; return (fused_rows, gold_rows, verdict_langs)."""
    from codeguard import fusion
    if thresholds is not None:
        fusion._THRESHOLDS_CACHE = dict(thresholds)
    fused_rows, gold_rows, langs = [], [], []
    from codeguard.engine import analyze_detailed
    for rec in records:
        _, diag = analyze_detailed(rec.get("code", ""), model=model)
        fused_rows.append(diag.get("category_scores", {}))
        gold_rows.append(set(_cats(rec)))
        langs.append(rec.get("language", "unknown"))
    return fused_rows, gold_rows, langs


def _best_f1_threshold(scores, y) -> float:
    """Threshold maximising F1; among near-best thresholds, prefer the lowest
    (i.e. maximise recall while keeping F1 — the FPR budget is enforced next)."""
    import numpy as np
    scores = np.asarray(scores, dtype=float)
    y = np.asarray(y, dtype=int)
    if y.sum() == 0:
        return 0.5
    candidates = []
    for t in sorted(set(np.round(scores, 3))):
        pred = scores >= t
        tp = int((pred & (y == 1)).sum())
        fp = int((pred & (y == 0)).sum())
        fn = int((~pred & (y == 1)).sum())
        denom = 2 * tp + fp + fn
        f1 = (2 * tp / denom) if denom else 0.0
        candidates.append((float(t), f1))
    if not candidates:
        return 0.5
    best_f1 = max(f1 for _, f1 in candidates)
    near = [t for t, f1 in candidates if f1 >= best_f1 - 0.02]
    # never let the threshold fall below 0.3 (avoid trivially firing everything)
    near = [t for t in near if t >= 0.3] or [max(near)]
    return round(min(near), 3)


def _verdicts(fused_rows, thresholds):
    return [
        any(row.get(c, 0.0) >= thresholds.get(c, 0.5) for c in CATEGORIES)
        for row in fused_rows
    ]


def tune_thresholds(fused_rows, gold_rows, budget=config.BENIGN_FPR_BUDGET):
    """Per-category best-F1 thresholds, bounded to a sane range and raised above
    the benign score distribution; then satisfy the overall FPR budget.

    Thresholds are capped at THRESHOLD_MAX to avoid over-fitting noisy val
    benign items (which otherwise pushes thresholds → ~0.95 and destroys recall).
    """
    import numpy as np

    T_MIN, T_MAX = 0.40, 0.72

    thresholds: dict[str, float] = {}
    for c in CATEGORIES:
        scores = [row.get(c, 0.0) for row in fused_rows]
        y = [1 if c in g else 0 for g in gold_rows]
        t = _best_f1_threshold(scores, y)
        benign_scores = [row.get(c, 0.0) for row, g in zip(fused_rows, gold_rows) if not g]
        if benign_scores:
            p99 = float(np.percentile(benign_scores, 99))
            t = max(t, round(p99 + 0.02, 3))
        thresholds[c] = min(max(t, T_MIN), T_MAX)

    benign_idx = [i for i, g in enumerate(gold_rows) if not g]
    while True:
        verd = _verdicts(fused_rows, thresholds)
        fps = [i for i in benign_idx if verd[i]]
        fpr = len(fps) / len(benign_idx) if benign_idx else 0.0
        if fpr <= budget or not fps:
            break
        contrib: dict[str, int] = {c: 0 for c in CATEGORIES}
        for i in fps:
            for c in CATEGORIES:
                if fused_rows[i].get(c, 0.0) >= thresholds[c]:
                    contrib[c] += 1
        cat = max(contrib, key=lambda k: contrib[k])
        nxt = round(thresholds[cat] + 0.05, 3)
        if nxt > T_MAX:
            thresholds[cat] = T_MAX
            if all(thresholds[c] >= T_MAX for c in CATEGORIES):
                break
        else:
            thresholds[cat] = nxt
    return thresholds


def evaluate(fused_rows, gold_rows, langs):
    cats = CATEGORIES
    tp = fp = tn = fn = 0
    per_cat = {c: {"tp": 0, "fp": 0, "fn": 0} for c in cats}
    lang_tot, lang_ok = {}, {}
    from codeguard import fusion
    thresholds = fusion.load_thresholds()
    for row, gold, lang in zip(fused_rows, gold_rows, langs):
        pred = {c for c in cats if row.get(c, 0.0) >= thresholds.get(c, 0.5)}
        gold_set = set(gold)
        is_mal = bool(gold_set)
        is_blk = bool(pred)
        if is_mal and is_blk:
            tp += 1
        elif is_mal and not is_blk:
            fn += 1
        elif not is_mal and is_blk:
            fp += 1
        else:
            tn += 1
        if is_mal:
            for c in gold_set:
                per_cat[c]["tp" if c in pred else "fn"] += 1
            for c in pred - gold_set:
                per_cat[c]["fp"] += 1
        lang_tot[lang] = lang_tot.get(lang, 0) + 1
        lang_ok[lang] = lang_ok.get(lang, 0) + (1 if (is_blk == is_mal) else 0)

    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    acc = (tp + tn) / max(1, tp + tn + fp + fn)

    cat_metrics = {}
    for c, d in per_cat.items():
        p = d["tp"] / (d["tp"] + d["fp"]) if d["tp"] + d["fp"] else 0.0
        r = d["tp"] / (d["tp"] + d["fn"]) if d["tp"] + d["fn"] else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        cat_metrics[c] = {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3),
                          "tp": d["tp"], "fp": d["fp"], "fn": d["fn"]}
    return {
        "verdict": {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
                    "fpr": round(fpr, 4), "accuracy": round(acc, 4)},
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "per_category": cat_metrics,
        "language_accuracy": {k: round(lang_ok[k] / lang_tot[k], 3) for k in lang_tot},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=config.DATASET_DIR)
    ap.add_argument("--out", default=config.MODEL_DIR)
    ap.add_argument("--dev", default="codeguard_dev.jsonl")
    args = ap.parse_args()

    data_dir = Path(args.data)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    train = _load_jsonl(data_dir / "train.jsonl")
    val = _load_jsonl(data_dir / "val.jsonl")
    test = _load_jsonl(data_dir / "test.jsonl")

    if not train:
        print("No training data found; building dataset first…")
        try:
            from datagen.build_dataset import main as build_main
            build_main()
            train = _load_jsonl(data_dir / "train.jsonl")
            val = _load_jsonl(data_dir / "val.jsonl")
            test = _load_jsonl(data_dir / "test.jsonl")
        except Exception as exc:
            print(f"Could not build dataset: {exc}")
            return 1

    print(f"train={len(train)} val={len(val)} test={len(test)}")
    texts = [r.get("code", "") for r in train]
    labels = [_cats(r) for r in train]

    ai_texts, ai_labels = [], []
    for r in train:
        t = _ai_text(r)
        if t.strip():
            ai_texts.append(t)
            ai_labels.append(1 if "ai_targeted_instructions" in _cats(r) else 0)

    model = MultiLabelModel()
    model.train(texts, labels, ai_texts=ai_texts, ai_labels=ai_labels)
    if not model._ready:
        print("Model could not be trained (scikit-learn unavailable?)")
        return 1

    # ── tune thresholds on val (using fused rule+ML scores) ──────────────────
    val_fused, val_gold, _ = _scores_via_engine(val, model)
    # model's own defaults first
    from codeguard import fusion
    thresholds = tune_thresholds(val_fused, val_gold)
    fusion._THRESHOLDS_CACHE = dict(thresholds)

    # ── evaluate on the held-out test split ──────────────────────────────────
    test_fused, test_gold, test_lang = _scores_via_engine(test, model, thresholds)
    metrics = evaluate(test_fused, test_gold, test_lang)
    metrics["n_train"] = len(train)
    metrics["n_val"] = len(val)
    metrics["n_test"] = len(test)
    metrics["thresholds"] = thresholds

    # ── persist ──────────────────────────────────────────────────────────────
    model.thresholds = thresholds
    model.save(out_dir / "ml.joblib")
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    Path(config.THRESHOLDS_PATH).write_text(json.dumps(thresholds, indent=2), encoding="utf-8")

    v = metrics["verdict"]
    print("\n== HELD-OUT TEST ==")
    print(f"  P={v['precision']} R={v['recall']} F1={v['f1']} FPR={v['fpr']} acc={v['accuracy']}")
    print("  per-category F1:")
    for c, m in sorted(metrics["per_category"].items()):
        print(f"    {c:<30s} F1={m['f1']} (P={m['precision']} R={m['recall']})")
    print(f"\n  wrote {out_dir/'ml.joblib'}, {out_dir/'metrics.json'}, {config.THRESHOLDS_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
