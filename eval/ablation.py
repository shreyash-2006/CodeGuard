"""
eval/ablation.py — component ablation on the held-out synthetic test split.

Toggles pipeline stages via config flags (env vars) and reports verdict P/R/F1/FPR.

    python eval/ablation.py
    CODEGUARD_ENABLE_ML=0 python eval/ablation.py
    CODEGUARD_ENABLE_DEOBFUSCATION=0 python eval/ablation.py
    ...
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard import config
from codeguard.engine import analyze
from codeguard.ml_model import ensure_model_ready

_ROOT = Path(__file__).parent.parent
_TEST = _ROOT / "datagen" / "out" / "test.jsonl"


def main() -> int:
    if not _TEST.exists():
        print(f"No test split at {_TEST}; run datagen/build_dataset.py first.")
        return 1
    model = ensure_model_ready(dev_path=str(_ROOT / "codeguard_dev.jsonl"))
    rows = [json.loads(l) for l in _TEST.read_text(encoding="utf-8").splitlines() if l.strip()]

    tp = fp = tn = fn = 0
    for r in rows:
        resp = analyze(r["code"], model=model)
        pred = resp["verdict"] == "block"
        gold = bool(r["categories"])
        if gold and pred:
            tp += 1
        elif gold:
            fn += 1
        elif pred:
            fp += 1
        else:
            tn += 1

    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0

    flags = {
        "deobfuscation": config.ENABLE_DEOBFUSCATION,
        "segmentation": config.ENABLE_SEGMENTATION,
        "parsing": config.ENABLE_PARSING,
        "ml": config.ENABLE_ML,
        "ml_policy": config.ML_POLICY,
    }
    print(f"flags={flags}")
    print(f"n={len(rows)} P={p:.4f} R={rc:.4f} F1={f1:.4f} FPR={fpr:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
