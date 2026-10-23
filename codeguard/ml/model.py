"""
ml/model.py — MultiLabelModel.

  * OneVsRestClassifier(CalibratedClassifierCV(LogisticRegression(class_weight='balanced')))
  * a separate small sub-model for ai_targeted_instructions (comment/string text)
  * joblib save/load; module-level singleton loaded once at startup
  * missing/corrupt artifact ⇒ rules-only degrade (ready=False)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import numpy as np

from codeguard import config
from codeguard.ml.features import FeatureBuilder
from codeguard.schema import VALID_CATEGORIES

try:
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.linear_model import LogisticRegression
    from sklearn.multiclass import OneVsRestClassifier
    from sklearn.preprocessing import MultiLabelBinarizer
    from sklearn.feature_extraction.text import TfidfVectorizer
    import joblib
    _SK = True
except Exception:  # pragma: no cover
    _SK = False

CATEGORIES = sorted(VALID_CATEGORIES)
_AI = "ai_targeted_instructions"


class MultiLabelModel:
    def __init__(self) -> None:
        self.fb: Optional[FeatureBuilder] = None
        self.clf = None
        self.mlb: Optional[MultiLabelBinarizer] = None
        self.ai_fb = None
        self.ai_clf = None
        self.thresholds: dict[str, float] = {c: 0.5 for c in CATEGORIES}
        self._ready = False

    # ── training ─────────────────────────────────────────────────────────────
    def train(self, texts, labels, ai_texts=None, ai_labels=None,
              thresholds: Optional[dict] = None) -> None:
        if not _SK:
            return
        texts = list(texts)
        mlb = MultiLabelBinarizer(classes=CATEGORIES)
        Y = mlb.fit_transform(labels)

        fb = FeatureBuilder().fit(texts)
        X = fb.transform(texts)

        base = LogisticRegression(C=1.0, max_iter=1000, solver="lbfgs", class_weight="balanced")
        cal = CalibratedClassifierCV(base, method="sigmoid", cv=3)
        clf = OneVsRestClassifier(cal)
        clf.fit(X, Y)

        self.fb, self.clf, self.mlb = fb, clf, mlb

        # ai sub-model (comment/string text only)
        if ai_texts:
            try:
                av = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5),
                                     max_features=40000, sublinear_tf=True, min_df=1)
                aX = av.fit_transform(ai_texts)
                ay = np.asarray(ai_labels, dtype=int)
                if len(set(ay.tolist())) < 2:
                    ay = np.concatenate([ay, [1 - ay[0]]]) if len(ay) else ay
                    aX = np.vstack([aX.toarray(), aX.toarray()[:1]]) if aX.shape[0] else aX
                aclf = LogisticRegression(C=1.0, max_iter=1000, class_weight="balanced")
                aclf.fit(aX, ay)
                self.ai_fb, self.ai_clf = av, aclf
            except Exception:
                self.ai_fb = self.ai_clf = None

        if thresholds:
            self.thresholds = {c: float(thresholds.get(c, 0.5)) for c in CATEGORIES}
        self._ready = True

    # ── inference ────────────────────────────────────────────────────────────
    def predict_proba(self, code: str) -> dict[str, float]:
        if not self._ready or not _SK:
            return {c: 0.0 for c in CATEGORIES}
        try:
            X = self.fb.transform([code[:20000]])
            proba = self.clf.predict_proba(X)[0]
            probs = {c: float(p) for c, p in zip(CATEGORIES, proba)}
        except Exception:
            probs = {c: 0.0 for c in CATEGORIES}

        if self.ai_clf is not None:
            try:
                from codeguard.pipeline.segment import segment
                segs = segment(code)
                text = "\n".join(s.text for s in segs if s.kind in ("comment", "docstring", "string", "prose"))
                if text.strip():
                    p = float(self.ai_clf.predict_proba(self.ai_fb.transform([text]))[0][1])
                    probs[_AI] = max(probs.get(_AI, 0.0), p)
            except Exception:
                pass
        return probs

    # ── persistence ──────────────────────────────────────────────────────────
    def save(self, path) -> None:
        if not self._ready or not _SK:
            return
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "fb": self.fb, "clf": self.clf, "mlb": self.mlb,
            "ai_fb": self.ai_fb, "ai_clf": self.ai_clf,
            "thresholds": self.thresholds, "categories": CATEGORIES,
        }, path)

    def load(self, path) -> bool:
        if not _SK:
            return False
        try:
            obj = joblib.load(Path(path))
            self.fb = obj["fb"]
            self.clf = obj["clf"]
            self.mlb = obj.get("mlb")
            self.ai_fb = obj.get("ai_fb")
            self.ai_clf = obj.get("ai_clf")
            self.thresholds = obj.get("thresholds", {c: 0.5 for c in CATEGORIES})
            self._ready = True
            return True
        except Exception:
            self._ready = False
            return False


# ── Singleton ────────────────────────────────────────────────────────────────
_MODEL: Optional[MultiLabelModel] = None


def get_model() -> MultiLabelModel:
    global _MODEL
    if _MODEL is None:
        _MODEL = MultiLabelModel()
    return _MODEL


def _fallback_training_data(dev_path: str | None):
    """Training data if no dataset/artifact exists: datagen output, else dev file."""
    texts, labels, ai_texts, ai_labels = [], [], [], []
    try:
        from datagen.build_dataset import build_records
        recs = build_records()
        for r in recs:
            texts.append(r["code"])
            labels.append(r["categories"])
    except Exception:
        # minimal dev-based fallback
        import json
        path = dev_path or "codeguard_dev.jsonl"
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    cats = [] if o.get("label", 0) == 0 else [
                        c.strip() for c in str(o.get("category", "")).split(",") if c.strip() in VALID_CATEGORIES
                    ]
                    texts.append(o.get("code", ""))
                    labels.append(cats)
    return texts, labels


def ensure_model_ready(dev_path: str | None = None) -> MultiLabelModel:
    """Load the artifact, or train a fresh model if none exists. Never raises."""
    model = get_model()
    if model._ready:
        return model

    path = Path(config.ML_MODEL_PATH)
    if path.exists() and model.load(path):
        return model

    try:
        texts, labels = _fallback_training_data(dev_path)
        if texts:
            model.train(texts, labels)
            try:
                model.save(path)
            except Exception:
                pass
    except Exception:
        pass
    return model
