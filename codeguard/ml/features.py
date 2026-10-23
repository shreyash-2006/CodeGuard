"""
ml/features.py — FeatureBuilder.

char n-gram TF-IDF (2–5, char_wb, ~150k) + word n-gram TF-IDF (1–2, ~50k)
+ dense handcrafted features (entropy, ratios, URL/IP/path/domain counts,
dangerous-token counts, base64/bidi flags, decoded-layer count, language one-hot).
"""
from __future__ import annotations

import math
import re
from collections import Counter

import numpy as np
from scipy import sparse

from codeguard.pipeline.deobfuscate import deobfuscate_with_meta
from codeguard.pipeline.langid import detect_language_scored

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import StandardScaler
    _SK = True
except Exception:  # pragma: no cover
    _SK = False

LANGUAGES = ["python", "bash", "javascript", "sql", "yaml", "markdown", "unknown"]

_URL = re.compile(r"https?://\S{1,2000}", re.IGNORECASE)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PATH = re.compile(r"(?:~?/[\w./\-]{1,200}|/etc/[\w./\-]{1,200}|\.aws|\.ssh|\.docker|\.kube)")
_DOMAIN = re.compile(r"\b[a-z0-9\-]{1,63}(?:\.[a-z0-9\-]{1,63})+\b", re.IGNORECASE)
_DANGEROUS = re.compile(
    r"\b(eval|exec|system|popen|subprocess|os\.system|rm|curl|wget|chmod|chown|sudo|"
    r"base64|b64decode|atob|fromCharCode|pickle|marshal|__import__|importlib|socket|"
    r"requests\.post|urlopen|sendBeacon|xp_cmdshell|drops?|truncate|crontab|systemctl|"
    r"authorized_keys|sudoers|LD_PRELOAD)\b",
    re.IGNORECASE,
)
_BASE64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class FeatureBuilder:
    def __init__(self) -> None:
        self.char = None
        self.word = None
        self.scaler = None
        self.dense_dim = 0

    # ── dense features ───────────────────────────────────────────────────────
    def _dense(self, text: str) -> np.ndarray:
        lang, _ = detect_language_scored(text)
        try:
            _, layers = deobfuscate_with_meta(text)
        except Exception:
            layers = 0
        n = max(1, len(text))
        digits = sum(ch.isdigit() for ch in text) / n
        alpha = sum(ch.isalpha() for ch in text) / n
        nonalnum = sum(not ch.isalnum() for ch in text) / n
        upper = sum(ch.isupper() for ch in text) / n
        whitespace = sum(ch.isspace() for ch in text) / n
        feats = [
            _entropy(text[:4000]),
            math.log1p(len(text)),
            digits,
            alpha,
            nonalnum,
            upper,
            whitespace,
            math.log1p(len(_URL.findall(text))),
            math.log1p(len(_IP.findall(text))),
            math.log1p(len(_PATH.findall(text))),
            math.log1p(len(_DOMAIN.findall(text))),
            math.log1p(len(_DANGEROUS.findall(text))),
            1.0 if _BASE64.search(text) else 0.0,
            1.0 if any(ord(ch) in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E) for ch in text) else 0.0,
            float(layers),
            text.count("\n") / 100.0,
            math.log1p(text.count(";")),
            math.log1p(text.count("|")),
        ]
        onehot = [1.0 if lang == L else 0.0 for L in LANGUAGES]
        return np.asarray(feats + onehot, dtype=np.float64)

    def _dense_matrix(self, texts) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dense_dim or 26), dtype=np.float64)
        return np.vstack([self._dense(t) for t in texts])

    # ── fit / transform ──────────────────────────────────────────────────────
    def fit(self, texts) -> "FeatureBuilder":
        texts = list(texts)
        self.char = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5),
                                    max_features=150000, sublinear_tf=True, min_df=2)
        self.word = TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                    max_features=50000, sublinear_tf=True, min_df=1,
                                    token_pattern=r"\S+")
        self.char.fit(texts)
        self.word.fit(texts)
        dense = self._dense_matrix(texts)
        self.dense_dim = dense.shape[1]
        self.scaler = StandardScaler(with_mean=True, with_std=True)
        self.scaler.fit(dense)
        return self

    def transform(self, texts) -> sparse.csr_matrix:
        # Cap length so huge inputs stay fast (bounded feature extraction).
        texts = [t[:20000] for t in texts]
        parts = [
            self.char.transform(texts),
            self.word.transform(texts),
            sparse.csr_matrix(self.scaler.transform(self._dense_matrix(texts))),
        ]
        return sparse.hstack(parts).tocsr()
