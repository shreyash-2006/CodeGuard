"""
config.py — Central place for every CodeGuard tunable.

Nothing in the pipeline should hard-code a limit, threshold, or flag;
read it from here so behaviour can be reasoned about and ablated.
"""
from __future__ import annotations

import os

# ── Identity ─────────────────────────────────────────────────────────────────
VERSION = "0.1.0"

# ── Input limits ─────────────────────────────────────────────────────────────
MAX_INPUT_BYTES = 1_000_000          # 1 MB hard ceiling
TRUNCATE_HEAD_BYTES = 200_000        # keep first 200 KB
TRUNCATE_TAIL_BYTES = 50_000         # keep last 50 KB
ANALYSIS_MAX_CHARS = 250_000         # always cap analysis input (ReDoS safety)

# ── Timeouts ─────────────────────────────────────────────────────────────────
SOFT_TIMEOUT_S = 0.5
HARD_TIMEOUT_S = 2.0

# ── Decision ─────────────────────────────────────────────────────────────────
BLOCK_THRESHOLD = 0.5
MAX_VULNERABLE_LINES = 20

# ── Feature flags ────────────────────────────────────────────────────────────
ENABLE_DEOBFUSCATION = os.environ.get("CODEGUARD_ENABLE_DEOBFUSCATION", "1") != "0"
ENABLE_ML = os.environ.get("CODEGUARD_ENABLE_ML", "1") != "0"
ENABLE_SEGMENTATION = os.environ.get("CODEGUARD_ENABLE_SEGMENTATION", "1") != "0"
ENABLE_PARSING = os.environ.get("CODEGUARD_ENABLE_PARSING", "1") != "0"
INCLUDE_EXTRA_FIELDS = os.environ.get("CODEGUARD_EXTRA_FIELDS", "0") == "1"

# ── Artifact paths (relative to the repo root) ───────────────────────────────
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(_REPO_ROOT, "models")
ML_MODEL_PATH = os.path.join(MODEL_DIR, "ml.joblib")
ML_METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")
THRESHOLDS_PATH = os.path.join(_REPO_ROOT, "codeguard", "data", "thresholds.json")
DATASET_DIR = os.path.join(_REPO_ROOT, "datagen", "out")

# ── ML training ──────────────────────────────────────────────────────────────
RANDOM_SEED = 2026
BENIGN_FPR_BUDGET = 0.04
TAINY_MAX_DEPTH = 4

# ── ML invocation policy ─────────────────────────────────────────────────────
# "always"        → every request
# "early_exit"    → every request except after a decisive hard-block (default)
# "on_no_evidence"→ only when no rule fired
ML_POLICY = os.environ.get("CODEGUARD_ML_POLICY", "early_exit")
DECISIVE_CONFIDENCE = 0.97

# ── Fusion ───────────────────────────────────────────────────────────────────
W_ML = 0.6
HARD_OVERRIDE = 0.97
