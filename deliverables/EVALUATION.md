# Evaluation Results & Efficiency Note

All numbers below are produced by the scripts in this repository and stored as
raw evidence in this folder. Hardware: single laptop CPU (no GPU), `--workers 1`.

| Evidence | Command |
|---|---|
| `evidence_dev_eval.txt` / `evidence_dev_report.json` | `python eval/run_eval.py codeguard_dev.jsonl` |
| `evidence_holdout_metrics.json` | `python -m codeguard.ml.train --data datagen/out --out models` |
| `evidence_latency.txt` | `python eval/latency.py` |
| `evidence_adversarial.txt` | `python eval/adversarial.py` |
| `evidence_interception.txt` | `python demo/intercept_check.py` |

> **Note:** the 42-snippet `codeguard_dev.jsonl` is provided by the organizer and
> is **not** redistributed in this repository (it contains fake demo credentials
> that trip secret scanners). Place it at the repo root, or set
> `CODEGUARD_DEV_PATH`, to reproduce the dev-sample numbers below.

---

## 1. Public dev sample (42 snippets: 30 malicious, 12 benign)

| Metric | Value |
|---|---|
| TP / FP / TN / FN | 30 / **0** / 12 / 0 |
| **Precision** | **1.0000** |
| **Recall** | **1.0000** |
| **F1** | **1.0000** |
| **False-positive rate (benign)** | **0.0000** |
| Accuracy | 1.0000 |

**Per-category F1 (dev sample)**

| Category | F1 | P | R | TP | FP | FN |
|---|---|---|---|---|---|---|
| `secret_access` | 1.000 | 1.000 | 1.000 | 4 | 0 | 0 |
| `data_exfiltration` | 1.000 | 1.000 | 1.000 | 3 | 0 | 0 |
| `destructive_command` | 1.000 | 1.000 | 1.000 | 5 | 0 | 0 |
| `obfuscated_execution` | 1.000 | 1.000 | 1.000 | 5 | 0 | 0 |
| `persistence_or_privesc` | 1.000 | 1.000 | 1.000 | 2 | 0 | 0 |
| `resource_exhaustion` | 1.000 | 1.000 | 1.000 | 3 | 0 | 0 |
| `ssrf_network_exfil` | 1.000 | 1.000 | 1.000 | 3 | 0 | 0 |
| `ai_targeted_instructions` | 1.000 | 1.000 | 1.000 | 4 | 0 | 0 |
| `dependency_risk` | 0.857 | 0.750 | 1.000 | 3 | 1 | 0 |

Language-detection accuracy on the dev sample: **1.000** for all six languages
(python, bash, sql, javascript, yaml, markdown).

**False positives: 0.** The single category-level deviation
(`dependency_risk` P=0.75) is a *category over-prediction on an already-blocked
malicious snippet* — the verdict is correct; an extra secondary category fires.
There are **no benign snippets blocked**.

---

## 2. Held-out synthetic test (family split — no family straddles train/test)

Trained on `datagen/out` (1 652 train / 378 val / 378 test rows). Metrics in
`evidence_holdout_metrics.json`:

| Metric | Value |
|---|---|
| TP / FP / TN / FN | 248 / **0** / 126 / 4 |
| Precision | 1.0000 |
| Recall | 0.9841 |
| **F1** | **0.9920** |
| **FPR** | **0.0000** |
| Accuracy | 0.9894 |

Per-category F1: `data_exfiltration`, `obfuscated_execution`,
`resource_exhaustion` = 1.00; `persistence_or_privesc` 0.94;
`ssrf_network_exfil` 0.85; `dependency_risk` / `destructive_command` 0.80;
`ai_targeted_instructions` 0.76; `secret_access` 0.61.

> **Why two categories are below 0.80:** the synthetic set *deliberately*
> co-labels credential-read-and-exfiltrate flows (gold = `data_exfiltration`) so
> `secret_access` legitimately fires as a **secondary** category, lowering its
> per-category precision without affecting the verdict. This is the
> multi-label over-prediction caveat from the risk register. Verdict-level F1
> (the scored quantity) is 0.992.

---

## 3. Robustness

**Adversarial mutation survival** (`eval/adversarial.py`): 177/180 = **0.983**
(target ≥ 0.90). Format-preserving mutations (comments, whitespace, identifier
renames, string splitting, embedding in fences/YAML `run:` blocks) do not break
detection. Weakest category: `obfuscated_execution` 0.900 (3/30 mutations evade).

**Fuzzing** (`tests/fuzz_test.py`, `scripts/selfcheck.py`): 1000/1000 responses
schema-valid across empty, `None`, binary, 1e5-line, nested-bracket, huge-line
and mixed-encoding inputs; deterministic across repeated runs.

---

## 4. Efficiency note

### Model artifacts (CPU, loaded once at startup)

| Artifact | Size | Contents |
|---|---|---|
| `models/ml.joblib` | **3.21 MB** | char TF-IDF (2–5, ≤150 k) + word TF-IDF (1–2, ≤50 k) + dense scaler + calibrated OvR (9 labels) |
| `models/metrics.json` | 2 KB | held-out metrics |
| `codeguard/data/thresholds.json` | <1 KB | per-category block thresholds |

No pretrained weights, no GPU, no external calls. The artifact is dominated by
the TF-IDF vocabularies; the classifiers themselves are tiny (linear models).

**Runtime footprint:** ~180 MB RSS after model load, 0.08 s to load the model,
~17.5 ms/request warm — fits a 512 MB Render free instance.

### Latency (500 warm sequential requests, typical snippets < 5 KB)

| | p50 | p95 | p99 |
|---|---|---|---|
| **Total** | **17.5 ms** | **24.2 ms** | **30.4 ms** |

Per-stage (one run): `preprocess 0.01 · langid 0.03 · segment 0.02 ·
deobfuscate 0.03 · parse 0.04 · detectors 0.50 · **ml 11.58** · fusion 0.01 ·
explain 0.02` ms. The ML transform dominates; detectors are sub-millisecond.

Pathological inputs (200 k lines, one 900 k-char line, 50 k nested brackets)
return **valid** responses in < 2 s (hard timeout + ReDoS guards), never hang.

### Accuracy before / after optimization

Measured during development on the **held-out synthetic split** (dev-sample F1 is
saturated at 1.0 in every configuration, so it does not discriminate):

| Configuration | Held-out F1 | Held-out FPR | p95 latency | Notes |
|---|---|---|---|---|
| Initial model — char 2–4 TF-IDF (30 k), **uncalibrated** OvR LogReg, hard-coded thresholds, unbounded regexes/parsing | 0.77 – 0.94 * | 0.01 – 0.11 * | ≈ 117 ms | overstated thresholds from noisy val; sqlglot/markdown re-init per call; pathological inputs hit the 2 s timeout → false blocks |
| **Final** — char 2–5 + word 1–2 + dense features, **calibrated** OvR; thresholds tuned + bounded to [0.40, 0.72]; bounded regexes, 20 k-char line cap, 250 k-char analysis cap, 20 k-char ML input cap | **0.992** | **0.000** | **24 ms** | no false blocks; timeout only for genuinely pathological input |

\* range across intermediate iterations observed in-session — **not a formal
A/B benchmark**; the final row is the reproducible, scripted result.

**Net effect of optimization:** ~5× lower p95 latency (≈117 → 24 ms) with **no
loss of detection quality** (dev F1 stays 1.0; held-out F1 improves to 0.992 and
FPR to 0.0), and pathological inputs no longer produce false `block`s.

---

## 5. Ablation

`eval/ablation.py` (toggle config flags) on the held-out split:

| Configuration | Dev F1 | Held-out F1 | Held-out FPR |
|---|---|---|---|
| Full system | 1.000 | 0.992 | 0.000 |
| Rules only (`CODEGUARD_ENABLE_ML=0`) | 1.000 | 0.992 | 0.000 |
| No deobfuscation | 1.000 | 0.992 | 0.000 |
| No parsing | 1.000 | 0.992 | 0.000 |

**Finding:** the intent/story **rules carry the verdict** on these sets; the
calibrated ML is a backup signal that feeds the fused score but does not flip a
verdict here. Its expected value is on unseen lookalikes outside the rule tables.
Benign **dampers** are the decisive lever for the zero-FPR result.
