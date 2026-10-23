# CodeGuard

**CPU-only code security analysis API.** Detects 9 categories of malicious code patterns using intent/story-based rules + a calibrated TF-IDF ML classifier. No external LLM calls anywhere.

---

## Quick Start

```bash
cd d:\hackathon

# Install dependencies
pip install -r requirements.txt

# Start the API server (single worker so the model loads once)
python -m uvicorn codeguard.app:app --host 0.0.0.0 --port 8000 --workers 1
```

- **API:** `http://localhost:8000`
- **Dashboard UI:** `http://localhost:8000/ui`

---

## API Endpoints

### `GET /ui` — Interactive Dashboard
The primary way to interact with CodeGuard. Features:
- **Check:** Real-time analysis with highlighted vulnerable lines.
- **Batch:** Analyze multiple snippets at once.
- **Interception Demo:** Live proof of execution prevention.
- **Health:** Real-time monitoring of engine and ML model status.

### `POST /check` — Primary judged endpoint
```bash
curl -X POST http://localhost:8000/check \
  -H "Content-Type: application/json" \
  -d '{"code": "import os; os.system(\"rm -rf /\")"}'
```

Response (always HTTP 200, always valid schema):
```json
{
  "verdict": "block",
  "risk_score": 0.9423,
  "categories": ["destructive_command"],
  "code_language": "python",
  "reason": "Unchecked path interpolated into rm -rf (T1485)",
  "vulnerable_lines": [1]
}
```

### `POST /batch` — Batch analysis
Accepts `{"snippets":[...]}`, `{"items":[...]}`, a bare list, plain strings, or `{"code":...}`.
Each item is analyzed in isolation — one bad item never fails the batch.
```bash
curl -X POST http://localhost:8000/batch \
  -H "Content-Type: application/json" \
  -d '{"snippets": [{"code": "print(1)", "id": "a"}, {"code": "rm -rf /", "id": "b"}]}'
```

### `POST /batch/csv` — Bulk analysis from a CSV file
Upload a CSV (multipart `file` field), or POST `{"csv": "<csv text>"}`, or a raw
CSV body. Columns are matched case-insensitively:

| Column | Aliases | Required |
|---|---|---|
| `code` | `snippet`, `text`, `content`, `input`, `source` | **yes** |
| `id` | `index`, `name` | no |
| `language` | `lang` | no |
| gold | `labels`, `categories`, `label`, `gold`, `expected`, `target` | no |

The gold column takes a category list (`;` / `|` / `,` separated) or a plain
label (`1/0`, `true/false`, `malicious/benign`). Quoted multi-line code cells
are supported. When gold labels are present the response includes a `summary`
with precision/recall/F1/FPR/accuracy and per-category metrics.

```bash
# upload a file
curl -X POST http://localhost:8000/batch/csv -F "file=@my_codes.csv"

# or send the CSV inline
curl -X POST http://localhost:8000/batch/csv -H "Content-Type: application/json" \
  -d '{"csv": "id,code,labels\n1,\"rm -rf /\",destructive_command\n"}'

# or download results as CSV
curl -X POST "http://localhost:8000/batch/csv?format=csv" -F "file=@my_codes.csv" -o results.csv
```

### `POST /analyze` — Deep analysis (not judged)
Same schema as `/check` plus diagnostics: `category_scores`, `evidence`, `deobfuscation_layers`,
`ml_probs`, `ml_ran`, `timings_ms`, `thresholds_used`.

### `GET /health` — Health check / warmup
```bash
curl http://localhost:8000/health
# {"status":"ok","models_loaded":true,"version":"0.1.0",...}
```

### `POST /demo/intercept` — Interception proof
Runs the safe/unsafe marker-file proof and returns `{"passed": bool, "evidence": [...]}`.

### Guard API (`codeguard/guard.py`)
```python
from codeguard.guard import check, guarded, safe_exec, BlockedByCodeGuard

check(code)                       # -> dict, never raises (fail-closed)
safe_exec(code)                   # runs only after an `allow` verdict
@guarded                          # decorator: fn(code) runs only if allowed
def run(code): ...
```
The check happens synchronously **before** the runner; `block` (or any guard error/timeout)
raises `BlockedByCodeGuard` — fail-closed.

---

## Response Schema

| Field | Type | Description |
|---|---|---|
| `verdict` | `"block"` or `"allow"` | Final decision |
| `risk_score` | `float [0,1]` | Confidence, 4 decimal places |
| `categories` | `list[str]` | Detected threat categories (sorted, de-duped) |
| `code_language` | `str` | Detected language |
| `reason` | `str` | Human-readable explanation |
| `vulnerable_lines` | `list[int]` | 1-indexed line numbers of flagged code |

**Invariants:**
- `verdict=="block"` ⟺ `categories` non-empty ⟺ `risk_score ≥ 0.5`
- `/check` always returns HTTP 200 — never 422 or 500, even on malformed input

---

## Detected Categories (9 total)

| Category | MITRE ATT&CK | Example Pattern |
|---|---|---|
| `secret_access` | T1552.x | Read `~/.aws/credentials` → POST to remote |
| `data_exfiltration` | T1048.x | `os.environ` secrets → webhook; ICMP exfil |
| `destructive_command` | T1485, T1059 | `rm -rf {path}`, `UPDATE ... SET balance=0` without WHERE |
| `obfuscated_execution` | T1059.006, T1027, T1620 | `__import__('sub'+'process')`, `shelve` pickle deserialization |
| `persistence_or_privesc` | T1543, T1548 | Write systemd unit with `curl|bash`; append to `/etc/sudoers` |
| `resource_exhaustion` | T1499.x | Unbounded `dd if=/dev/zero`, 50,000 open sockets |
| `ssrf_network_exfil` | T1090 | `gopher://127.0.0.1:6379/`; cloud metadata 169.254.169.254 |
| `ai_targeted_instructions` | AML.T0054 | Prompt injection in comments/tool descriptions |
| `dependency_risk` | T1195.001 | Typosquatted packages (`colourama`); untrusted git URLs |

---

## Architecture

```
code input
 └─▶ preprocess     BOM/NUL/zero-width/newline normalization; 1 MB guard + head/tail truncate
 └─▶ langid         Heuristic regex scorer → python|bash|js|sql|yaml|markdown|unknown (+confidence)
 └─▶ segment        comments, strings, Markdown fences, YAML run blocks, heredocs, bash -c, eval args
 └─▶ deobfuscate    Layered (with line maps): base64(+zlib), \xNN, chr(), concat, alias, rot13, URL, reverse, shell
 └─▶ parse          ast / sqlglot / yaml.compose_all / markdown-it-py (regex fallback; never allows on parse failure)
 └─▶ detectors      9 intent/story rule packs (MITRE-tagged) + language packs + AST taint
                    + network/IP-normalization + dependency typosquat + injection + resource
 └─▶ ML             char (2-5) + word (1-2) TF-IDF + dense features → OvR CalibratedClassifierCV(LogReg)
                    (+ a small ai_targeted_instructions sub-model on comment/string text)
 └─▶ fusion         rule_p[c]=1−Π(1−confᵢ); p[c]=1−(1−rule_p[c])(1−w_ml·ml_p[c])·dampers
 └─▶ explain        reason + vulnerable_lines (original line numbers, secrets masked)
 └─▶ finalize_response()   Single schema enforcement point
 └─▶ JSON response
```

**Key design principle:** Rules encode *intent stories* (sensitive source → processing → external sink), not keyword blocklists. Benign dampers are a first-class deliverable — every benign lookalike from the dev sample has an explicit damper.

---

## Interception Demo

```bash
cd d:\hackathon

# Run all 4 demo scenarios (blocked / allowed / fail-closed / schema validation)
python demo/intercept_check.py

# CLI: analyze a file
python guard.py check mycode.py

# CLI: guarded execution (blocks if malicious)
python guard.py exec mycode.py
```

---

## Evaluation

```bash
cd d:\hackathon

# Everything (tests + selfcheck + demo + latency)
make check

# Train / re-train the model on the generated dataset
make train                      # = datagen/build_dataset.py + codeguard.ml.train

# Individually
python -X utf8 tests/test_schema.py
python -X utf8 tests/test_guard.py
python -X utf8 tests/test_deobfuscate.py
python -X utf8 tests/test_langid.py
python -X utf8 tests/test_fusion.py
python -X utf8 tests/test_markdown_yaml_lines.py
python -X utf8 tests/regressions/test_known_fixes.py
python -X utf8 tests/fuzz_test.py
python -X utf8 scripts/selfcheck.py 1000
python -X utf8 demo/intercept_check.py
python -X utf8 eval/latency.py
python -X utf8 eval/adversarial.py
python -X utf8 eval/run_eval.py codeguard_dev.jsonl
python -X utf8 eval/ablation.py

# Evaluate many snippets from a CSV (in-process or against the live server)
python -X utf8 eval/eval_csv.py examples/sample_codes.csv
python -X utf8 eval/eval_csv.py my_codes.csv --out results.csv
python -X utf8 eval/eval_csv.py my_codes.csv --url http://localhost:8000
```

> **Note — dev sample not redistributed.** The 42-snippet `codeguard_dev.jsonl`
> is provided by the organizer and is intentionally **not committed** (it contains
> fake demo credentials that trip GitHub secret scanning). Drop it at the repo
> root — or point `CODEGUARD_DEV_PATH` at it — to reproduce the dev-sample numbers
> below. The trained model in `models/` is committed, so the service runs without it.

**Dev-sample results (42 snippets):** verdict precision/recall/F1 = 1.0000, FPR = 0.0000.

**Held-out, family-split synthetic test** (`models/metrics.json`, no family straddles train/test):

| Metric | Value |
|---|---|
| Verdict precision / recall / F1 | 1.000 / 0.984 / **0.992** |
| Benign FPR | **0.000** |
| Per-category F1 | mostly ≥ 0.8 (see note below) |

The synthetic stress set deliberately co-fires categories (e.g. a credential read
that is also exfiltrated is labelled `data_exfiltration`, but `secret_access`
also fires), so `secret_access` / `ai_targeted_instructions` per-category
precision is lower even though the verdict is correct — see `writeup.md` §5–6.

**Latency:** p50 ≈ 19 ms, p95 ≈ 25 ms (typical snippets &lt; 5 KB); pathological
inputs (huge single line, 200 k lines, nested brackets) return valid responses
in &lt; 2 s (soft ReDoS guards + hard timeout).

**Dev-sample results:**

| Metric | Value |
|---|---|
| Verdict Precision | 1.0000 |
| Verdict Recall | 1.0000 |
| Verdict F1 | 1.0000 |
| Benign FPR | 0.0000 |
| Per-category F1 (all 9) | 1.000 each |
| Language accuracy (all 6) | 1.000 each |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CODEGUARD_DEV_PATH` | `codeguard_dev.jsonl` | Path to dev sample (used for model training) |
| `PORT` | `8000` | (uvicorn arg, not env var) |

---

## Dependencies & Licenses

| Package | Version | License | Use |
|---|---|---|---|
| `fastapi` | ≥0.110 | MIT | REST API framework |
| `uvicorn` | ≥0.29 | BSD-3 | ASGI server |
| `scikit-learn` | ≥1.4 | BSD-3 | TF-IDF + calibrated LogReg classifier |
| `scipy` | ≥1.11 | BSD-3 | sparse feature matrices |
| `joblib` | ≥1.3 | BSD-3 | model persistence |
| `numpy` | ≥1.26 | BSD-3 | numerical ops |
| `pydantic` | ≥2.0 | MIT | request handling |
| `PyYAML` | ≥6.0 | MIT | YAML parsing (`compose_all`, never `load`) |
| `sqlglot` | ≥20 | MIT | SQL AST parsing |
| `markdown-it-py` | ≥3.0 | MIT | Markdown parsing |

No pretrained weights, no LLM, no external API calls.

---

## File Structure

```
d:\hackathon\
├── LICENSE                 ← MIT
├── .gitignore  .env.example  requirements.txt  Makefile
├── README.md               ← this file
├── writeup.md  RUN.md
├── guard.py                ← CLI entry (wraps codeguard.guard)
├── codeguard_dev.jsonl     ← 42-snippet dev sample (provided by the organizer; NOT redistributed — see note below)
├── codeguard\
│   ├── config.py           ← all tunables (timeouts, ML_POLICY, limits, paths)
│   ├── schema.py           ← finalize_response() / fail_closed() / empty_input() / is_valid_response()
│   ├── guard.py            ← BlockedByCodeGuard, check(), @guarded, safe_exec()
│   ├── api.py / app.py     ← FastAPI endpoints
│   ├── engine.py           ← pipeline orchestrator (hard timeout, never raises)
│   ├── fusion.py           ← noisy-OR rule fusion + ML + thresholds
│   ├── explain.py          ← reason + vulnerable_lines (secrets masked)
│   ├── csvio.py            ← CSV parse/serialise for bulk evaluation
│   ├── metrics.py          ← verdict/category metric summariser
│   ├── rules.py            ← backward-compat shim → codeguard.detectors
│   ├── ml_model.py         ← backward-compat shim → codeguard.ml
│   ├── pipeline\
│   │   ├── preprocess.py   ← normalization, size/line guards
│   │   ├── langid.py       ← language + confidence
│   │   ├── segment.py      ← comments/strings/embedded blocks with line maps
│   │   ├── deobfuscate.py  ← layered decoding + line maps
│   │   └── parse.py        ← ast / sqlglot / yaml / markdown-it (best-effort)
│   ├── detectors\
│   │   ├── base.py dampers.py universal.py
│   │   ├── python_pack.py bash_pack.py js_pack.py sql_pack.py yaml_pack.py markdown_pack.py
│   │   ├── taint.py network.py dependency.py resource.py injection.py
│   ├── ml\
│   │   ├── features.py     ← char+word TF-IDF + dense handcrafted features
│   │   ├── model.py        ← OvR CalibratedClassifierCV + ai sub-model + singleton
│   │   └── train.py        ← `python -m codeguard.ml.train`
│   └── data\
│       ├── thresholds.json top_packages_pypi.txt top_packages_npm.txt
│       └── sensitive_paths.yaml injection_phrases.yaml
├── datagen\                ← templates/  benign/  mutators.py  build_dataset.py  → datagen/out (git-ignored)
├── models\                 ← ml.joblib (3.2 MB, committed), metrics.json
├── examples\sample_codes.csv ← ready-to-eval CSV
├── demo\intercept_check.py
├── tests\   (schema, guard, deobfuscate, langid, fusion, markdown_yaml_lines, csv, regressions, fuzz)
├── scripts\ (selfcheck.py, smoke_live.py, smoke_csv.py, capture_evidence.py)
├── eval\    (run_eval.py, eval_csv.py, ablation.py, latency.py, adversarial.py)
├── web\     (index.html, styles.css, app.js)
├── deliverables\           ← submission docs: INDEX / README / WRITEUP / EVALUATION / INTERCEPTION + evidence
└── docs\                   ← archived spec & notes (CodeGuard_Build_Spec.md, 3.docx, session_context.md)
```

**Submission deliverables** (interception proof, evaluation + efficiency note,
README, write-up) live in [`deliverables/`](deliverables/INDEX.md). Repo license: **MIT**.

---

## Configuration

Every tunable lives in `codeguard/config.py` (or via env vars):

| Setting | Default | Notes |
|---|---|---|
| `HARD_TIMEOUT_S` | `2.0` | pipeline runs in a worker thread; timeout ⇒ fail-closed block |
| `MAX_INPUT_BYTES` | `1_000_000` | larger inputs truncated to head 200 KB + tail 50 KB |
| `ANALYSIS_MAX_CHARS` | `250_000` | always caps analysis size (ReDoS safety); single lines capped at 20 k chars |
| `MAX_VULNERABLE_LINES` | `20` | cap on reported lines |
| `ML_POLICY` | `early_exit` | `always` / `early_exit` / `on_no_evidence` |
| `DECISIVE_CONFIDENCE` | `0.97` | early-exit threshold for decisive rule hits |
| `W_ML` | `0.6` | ML weight in fusion |
| `ENABLE_DEOBFUSCATION` / `ENABLE_SEGMENTATION` / `ENABLE_PARSING` / `ENABLE_ML` | `1` | ablation flags |
| `CODEGUARD_ML_POLICY` | — | override `ML_POLICY` at runtime |

Thresholds are read from `codeguard/data/thresholds.json` (written by
`codeguard.ml.train`). Model artifacts live in `models/` (`ml.joblib`, `metrics.json`).

---

## Assumptions & Limitations

- **Python 3.11+** required (uses `match`, type hints)
- **CPU-only:** No GPU acceleration used or needed. p95 latency < 50ms on a laptop CPU.
- **Model training:** `codeguard.ml.train` trains on a generated family-split dataset in `datagen/out` (hand-written templates + mutation; no LLM, no public-dataset copying). It also falls back to the dev sample if no dataset/artifact exists. No answers are hard-coded — rules encode attack *stories*, not sample lookups.
- **Category label conventions are fuzzy and multi-label:** the dev sample labels some read-and-post snippets as `secret_access` only, while a synthetic template may label the same flow `data_exfiltration`. This co-firing lowers per-category precision without affecting the verdict (see `writeup.md`).
- **ReDoS guards:** patterns are bounded, single lines are capped at 20 k chars, analysis input at 250 k chars, and the whole pipeline has a 2 s hard timeout (fail-closed).
- **Fail-closed:** Any internal error or timeout still returns a valid block verdict at HTTP 200.
