# CodeGuard — Real-time pre-execution safety for LLM-generated code

CodeGuard accepts a code string and returns a fixed-schema allow/block verdict —
**before the code runs**. CPU-only, fully local, **no LLM calls anywhere**.

**🔗 Live deployment:** dashboard **<https://codeguard-bdmu.onrender.com/ui/>** ·
judge endpoint **`POST https://codeguard-bdmu.onrender.com/check`** ·
health **`GET https://codeguard-bdmu.onrender.com/health`**<br>
**🔗 Cloudflare Endpoint:** dashboard **<https://cancel-subjects-meyer-ethics.trycloudflare.com/ui/>** ·

```
POST /check  {"code": "..."}  ->  {"verdict","risk_score","categories","code_language","reason","vulnerable_lines"}
```

---

## Quick start

```bash
pip install -r requirements.txt
python -m uvicorn codeguard.api:app --host 0.0.0.0 --port 8000 --workers 1
```

* API: `http://localhost:8000` · Dashboard: `http://localhost:8000/ui` · Docs: `/docs`
* The model (`models/ml.joblib`) is loaded once at startup; if absent, a fallback
  model is trained automatically (rules-only if scikit-learn is unavailable).

```bash
curl -X POST http://localhost:8000/check -H "Content-Type: application/json" \
  -d '{"code":"import os; os.system(\"rm -rf /\")"}'
```

---

## Response contract

| Field | Type | Notes |
|---|---|---|
| `verdict` | `"block"` \| `"allow"` | required |
| `risk_score` | float `[0,1]`, 4 dp | required |
| `categories` | list of the 9 fixed strings | required, sorted/de-duped |
| `code_language` | `python\|bash\|javascript\|sql\|yaml\|markdown\|unknown` | required |
| `reason` | string (≤400 chars, secrets masked) | good-to-have |
| `vulnerable_lines` | sorted unique 1-based ints (≤20) | good-to-have |

**Invariants (enforced in one place, `schema.finalize_response`):**
`verdict=="block"` ⟺ `categories` non-empty ⟺ `risk_score ≥ 0.5`; `allow` ⇒ empty
categories and lines, score < 0.5. `/check` **never** returns 4xx/5xx — malformed
input yields a valid `allow`/`"Empty input"` at HTTP 200; any internal error or
timeout yields a fail-closed `block`.

### Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /check` | primary judged endpoint (fixed schema) |
| `POST /batch` | many snippets → `{"results":[…]}` (accepts `snippets`/`items`/bare list/`{code}`) |
| `POST /batch/csv` | **bulk CSV** upload (file / JSON / raw) + metrics when gold labels present; `?format=csv` downloads results |
| `POST /analyze` | same schema + diagnostics (`category_scores`, `evidence`, `deobfuscation_layers`, `ml_probs`, `timings_ms`, `thresholds_used`) |
| `GET /health` | `{"status":"ok","models_loaded":true,"version":"0.1.0"}` |
| `GET /ui` | dashboard (Check / Batch / Interception / About) |
| `POST /demo/intercept` | runs the interception proof, returns `{passed,evidence}` |

---

## Architecture

```
code input
 └─▶ preprocess     BOM/NUL/zero-width/newline normalization; 1 MB guard + head/tail truncate; 20k-char line cap
 └─▶ langid         heuristic regex scorer (+ confidence)
 └─▶ segment        comments, strings, Markdown fences, YAML run blocks, heredocs, bash -c, eval args (with line maps)
 └─▶ deobfuscate    layered (line-mapped): base64(+zlib), \xNN, chr(), concat fold, alias, rot13, URL, reverse, ${IFS}, $'\xNN'
 └─▶ parse          ast / sqlglot / yaml.compose_all / markdown-it-py   (regex fallback; parse failure never ⇒ allow)
 └─▶ detectors      9 intent/story packs + language packs + AST taint + network/IP normalization + dependency + injection + resource
 └─▶ ML             char+word TF-IDF + dense features → OvR CalibratedClassifierCV(LogReg) (+ ai_targeted sub-model)
 └─▶ fusion         rule_p=1−Π(1−conf); p=1−(1−rule_p)(1−w_ml·ml_p)·dampers; hard override ≥0.97; per-category thresholds
 └─▶ explain        reason + vulnerable_lines (original line numbers, secrets masked)
 └─▶ finalize_response()   single schema-enforcement point
 └─▶ JSON (always HTTP 200)
```

**Key design principle:** detectors encode attack **stories** (sensitive source →
processing → external sink), not keyword blocklists. Benign **dampers** are a
first-class deliverable — every benign lookalike (parameterized SQL,
`ast.literal_eval`, docstring credentials, read-only `crontab -l`, allowlisted
hosts) is explicitly suppressed.

### The nine categories

`secret_access` · `data_exfiltration` · `destructive_command` ·
`obfuscated_execution` · `persistence_or_privesc` · `resource_exhaustion` ·
`ssrf_network_exfil` · `ai_targeted_instructions` · `dependency_risk`

### Interception

`codeguard/guard.py` checks **synchronously before** any runner:

```python
from codeguard.guard import check, guarded, safe_exec, BlockedByCodeGuard
check(code)          # never raises (fail-closed)
@guarded
def run(code): ...   # runs only after an `allow` verdict
```

Proven with an observable side effect in `demo/intercept_check.py`
(blocked code never executes). See [`INTERCEPTION.md`](INTERCEPTION.md).

---

## Components & licenses

**No pretrained weights and no LLM are used.** Every component is an
open-source library; the ML model is trained from hand-written templates +
mutations:

| Component | License | Use |
|---|---|---|
| Python standard library (`ast`, `csv`, `re`, …) | PSF | parsing, CSV, regex |
| `fastapi` | MIT | HTTP API |
| `uvicorn` | BSD-3-Clause | ASGI server |
| `pydantic` | MIT | request handling |
| `scikit-learn` | BSD-3-Clause | TF-IDF, calibration, logistic regression |
| `scipy` | BSD-3-Clause | sparse feature matrices |
| `joblib` | BSD-3-Clause | model persistence |
| `numpy` | BSD-3-Clause | numerical ops |
| `PyYAML` | MIT | YAML parsing (`compose_all`, never `load`) |
| `sqlglot` | MIT | SQL AST parsing |
| `markdown-it-py` | MIT | Markdown parsing |
| `python-multipart` | Apache-2.0 | CSV file upload |

Trained artifacts (`models/ml.joblib`, 3.2 MB) are generated locally, not
downloaded.

---

## Evaluation (summary)

* **Public dev sample (42 snippets):** precision / recall / F1 = **1.0000**,
  **false positives = 0**, FPR = 0.0000; language accuracy 1.000.
* **Held-out family-split synthetic test:** F1 = **0.992**, FPR = **0.000**.
* **Latency (typical < 5 KB):** p50 ≈ 17 ms, p95 ≈ 24 ms; pathological inputs
  return valid responses < 2 s.
* **Adversarial mutation survival:** 0.983.

Full tables, model sizes and the before/after optimisation note:
[`EVALUATION.md`](EVALUATION.md).

---

## Assumptions

* Inputs are single code snippets (one request per snippet), as in the dev sample.
* The hidden set follows the same generator/style as the public dev sample.
* Category conventions are fuzzy and **multi-label**: e.g. the dev sample labels
  some read-and-post snippets as `secret_access` only, while a synthetic template
  may label the same flow `data_exfiltration`. CodeGuard therefore reports its
  best top-k categories rather than forcing a single label.
* Analysis sizes are capped (1 MB input → 200 KB head + 50 KB tail; 250 k chars;
  20 k chars/line) so analysis stays bounded; the spec's truncation allowance is
  used.
* `--workers 1` is used so the ML model is loaded exactly once.

## Known limitations

* **Heuristic, not a compiler.** Language ID and many rules are regex-based;
  detection is intentionally conservative and cannot reason about arbitrary
  control flow.
* **Taint is intra-snippet and shallow** (Python AST source→sink; JS/bash
  approximations). Inter-procedural or cross-file flows are not tracked.
* **Deobfuscation is bounded** to base64/zlib, hex, `chr()`, concat, alias,
  rot13, URL, reversed strings and common shell tricks (depth 4); arbitrary
  crypto/packing is not undone.
* **Per-category F1 is imperfect on the synthetic stress set** for
  `secret_access` / `ai_targeted_instructions` due to multi-label co-firing (see
  EVALUATION §2); verdict-level metrics are unaffected.
* **No guarantee against novel, out-of-distribution attacks** — the rules target
  known MITRE ATT&CK / AML.T0054 techniques plus their mutations.
* Pathological inputs may reach the 2 s hard timeout and consequently **fail
  closed** (block); this is deliberate and documented.

---

## Repository layout

```
codeguard/
  config.py schema.py guard.py api.py app.py engine.py fusion.py explain.py
  csvio.py metrics.py
  pipeline/    preprocess langid segment deobfuscate parse
  detectors/   base dampers universal python_pack bash_pack js_pack sql_pack
               yaml_pack markdown_pack taint network dependency resource injection
  ml/          features model train
  data/        thresholds.json top_packages_*.txt sensitive_paths.yaml injection_phrases.yaml
datagen/   templates/ benign/ mutators.py build_dataset.py     -> datagen/out/*.jsonl
models/    ml.joblib metrics.json
demo/      intercept_check.py
eval/      run_eval.py eval_csv.py ablation.py latency.py adversarial.py
tests/     test_schema test_guard test_deobfuscate test_langid test_fusion
           test_markdown_yaml_lines test_csv regressions/ fuzz_test
scripts/   selfcheck.py smoke_live.py smoke_csv.py
web/       index.html styles.css app.js
deliverables/  INDEX.md README.md WRITEUP.md EVALUATION.md INTERCEPTION.md + evidence
Makefile   requirements.txt  README.md  writeup.md
```

See [`WRITEUP.md`](WRITEUP.md) for the design rationale, and
[`INDEX.md`](INDEX.md) for the deliverable map.
