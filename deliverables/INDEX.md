# CodeGuard — Deliverables Index

Mapping of the required submission deliverables to files in this repository.

| # | Deliverable | Status | Location |
|---|---|---|---|
| 1 | Public GitHub repository | **done** | <https://github.com/shreyash-2006/CodeGuard> (branch `main`) |
| 2 | Runnable service + submit endpoint URL | **runnable** | `codeguard.api:app` / `codeguard.app:app` · [`DEPLOYMENT.md`](DEPLOYMENT.md) — URL to be submitted to the organizer |
| 3 | Interception-proof demo script | **done** | `demo/intercept_check.py` · [`INTERCEPTION.md`](INTERCEPTION.md) · `evidence_interception.txt` |
| 4 | Dev-sample evaluation + efficiency note | **done** | [`EVALUATION.md`](EVALUATION.md) · `evidence_dev_eval.txt` · `evidence_latency.txt` · `evidence_holdout_metrics.json` |
| 5 | README (architecture, components+licenses, assumptions, limitations) | **done** | [`README.md`](README.md) |
| 6 | Short write-up (2–3 pages) | **done** | [`WRITEUP.md`](WRITEUP.md) |

## Captured evidence (raw, reproducible)

| File | Produced by |
|---|---|
| `evidence_interception.txt` | `python demo/intercept_check.py` |
| `evidence_dev_eval.txt` | `python eval/run_eval.py codeguard_dev.jsonl` |
| `evidence_dev_report.json` | `eval/eval_report.json` (dev-sample metrics) |
| `evidence_holdout_metrics.json` | `models/metrics.json` (held-out family-split test) |
| `evidence_latency.txt` | `python eval/latency.py` |
| `evidence_adversarial.txt` | `python eval/adversarial.py` |

## Reproduce all of it

```bash
pip install -r requirements.txt
python datagen/build_dataset.py
python -m codeguard.ml.train --data datagen/out --out models
make check                       # tests + selfcheck + demo + latency
python eval/eval_csv.py examples/sample_codes.csv

# run the service
python -m uvicorn codeguard.api:app --host 0.0.0.0 --port 8000 --workers 1
```

> The 42-snippet `codeguard_dev.jsonl` dev sample is provided by the organizer and
> is **not** committed (its fake demo credentials trip secret scanners). Place it
> at the repo root to reproduce the dev-sample numbers; the model in `models/` is
> committed, so the service runs without it.
