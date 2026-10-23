# How to Run CodeGuard

Follow these steps to set up and run the CodeGuard security layer.

## 1. Prerequisites
- Python 3.11+
- All dependencies listed in `requirements.txt`

## 2. Setup
Clone the repository and install the required packages:

```bash
cd d:\hackathon
pip install -r requirements.txt
```

## 3. Starting the Server
Run the FastAPI application using `uvicorn`:

```bash
python -m uvicorn codeguard.app:app --host 0.0.0.0 --port 8000 --workers 1
```

The server will initialize and load the ML model (training it if necessary on the first run).

## 4. Accessing the Dashboard
Open your browser and navigate to:
**[http://localhost:8000/ui](http://localhost:8000/ui)**

From the dashboard, you can:
- Paste code snippets for analysis.
- Use **Load Safe Sample** or **Load Unsafe Sample** to see CodeGuard in action.
- Run **Batch** analysis on multiple snippets.
- Execute the **Interception Proof** to verify real-time execution prevention.

## 5. Training the model (optional)

The model is trained on a generated, family-split dataset (no LLM, no external calls):

```bash
python -X utf8 datagen/build_dataset.py          # writes datagen/out/{train,val,test}.jsonl
python -X utf8 -m codeguard.ml.train --data datagen/out --out models
```

This writes `models/ml.joblib`, `models/metrics.json` and
`codeguard/data/thresholds.json`. The server loads `models/ml.joblib` at
startup; if it is absent it trains a fallback model automatically.

## 6. Running Tests & Evaluation
To verify the engine's performance and accuracy, run everything with:

```bash
make check
```

Or individually:

### Schema + guard tests
```bash
python -X utf8 tests/test_schema.py
python -X utf8 tests/test_guard.py
```

### Interception Demo
Verifies that malicious code is actually blocked from running:
```bash
python demo/intercept_check.py
```

### Full Evaluation
Runs the engine against the 42-snippet development dataset and generates a report:
```bash
python -X utf8 eval/run_eval.py codeguard_dev.jsonl
```

### Fuzz & Regression Tests
Ensures robustness against pathological inputs:
```bash
python -X utf8 tests/fuzz_test.py
```

### Self-check (schema on 1000+ responses)
```bash
python -X utf8 scripts/selfcheck.py 1000
```

### Latency & adversarial robustness
```bash
python -X utf8 eval/latency.py
python -X utf8 eval/adversarial.py
```

### Bulk evaluation from CSV
Upload a CSV of codes (with an optional gold-label column) to `/batch/csv`:

```bash
curl -X POST http://localhost:8000/batch/csv -F "file=@my_codes.csv"
```

or evaluate a CSV directly with the CLI (in-process):

```bash
python -X utf8 eval/eval_csv.py examples/sample_codes.csv
```

In the dashboard, the **Batch** tab accepts a pasted CSV (or **Upload CSV / JSONL**),
shows a results table with a metrics summary, and lets you **Download results CSV**.
A ready-to-use sample lives at `examples/sample_codes.csv`.

## 7. API Usage (CLI)
You can also use `curl` to interact with the API directly:

```bash
curl -X POST http://localhost:8000/check \
  -H "Content-Type: application/json" \
  -d '{"code": "import os; os.system(\"rm -rf /\")"}'
```
