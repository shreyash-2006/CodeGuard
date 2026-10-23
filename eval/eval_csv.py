"""
eval/eval_csv.py — evaluate CodeGuard on many snippets from a CSV file.

    python eval/eval_csv.py examples/sample_codes.csv
    python eval/eval_csv.py my_codes.csv --out results.csv
    python eval/eval_csv.py my_codes.csv --url http://localhost:8000   # via the live API

The CSV needs a `code` column (aliases: snippet/text/content/input/source).
Optional: `id`, `language`, and a gold column (`labels`/`categories`/`label`)
whose value is a category list (`;`/`|`/`,` separated) or 1/0, true/false,
malicious/benign. When gold labels are present, precision/recall/F1/FPR are
printed. Results are written to `<input>.results.csv` (or --out).
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard.csvio import parse_csv, results_to_csv
from codeguard.metrics import summarize
from codeguard.schema import VALID_CATEGORIES


def _run_local(items: list[dict]) -> list[dict]:
    from codeguard.engine import analyze
    from codeguard.ml_model import ensure_model_ready

    model = ensure_model_ready()
    results = []
    for it in items:
        r = dict(analyze(it["code"], model=model))
        r["id"] = it["id"]
        r["gold_malicious"] = it["gold_malicious"]
        r["gold_categories"] = it["gold_categories"]
        if it["gold_malicious"] is not None:
            r["correct"] = (r["verdict"] == "block") == bool(it["gold_malicious"])
        results.append(r)
    return results


def _run_http(url: str, csv_text: str) -> list[dict]:
    body = json.dumps({"csv": csv_text}).encode()
    req = urllib.request.Request(
        url.rstrip("/") + "/batch/csv",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        payload = json.loads(resp.read())
    return payload.get("results", [])


def _print_summary(summary: dict) -> None:
    print("=" * 60)
    print("  CODEGUARD — CSV EVALUATION")
    print("=" * 60)
    print(f"  total snippets : {summary['total']}")
    print(f"  blocked        : {summary['blocked']}")
    print(f"  allowed        : {summary['allowed']}")
    if summary.get("labeled"):
        v = summary["verdict"]
        c = summary["confusion"]
        print(f"  labeled        : {summary['labeled']}")
        print(f"\n  TP={c['tp']}  FP={c['fp']}  TN={c['tn']}  FN={c['fn']}")
        print(f"    Precision : {v['precision']:.4f}")
        print(f"    Recall    : {v['recall']:.4f}")
        print(f"    F1        : {v['f1']:.4f}")
        print(f"    FPR       : {v['fpr']:.4f}")
        print(f"    Accuracy  : {v['accuracy']:.4f}")
        print("\n  per-category (where gold categories were provided):")
        for cat in sorted(VALID_CATEGORIES):
            m = summary["per_category"][cat]
            if m["tp"] or m["fp"] or m["fn"]:
                print(f"    {cat:<30s} F1={m['f1']:.3f} P={m['precision']:.3f} R={m['recall']:.3f}")
    print("=" * 60)


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate CodeGuard on a CSV of snippets.")
    ap.add_argument("csv_path", help="input CSV file")
    ap.add_argument("--out", default=None, help="output CSV (default: <input>.results.csv)")
    ap.add_argument("--url", default=None, help="evaluate via a running server instead of in-process")
    ap.add_argument("--limit", type=int, default=0, help="only evaluate the first N rows")
    args = ap.parse_args()

    path = Path(args.csv_path)
    if not path.exists():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2

    csv_text = path.read_text(encoding="utf-8-sig", errors="replace")
    items = parse_csv(csv_text)
    if args.limit:
        items = items[: args.limit]
    if not items:
        print("error: no rows parsed (need a `code` column)", file=sys.stderr)
        return 2

    if args.url:
        print(f"Evaluating {len(items)} snippets via {args.url} …")
        # re-serialise the limited set so --limit works over HTTP too
        limited = "\n".join(["id,language,code,labels"] + [
            f'{i},"{it["language"]}","{it["code"].replace(chr(34), chr(34)*2)}",'
            f'{"".join(it["gold_categories"]) or ("" if it["gold_malicious"] is None else ("1" if it["gold_malicious"] else "0"))}'
            for i, it in enumerate(items)
        ])
        results = _run_http(args.url, limited)
    else:
        print(f"Evaluating {len(items)} snippets in-process …")
        results = _run_local(items)

    summary = summarize(results)
    _print_summary(summary)

    out = Path(args.out) if args.out else path.with_suffix(".results.csv")
    out.write_text(results_to_csv(results), encoding="utf-8")
    print(f"  results written to: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
