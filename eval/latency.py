"""
eval/latency.py — measure p50/p95/p99 latency.

Warms up 50 requests, then measures 500 sequential analyses of typical
snippets (< 5 KB). Also reports per-stage timings from /analyze diagnostics.

Targets: p50 < 20 ms, p95 < 100 ms.

Run:
    python eval/latency.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard.engine import analyze, analyze_detailed
from codeguard.ml_model import ensure_model_ready

_ROOT = Path(__file__).parent.parent
_DEV = _ROOT / "codeguard_dev.jsonl"

_TYPICAL = [
    "def add(a, b):\n    return a + b\n",
    "import os\nos.system('ls -la')\n",
    "SELECT id, name FROM users WHERE id = ?;",
    "const x = require('fs');\nconsole.log(x);\n",
    "import requests\nr = requests.get('https://api.example.com/health', timeout=5)\n",
    "rm -rf /",
]


def _snippets() -> list[str]:
    pool = list(_TYPICAL)
    if _DEV.exists():
        import json
        for line in _DEV.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    pool.append(json.loads(line)["code"])
                except Exception:
                    pass
    return pool


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    idx = min(len(values) - 1, int(len(values) * p))
    return values[idx]


def main() -> int:
    model = ensure_model_ready(dev_path=str(_DEV))
    snippets = _snippets()

    # Warm up
    for i in range(50):
        analyze(snippets[i % len(snippets)], model=model)

    # Measure
    times = []
    n = 500
    for i in range(n):
        code = snippets[i % len(snippets)]
        t0 = time.perf_counter()
        analyze(code, model=model)
        times.append((time.perf_counter() - t0) * 1000.0)

    times.sort()
    p50, p95, p99 = _pct(times, 0.50), _pct(times, 0.95), _pct(times, 0.99)
    print("=" * 56)
    print("  CODEGUARD LATENCY")
    print("=" * 56)
    print(f"  snippets measured : {n} (warm, sequential)")
    print(f"  p50 : {p50:7.2f} ms")
    print(f"  p95 : {p95:7.2f} ms   (target < 100 ms)")
    print(f"  p99 : {p99:7.2f} ms")

    # Per-stage from one detailed run
    _, diag = analyze_detailed(snippets[0], model=model)
    print(f"\n  per-stage (one run): {diag.get('timings_ms')}")

    # Per-suite p95 (typical snippets, warm)
    suites = [
        ("dev sample", _DEV),
        ("held-out test", _ROOT / "datagen" / "out" / "test.jsonl"),
    ]
    print("\n  per-suite latency (warm, p50 / p95):")
    for label, path in suites:
        if not path.exists():
            print(f"    {label:<15s} (dataset not present — skipped)")
            continue
        codes = []
        import json
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    codes.append(json.loads(line)["code"])
                except Exception:
                    pass
        if not codes:
            continue
        for c in codes[:10]:
            analyze(c, model=model)
        t = []
        for c in codes:
            t0 = time.perf_counter()
            analyze(c, model=model)
            t.append((time.perf_counter() - t0) * 1000.0)
        t.sort()
        print(f"    {label:<15s} n={len(codes):<4d} p50={_pct(t, 0.50):.1f} ms  p95={_pct(t, 0.95):.1f} ms")

    print("=" * 56)

    ok = p95 < 100.0
    print("  RESULT:", "PASS" if ok else "FAIL (p95 ≥ 100 ms)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
