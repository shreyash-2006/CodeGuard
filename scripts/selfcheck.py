"""
scripts/selfcheck.py — validate the response schema on N sample responses.

Runs the engine in-process over the dev sample, a battery of garbage inputs,
and random strings, asserting every response satisfies §2.3 invariants.

Run:
    python scripts/selfcheck.py [N]
"""
from __future__ import annotations

import json
import random
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard.engine import analyze
from codeguard.ml_model import ensure_model_ready
from codeguard.schema import VALID_CATEGORIES, is_valid_response

_ROOT = Path(__file__).parent.parent
_DEV_PATH = _ROOT / "codeguard_dev.jsonl"

_GARBAGE = [
    "", "   ", "\n\n", None, 0, -1, 3.14, True, False, [], {}, ["a", "b"],
    {"k": "v"}, "\x00\x00", "\x00\x01\x02\xff", "\ufeffimport os",
    "\u202eimport os\u202c", "\r\n\r\n", "x" * 200000,
    "eval(" * 5000, "[" * 5000, ")" * 5000,
]


def _dev_codes() -> list[str]:
    if not _DEV_PATH.exists():
        return []
    out = []
    for line in _DEV_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line).get("code", ""))
            except Exception:
                pass
    return out


def _random_strings(n: int) -> list[str]:
    rng = random.Random(1234)
    alphabet = string.printable
    return ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 200))) for _ in range(n)]


def main() -> int:
    target_n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    model = ensure_model_ready(dev_path=str(_DEV_PATH))

    pool: list = list(_dev_codes()) + list(_GARBAGE)
    if not pool:
        pool = ["print('hello')"]
    # Fill up to target_n by cycling + random strings
    inputs = [pool[i % len(pool)] for i in range(target_n)]
    if target_n > len(pool):
        inputs = pool + _random_strings(target_n - len(pool))

    failures = 0
    for i, code in enumerate(inputs):
        try:
            result = analyze(code, model=model)
        except Exception as exc:
            print(f"[FAIL] #{i} raised: {exc!r} for input {code!r:.60}")
            failures += 1
            continue
        if not is_valid_response(result):
            print(f"[FAIL] #{i} invalid response for input {code!r:.60}: {result}")
            failures += 1
            continue
        # extra: block/cats/risk consistency (is_valid_response already covers it)
        if result["verdict"] == "block":
            if not (result["categories"] and result["risk_score"] >= 0.5):
                print(f"[FAIL] #{i} block invariant violated: {result}")
                failures += 1

    print(f"\nselfcheck: {len(inputs) - failures}/{len(inputs)} responses valid "
          f"({len(VALID_CATEGORIES)} categories).")
    if failures:
        print(f"selfcheck: {failures} FAILURE(S)")
        return 1
    print("selfcheck: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
