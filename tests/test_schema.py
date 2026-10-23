"""
tests/test_schema.py — every response satisfies §2.3, including malformed input.

Runs as a plain script (python tests/test_schema.py) or under pytest.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard.engine import analyze
from codeguard.ml_model import ensure_model_ready
from codeguard.schema import (
    VALID_CATEGORIES,
    empty_input,
    fail_closed,
    finalize_response,
    is_valid_response,
)

_MODEL = None


def _model():
    global _MODEL
    if _MODEL is None:
        _MODEL = ensure_model_ready()
    return _MODEL


BAD_INPUTS = ["", "   ", "\n\n", None, 0, 3.14, True, [], {}, "\x00\x01", "x" * 100000]


def test_malformed_inputs_are_valid():
    for code in BAD_INPUTS:
        result = analyze(code, model=_model())
        assert is_valid_response(result), f"invalid response for {code!r}: {result}"


def test_empty_input_shape():
    result = analyze("", model=_model())
    assert result["verdict"] == "allow"
    assert result["risk_score"] == 0.0
    assert result["categories"] == []
    assert result["code_language"] == "unknown"
    assert result["vulnerable_lines"] == []


def test_block_invariant():
    result = analyze("import os; os.system('rm -rf /')", model=_model())
    assert result["verdict"] == "block"
    assert result["categories"]
    assert result["risk_score"] >= 0.5


def test_finalize_enforces_consistency():
    # categories present but low score → forced to block ≥ 0.5
    r = finalize_response(verdict="allow", risk_score=0.1,
                          categories=["secret_access"], code_language="python")
    assert r["verdict"] == "block" and r["risk_score"] >= 0.5
    # no categories but high score → forced allow < 0.5, vuln cleared
    r = finalize_response(verdict="block", risk_score=0.9, categories=[],
                          code_language="python", vulnerable_lines=[1, 2])
    assert r["verdict"] == "allow" and r["risk_score"] < 0.5 and r["vulnerable_lines"] == []


def test_finalize_dedups_and_caps_lines():
    r = finalize_response(verdict="block", risk_score=0.9, categories=["secret_access"],
                          code_language="python", vulnerable_lines=[3, 1, 3, 1, 2],
                          total_lines=10)
    assert r["vulnerable_lines"] == [1, 2, 3]
    # out-of-range line dropped
    r2 = finalize_response(verdict="block", risk_score=0.9, categories=["secret_access"],
                           code_language="python", vulnerable_lines=[999], total_lines=5)
    assert r2["vulnerable_lines"] == []


def test_helpers_always_valid():
    assert is_valid_response(empty_input())
    assert is_valid_response(fail_closed())
    assert fail_closed()["verdict"] == "block"


def test_is_valid_response_rejects_garbage():
    assert not is_valid_response(None)
    assert not is_valid_response({})
    assert not is_valid_response({"verdict": "maybe", "risk_score": 0.0,
                                  "categories": [], "code_language": "python"})
    assert not is_valid_response({"verdict": "block", "risk_score": 0.2,
                                  "categories": ["secret_access"], "code_language": "python"})
    assert not is_valid_response({"verdict": "allow", "risk_score": 0.0,
                                  "categories": ["bogus"], "code_language": "python"})


def _main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as exc:
            print(f"  FAIL  {t.__name__}: {exc}")
            failures += 1
        except Exception as exc:
            print(f"  ERROR {t.__name__}: {exc}")
            failures += 1
    print(f"\ntest_schema: {len(tests) - failures}/{len(tests)} passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(_main())
