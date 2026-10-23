"""
tests/test_csv.py — CSV ingestion, gold parsing and metric summarisation.

Runs as a plain script or under pytest.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard.csvio import parse_csv, parse_gold, results_to_csv
from codeguard.metrics import summarize


def test_parse_basic_header():
    items = parse_csv("id,code,labels\n1,\"rm -rf /\",destructive_command\n2,print(1),benign\n")
    assert len(items) == 2
    assert items[0]["id"] == "1"
    assert items[0]["code"] == "rm -rf /"
    assert items[0]["gold_malicious"] is True
    assert items[0]["gold_categories"] == ["destructive_command"]
    assert items[1]["gold_malicious"] is False


def test_parse_aliases_and_multiline():
    csv = 'name,snippet,language,category\nx,"import os\nos.system(\'id\')",python,destructive_command\n'
    items = parse_csv(csv)
    assert len(items) == 1
    assert "\n" in items[0]["code"]
    assert items[0]["id"] == "x"
    assert items[0]["language"] == "python"


def test_parse_headerless():
    items = parse_csv("print(1)\nrm -rf /\n")
    assert len(items) == 2
    assert items[1]["code"] == "rm -rf /"
    assert items[0]["gold_malicious"] is None


def test_parse_empty():
    assert parse_csv("") == []
    assert parse_csv("   \n") == []


def test_parse_gold_variants():
    assert parse_gold("1") == (True, [])
    assert parse_gold("benign") == (False, [])
    assert parse_gold("malicious") == (True, [])
    assert parse_gold("secret_access;data_exfiltration") == (True, ["data_exfiltration", "secret_access"])
    assert parse_gold("") == (None, [])
    assert parse_gold(None) == (None, [])


def test_results_to_csv_roundtrip():
    results = [{
        "id": "a", "verdict": "block", "risk_score": 0.9,
        "categories": ["secret_access"], "code_language": "python",
        "reason": "Blocked: secret_access — x", "vulnerable_lines": [1, 2],
        "gold_malicious": True, "gold_categories": ["secret_access"], "correct": True,
    }]
    text = results_to_csv(results)
    lines = text.strip().splitlines()
    assert lines[0].startswith("id,verdict,risk_score")
    assert "secret_access" in lines[1]
    assert lines[1].startswith("a,block,0.9")


def test_summarize_metrics():
    results = [
        {"verdict": "block", "gold_malicious": True, "categories": ["destructive_command"], "gold_categories": ["destructive_command"]},
        {"verdict": "allow", "gold_malicious": False, "categories": [], "gold_categories": []},
        {"verdict": "allow", "gold_malicious": True, "categories": [], "gold_categories": ["secret_access"]},
    ]
    s = summarize(results)
    assert s["total"] == 3
    assert s["confusion"] == {"tp": 1, "fp": 0, "tn": 1, "fn": 1}
    assert s["verdict"]["precision"] == 1.0
    assert 0.0 <= s["verdict"]["f1"] <= 1.0


def test_summarize_unlabeled():
    s = summarize([{"verdict": "allow"}, {"verdict": "block"}])
    assert s["total"] == 2 and s["blocked"] == 1 and "verdict" not in s


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
    print(f"\ntest_csv: {len(tests) - failures}/{len(tests)} passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(_main())
