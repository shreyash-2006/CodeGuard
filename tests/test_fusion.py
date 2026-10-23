"""
tests/test_fusion.py — thresholds, hard override, ML invocation policy.

Runs as a plain script or under pytest.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard import config, fusion
from codeguard.detectors.base import Evidence


def test_noisy_or_combines_evidence():
    ev = [Evidence("secret_access", 0.5, [1]), Evidence("secret_access", 0.5, [2])]
    fused = fusion.fuse(ev, {}, {})
    assert abs(fused["secret_access"] - 0.75) < 1e-6


def test_hard_override():
    ev = [Evidence("persistence_or_privesc", 0.97, [1], hard_block=True)]
    fused = fusion.fuse(ev, {}, {})
    assert fused["persistence_or_privesc"] >= 0.97


def test_damper_suppresses():
    ev = [Evidence("secret_access", 0.9, [1])]
    fused = fusion.fuse(ev, {}, {"secret_access": 0.05})
    assert fused["secret_access"] < 0.5


def test_ml_weight_applied():
    ev = [Evidence("data_exfiltration", 0.3, [1])]
    fused = fusion.fuse(ev, {"data_exfiltration": 1.0}, {})
    expected = 1 - (1 - 0.3) * (1 - config.W_ML)
    assert abs(fused["data_exfiltration"] - expected) < 1e-6


def test_decide_thresholds_and_reason():
    fused = {c: 0.0 for c in fusion.VALID_CATEGORIES}
    fused["destructive_command"] = 0.9
    ev = [Evidence("destructive_command", 0.9, [3], "rm -rf / (T1485)")]
    cats, risk, lines, reason = fusion.decide(fused, ev, lang="bash")
    assert cats == ["destructive_command"]
    assert risk >= 0.5
    assert 3 in lines
    assert reason.startswith("Blocked:") and "line 3" in reason


def test_decide_allow_reason():
    fused = {c: 0.01 for c in fusion.VALID_CATEGORIES}
    cats, risk, lines, reason = fusion.decide(fused, [], lang="python", ml_max=0.03)
    assert cats == [] and risk < 0.5 and lines == []
    assert reason.startswith("Allowed:")


def test_thresholds_loaded_from_file():
    th = fusion.load_thresholds()
    assert set(th) == fusion.VALID_CATEGORIES
    assert all(0.0 <= v <= 1.0 for v in th.values())


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
    print(f"\ntest_fusion: {len(tests) - failures}/{len(tests)} passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(_main())
