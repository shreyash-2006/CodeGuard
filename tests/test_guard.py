"""
tests/test_guard.py — interception guarantees.

  * allow  → guarded function runs
  * block  → guarded function NEVER runs
  * guard errors fail closed
  * safe_exec runs allowed code and refuses blocked code

Runs as a plain script or under pytest.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard import guard
from codeguard.guard import BlockedByCodeGuard, check, guarded, safe_exec

_UNSAFE = "import os; os.system('rm -rf /')"
_SAFE = "x = 1 + 1"


def test_check_never_raises():
    for code in ["", None, 0, "import os"]:
        result = check(code)
        assert result["verdict"] in ("block", "allow")


def test_block_raises():
    try:
        safe_exec(_UNSAFE)
        assert False, "safe_exec did not block unsafe code"
    except BlockedByCodeGuard as exc:
        assert exc.result["verdict"] == "block"


def test_guarded_runs_on_allow():
    ran = {"n": 0}

    @guarded
    def run(code):
        ran["n"] += 1
        return "ok"

    assert run(_SAFE) == "ok"
    assert ran["n"] == 1


def test_guarded_never_runs_on_block():
    ran = {"n": 0}

    @guarded
    def run(code):
        ran["n"] += 1

    try:
        run(_UNSAFE)
        assert False, "guarded ran blocked code"
    except BlockedByCodeGuard:
        pass
    assert ran["n"] == 0, "blocked code was executed!"


def test_safe_exec_runner_called_only_when_allowed():
    calls = {"n": 0}

    def runner(code, **kw):
        calls["n"] += 1
        return "ran"

    assert safe_exec(_SAFE, runner=runner) == "ran"
    assert calls["n"] == 1
    try:
        safe_exec(_UNSAFE, runner=runner)
    except BlockedByCodeGuard:
        pass
    assert calls["n"] == 1, "runner was called for blocked code!"


def test_guard_fails_closed_on_error(monkeypatch=None):
    """If the analyzer explodes, the guard must block."""
    original = guard.analyze

    def boom(*a, **k):
        raise RuntimeError("simulated engine failure")

    guard.analyze = boom
    try:
        result = check("print(1)")
        assert result["verdict"] == "block", "guard did not fail closed"
    finally:
        guard.analyze = original


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
    print(f"\ntest_guard: {len(tests) - failures}/{len(tests)} passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(_main())
