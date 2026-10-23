"""
guard.py — CodeGuard CLI wrapper and safe-execution guard.

Usage:
    python guard.py check <file_or_snippet>   # analyze a file or inline code
    python guard.py exec  <python_file>        # guarded execution (blocks if malicious)

The `exec` subcommand demonstrates the interception story:
  - If CodeGuard returns block → execution is refused (fail-closed)
  - If CodeGuard returns allow → subprocess is launched safely
  - On any internal error → fail-closed (refuse execution)
"""
from __future__ import annotations

import json
import subprocess
import sys
import os
from pathlib import Path

# Ensure the project root is on the path
sys.path.insert(0, str(Path(__file__).parent))

from codeguard.engine import analyze
from codeguard.ml_model import ensure_model_ready
from codeguard.guard import (  # re-export the guard API for backwards compatibility
    BlockedByCodeGuard,
    check,
    guarded,
    safe_exec,
)

_DEV_PATH = str(Path(__file__).parent / "codeguard_dev.jsonl")
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _load_model():
    return ensure_model_ready(dev_path=_DEV_PATH)


def _print_result(result: dict) -> None:
    verdict = result["verdict"]
    color = _RED if verdict == "block" else _GREEN
    print(f"\n{_BOLD}Verdict:{_RESET}        {color}{verdict.upper()}{_RESET}")
    print(f"{_BOLD}Risk score:{_RESET}     {result['risk_score']:.4f}")
    print(f"{_BOLD}Language:{_RESET}       {result['code_language']}")
    if result["categories"]:
        print(f"{_BOLD}Categories:{_RESET}     {', '.join(result['categories'])}")
    if result["reason"]:
        print(f"{_BOLD}Reason:{_RESET}         {result['reason'][:120]}")
    if result.get("vulnerable_lines"):
        print(f"{_BOLD}Flagged lines:{_RESET}  {result['vulnerable_lines']}")
    print()


def cmd_check(args: list[str]) -> int:
    """Analyze a file or inline code string."""
    if not args:
        print("Usage: guard.py check <file_or_code>", file=sys.stderr)
        return 2

    target = args[0]
    path = Path(target)
    if path.exists() and path.is_file():
        code = path.read_text(encoding="utf-8", errors="replace")
        print(f"Analyzing file: {path}")
    else:
        code = target
        print("Analyzing inline code snippet.")

    model = _load_model()
    result = analyze(code, model=model)
    _print_result(result)
    print(json.dumps(result, indent=2))
    return 0 if result["verdict"] == "allow" else 1


def cmd_exec(args: list[str]) -> int:
    """
    Guarded execution. Analyzes the target Python file first.
    If verdict == block → refuse execution (fail-closed).
    If verdict == allow → execute with subprocess.
    On internal error → fail-closed (refuse execution).
    """
    if not args:
        print("Usage: guard.py exec <python_file> [args...]", file=sys.stderr)
        return 2

    target = Path(args[0])
    if not target.exists():
        print(f"[guard] ERROR: file not found: {target}", file=sys.stderr)
        return 2

    code = target.read_text(encoding="utf-8", errors="replace")

    try:
        model = _load_model()
        result = analyze(code, model=model)
    except Exception as exc:
        # Fail-closed on any internal error
        print(f"{_RED}[guard] BLOCKED (fail-closed): analysis error — {exc}{_RESET}", file=sys.stderr)
        return 1

    _print_result(result)

    if result["verdict"] == "block":
        print(f"{_RED}{_BOLD}[guard] EXECUTION BLOCKED{_RESET}", file=sys.stderr)
        print(f"  Categories: {result['categories']}", file=sys.stderr)
        print(f"  Risk score: {result['risk_score']}", file=sys.stderr)
        return 1

    # Verdict == allow → execute
    print(f"{_GREEN}[guard] Execution ALLOWED — launching process...{_RESET}")
    proc = subprocess.run(
        [sys.executable] + args,
        capture_output=False,
    )
    return proc.returncode


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    cmd = sys.argv[1].lower()
    rest = sys.argv[2:]

    if cmd == "check":
        return cmd_check(rest)
    elif cmd == "exec":
        return cmd_exec(rest)
    else:
        print(f"Unknown command: {cmd}. Use 'check' or 'exec'.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
