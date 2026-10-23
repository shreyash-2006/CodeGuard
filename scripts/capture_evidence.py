"""
scripts/capture_evidence.py — regenerate the raw evidence in deliverables/.

Runs the demo + evaluation scripts and writes ASCII-safe, ANSI-free captures
plus copies of the JSON metrics.

    python scripts/capture_evidence.py
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
OUT = ROOT / "deliverables"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_REPLACEMENTS = {
    "═": "=", "─": "-", "│": "|", "·": "*",
    "✓": "[OK]", "✗": "[X]", "→": "->", "≥": ">=", "≤": "<=",
    "—": "-", "–": "-", "…": "...", "“": '"', "”": '"', "’": "'",
}

COMMANDS = [
    ([sys.executable, "-X", "utf8", "demo/intercept_check.py"], "evidence_interception.txt"),
    ([sys.executable, "-X", "utf8", "eval/run_eval.py", "codeguard_dev.jsonl"], "evidence_dev_eval.txt"),
    ([sys.executable, "-X", "utf8", "eval/latency.py"], "evidence_latency.txt"),
    ([sys.executable, "-X", "utf8", "eval/adversarial.py"], "evidence_adversarial.txt"),
]

COPIES = [
    (ROOT / "eval" / "eval_report.json", "evidence_dev_report.json"),
    (ROOT / "models" / "metrics.json", "evidence_holdout_metrics.json"),
]


def _clean(text: str) -> str:
    text = _ANSI.sub("", text)
    for src, dst in _REPLACEMENTS.items():
        text = text.replace(src, dst)
    # drop any remaining non-ASCII
    return text.encode("ascii", "ignore").decode("ascii")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for cmd, name in COMMANDS:
        print("running:", " ".join(cmd[1:]))
        proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True)
        text = _clean(proc.stdout.decode("utf-8", "replace"))
        (OUT / name).write_text(text, encoding="utf-8")
    for src, name in COPIES:
        if src.exists():
            shutil.copyfile(src, OUT / name)
    print(f"wrote evidence to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
