"""
tests/test_markdown_yaml_lines.py — line-number correctness for embedded blocks.

A malicious command inside a Markdown fence or a YAML `run:` block must be
reported at its ORIGINAL line number in the document.

Runs as a plain script or under pytest.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard.engine import analyze
from codeguard.ml_model import ensure_model_ready
from codeguard.pipeline.segment import segment

_MODEL = None


def _model():
    global _MODEL
    if _MODEL is None:
        _MODEL = ensure_model_ready()
    return _MODEL


def test_segment_line_map():
    md = "# Title\n\n```bash\nrm -rf /\n```\n"
    segs = segment(md, "markdown")
    fences = [s for s in segs if s.kind == "fence"]
    assert fences and fences[0].line == 3, [(s.kind, s.line) for s in segs]


def test_markdown_fence_blocks_with_correct_line():
    md = "# Notes\n\nSome prose.\n\n```bash\nrm -rf /\n```\n"
    result = analyze(md, model=_model())
    assert result["verdict"] == "block"
    assert 6 in result["vulnerable_lines"], result["vulnerable_lines"]


def test_yaml_run_block_line():
    y = "name: x\non: [push]\njobs:\n  j:\n    steps:\n      - run: rm -rf /\n"
    segs = segment(y, "yaml")
    runs = [s for s in segs if s.kind == "yaml_script"]
    assert runs and runs[0].line == 6
    result = analyze(y, model=_model())
    assert result["verdict"] == "block"
    assert 6 in result["vulnerable_lines"], result["vulnerable_lines"]


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
    print(f"\ntest_markdown_yaml_lines: {len(tests) - failures}/{len(tests)} passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(_main())
