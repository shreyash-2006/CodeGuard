"""
tests/test_langid.py — language identification.

Runs as a plain script or under pytest.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard.pipeline.langid import detect_language, detect_language_scored

CASES = [
    ("python", "def f(x):\n    return x + 1"),
    ("python", "import os\nclass A:\n    pass"),
    ("bash", "#!/bin/bash\nset -euo pipefail\necho hi"),
    ("bash", "rm -rf /"),
    ("javascript", "const x = require('fs');\nconsole.log(x);"),
    ("javascript", "const add = (a, b) => a + b;"),
    ("sql", "SELECT * FROM users WHERE id = 1;"),
    ("sql", "UPDATE accounts SET balance = 0;"),
    ("yaml", "name: ci\non:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest"),
    ("markdown", "# Title\n\nSome **bold** text and a [link](https://example.com)."),
]


def test_languages():
    for lang, code in CASES:
        got = detect_language(code)
        assert got == lang, f"{code!r} -> {got}, expected {lang}"


def test_unknown():
    assert detect_language("") == "unknown"
    assert detect_language("   ") == "unknown"
    assert detect_language("+ 42 xyz") == "unknown"


def test_confidence_bounds():
    for _, code in CASES:
        lang, conf = detect_language_scored(code)
        assert 0.0 <= conf <= 1.0


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
    print(f"\ntest_langid: {len(tests) - failures}/{len(tests)} passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(_main())
