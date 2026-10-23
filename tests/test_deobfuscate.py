"""
tests/test_deobfuscate.py — layered decoding + line maps.

Runs as a plain script or under pytest.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from codeguard.pipeline.deobfuscate import (
    deobfuscate,
    deobfuscate_layers,
    deobfuscate_with_meta,
    resolve_line,
)


def test_base64_decoded():
    out = deobfuscate("exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk='))")
    assert "os.system" in out or "import os" in out


def test_hex_decoded():
    assert "rm" in deobfuscate("os.system('\\x72\\x6d')")


def test_chr_python_concat():
    out = deobfuscate("eval(chr(49)+chr(43)+chr(49))")
    assert "1" in out


def test_alias_resolution():
    out = deobfuscate("import os as o\no.system('ls')")
    assert "os.system" in out


def test_concat_fold():
    assert "subprocess" in deobfuscate("__import__('sub'+'process')")


def test_shell_ifs_normalization():
    assert "rm -rf /" in deobfuscate("rm${IFS}-rf${IFS}/")


def test_layers_and_line_map():
    layers = deobfuscate_layers("x = 1\nexec(base64.b64decode('aW1wb3J0IG9z'))\n")
    assert layers[0].kind == "original"
    assert len(layers) >= 2
    # the decoded blob belongs to original line 2
    assert resolve_line(layers, 1, 2) == 2


def test_meta_counts_passes():
    _, n = deobfuscate_with_meta("__import__('sub'+'process')")
    assert n >= 1


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
    print(f"\ntest_deobfuscate: {len(tests) - failures}/{len(tests)} passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(_main())
