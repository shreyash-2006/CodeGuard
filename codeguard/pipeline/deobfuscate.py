"""
pipeline/deobfuscate.py — iterative deobfuscation with per-layer line maps.

Transforms (up to MAX_DEPTH passes): base64 (+zlib), \\xNN hex, chr(N),
string-concat folding, import-alias resolution, rot13, URL decoding,
reversed strings, and shell obfuscation normalization (${IFS}, $'\\xNN',
line continuations).

Each Layer keeps `line_map`, so a hit in a decoded layer can be mapped back
to the original line of the encoded blob it came from.
"""
from __future__ import annotations

import base64
import codecs
import re
import urllib.parse
import zlib
from dataclasses import dataclass

_MAX_DEPTH = 4

# ── Patterns ─────────────────────────────────────────────────────────────────
_B64_CALL = re.compile(r"""b64decode\s*\(\s*['"]([A-Za-z0-9+/=]{8,})['"]\s*\)""")
_B64_LITERAL = re.compile(r"""['"]([A-Za-z0-9+/]{24,}={0,2})['"]""")
_HEX_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_CHR_RE = re.compile(r"chr\((\d+)\)")
_STR_CONCAT = re.compile(r"""['"](\w+)['"]\s*\+\s*['"](\w+)['"]""")
_IMPORT_AS = re.compile(r"import\s+(\w+)\s+as\s+(\w+)")
_ROT13_CALL = re.compile(r"""codecs\.decode\(\s*['"]([^'"]+)['"]\s*,\s*['"]rot13['"]\s*\)""")
_PERCENT_LIT = re.compile(r"""['"]([^'"]*%[0-9a-fA-F]{2}[^'"]*)['"]""")
_REVERSE_SLICE = re.compile(r"""['"]([^'"]+)['"]\s*\[\s*::\s*-1\s*\]""")
_REVERSE_JOIN = re.compile(r"""''\.join\(reversed\(\s*['"]([^'"]+)['"]\s*\)\)""")
_DOLLAR_HEX = re.compile(r"""\$\'((?:\\x[0-9a-fA-F]{2})+)\'""")
_SHELL_IFS = re.compile(r"\$\{?IFS\}?")
_LINE_CONT = re.compile(r"\\\n")


@dataclass
class Layer:
    text: str
    line_map: list[int]   # index i → original 1-based line for line i
    kind: str


def _identity_map(text: str) -> list[int]:
    return list(range(1, text.count("\n") + 2))


def _cmap_from_line_map(text: str, line_map: list[int]) -> list[int]:
    """Expand a per-line map to a per-character map."""
    cm: list[int] = []
    for i, line in enumerate(text.split("\n")):
        cm.extend([line_map[i] if i < len(line_map) else (line_map[-1] if line_map else 1)] * len(line))
        if i < text.count("\n"):
            cm.append(line_map[i] if i < len(line_map) else 1)  # the '\n'
    return cm


def _line_map_from_cmap(text: str, cm: list[int]) -> list[int]:
    lm: list[int] = []
    idx = 0
    for line in text.split("\n"):
        lm.append(cm[idx] if idx < len(cm) else (cm[-1] if cm else 1))
        idx += len(line) + 1
    return lm


def _apply_cm(text: str, cm: list[int], pattern: re.Pattern, repl_fn):
    """Apply a regex transform while tracking a per-char original-line map."""
    out_chars: list[str] = []
    out_cm: list[int] = []
    pos = 0
    for m in pattern.finditer(text):
        out_chars.append(text[pos:m.start()])
        out_cm.extend(cm[pos:m.start()])
        repl = repl_fn(m)
        if repl is None:
            out_chars.append(m.group(0))
            out_cm.extend(cm[m.start():m.end()])
        else:
            out_chars.append(repl)
            out_cm.extend([cm[m.start()] if m.start() < len(cm) else 1] * len(repl))
        pos = m.end()
    out_chars.append(text[pos:])
    out_cm.extend(cm[pos:])
    return "".join(out_chars), out_cm


# ── Individual transforms ────────────────────────────────────────────────────
def _dec_b64(s: str) -> str | None:
    try:
        data = base64.b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return None
    if data[:2] == b"\x1f\x8b" or data[:1] == b"\x78":
        try:
            data = zlib.decompress(data)
        except Exception:
            pass
    try:
        dec = data.decode("utf-8")
    except Exception:
        return None
    if not dec.strip() or len(dec.strip()) < 4:
        return None
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in dec)
    if printable < len(dec) * 0.9:
        return None
    return dec


def _t_base64(text: str, cm: list[int]):
    def repl(m):
        dec = _dec_b64(m.group(1))
        return repr(dec) if dec is not None else None

    text, cm = _apply_cm(text, cm, _B64_CALL, repl)
    text, cm = _apply_cm(text, cm, _B64_LITERAL, repl)
    return text, cm


def _t_hex(text, cm):
    return _apply_cm(text, cm, _HEX_RE, lambda m: chr(int(m.group(1), 16)))


def _t_chr(text, cm):
    def repl(m):
        try:
            return repr(chr(int(m.group(1))))
        except Exception:
            return None
    return _apply_cm(text, cm, _CHR_RE, repl)


def _t_concat(text, cm):
    return _apply_cm(text, cm, _STR_CONCAT, lambda m: f"'{m.group(1)}{m.group(2)}'")


def _t_alias(text, cm):
    aliases = {m.group(2): m.group(1) for m in _IMPORT_AS.finditer(text)}
    for alias, real in aliases.items():
        text, cm = _apply_cm(text, cm, re.compile(rf"\b{re.escape(alias)}\."), lambda m, real=real: f"{real}.")
    return text, cm


def _t_rot13(text, cm):
    return _apply_cm(text, cm, _ROT13_CALL, lambda m: repr(codecs.decode(m.group(1), "rot13")))


def _t_url(text, cm):
    def repl(m):
        inner = m.group(1)
        if len(re.findall(r"%[0-9a-fA-F]{2}", inner)) < 2:
            return None
        return "'" + urllib.parse.unquote(inner) + "'"
    return _apply_cm(text, cm, _PERCENT_LIT, repl)


def _t_reverse(text, cm):
    text, cm = _apply_cm(text, cm, _REVERSE_SLICE, lambda m: repr(m.group(1)[::-1]))
    text, cm = _apply_cm(text, cm, _REVERSE_JOIN, lambda m: repr(m.group(1)[::-1]))
    return text, cm


def _t_shell(text, cm):
    def dollar(m):
        body = m.group(1)
        try:
            chars = bytes(int(x, 16) for x in re.findall(r"\\x([0-9a-fA-F]{2})", body)).decode("latin-1")
            return "'" + chars + "'"
        except Exception:
            return None
    text, cm = _apply_cm(text, cm, _DOLLAR_HEX, dollar)
    text, cm = _apply_cm(text, cm, _SHELL_IFS, lambda m: " " if m.group(0).startswith("${") or m.group(0) in ("$IFS", "${IFS}") else None)
    text, cm = _apply_cm(text, cm, _LINE_CONT, lambda m: "")
    return text, cm


_TRANSFORMS = [
    ("base64", _t_base64),
    ("hex", _t_hex),
    ("chr", _t_chr),
    ("concat", _t_concat),
    ("alias", _t_alias),
    ("rot13", _t_rot13),
    ("url", _t_url),
    ("reverse", _t_reverse),
    ("shell", _t_shell),
]


# ── Public API ───────────────────────────────────────────────────────────────
def deobfuscate_layers(code: str) -> list[Layer]:
    """Return the chain of layers: [original, decoded…] with line maps."""
    layers: list[Layer] = [Layer(text=code, line_map=_identity_map(code), kind="original")]
    text, cm = code, _cmap_from_line_map(code, _identity_map(code))

    for _ in range(_MAX_DEPTH):
        changed_kinds: list[str] = []
        for kind, fn in _TRANSFORMS:
            before = text
            text, cm = fn(text, cm)
            if text != before:
                changed_kinds.append(kind)
        if text == layers[-1].text:
            break
        lm = _line_map_from_cmap(text, cm)
        layers.append(Layer(text=text, line_map=lm, kind="+".join(changed_kinds) or "pass"))
    return layers


def deobfuscate(code: str) -> str:
    return deobfuscate_layers(code)[-1].text


def deobfuscate_with_meta(code: str) -> tuple[str, int]:
    """Return (decoded_text, number_of_non_trivial_passes)."""
    layers = deobfuscate_layers(code)
    return layers[-1].text, len(layers) - 1


def resolve_line(layers: list[Layer], layer_index: int, line: int) -> int:
    """Map a 1-based line in layers[layer_index] back to the original line."""
    cur = line
    for idx in range(layer_index, 0, -1):
        lm = layers[idx].line_map
        if lm:
            cur = lm[min(max(cur, 1), len(lm)) - 1]
    return cur


def describe_layers(layers: list[Layer]) -> str:
    """Human summary of the transform chain, e.g. 'base64 → eval'."""
    kinds = [ly.kind for ly in layers[1:] if ly.kind and ly.kind != "pass"]
    return " → ".join(kinds) if kinds else ""
