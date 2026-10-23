"""
datagen.mutators — formatting-preserving mutation operators.

These change identifiers, quoting, whitespace, comments and embedding context
without removing the underlying malicious intent, so a robust detector keeps
firing. Used both to expand the dataset and by eval/adversarial.py.
"""
from __future__ import annotations

import random
import re

_IDENT = re.compile(r"\b(payload|data|path|cmd|result|tmp|stage|value|creds|secret|token)\b")


def add_comment_padding(code: str) -> str:
    pad = "# " + " ".join(["note"] * random.randint(2, 8)) + "\n"
    return pad + code


def change_whitespace(code: str) -> str:
    code = code.replace("    ", "\t")
    code = re.sub(r"[ \t]+,", ",", code)
    return re.sub(r"\n{3,}", "\n\n", code)


def wrap_function(code: str, language: str = "python") -> str:
    indented = "\n".join("    " + ln for ln in code.split("\n"))
    if language in ("javascript",):
        return f"function _m() {{\n{indented}\n}}"
    return f"def _mutated():\n{indented}\n"


def wrap_main(code: str, language: str = "python") -> str:
    if language != "python":
        return code
    indented = "\n".join("    " + ln for ln in code.split("\n"))
    return f"if __name__ == '__main__':\n{indented}\n"


def embed_markdown_fence(code: str, language: str = "python") -> str:
    tag = "python" if language in ("python",) else ("bash" if language == "bash" else "")
    return f"# Example\n\n```{tag}\n{code}\n```\n"


def embed_yaml_run(code: str, language: str = "bash") -> str:
    indented = "\n".join("        " + ln for ln in code.split("\n"))
    return f"name: x\non: [push]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n{indented}\n"


def rename_identifiers(code: str) -> str:
    return _IDENT.sub(lambda m: m.group(1) + "_x", code)


def swap_requests_urllib(code: str) -> str:
    if "requests.post(" in code:
        return code.replace("requests.post(", "urllib.request.urlopen(")
    return code


def split_string(code: str) -> str:
    m = re.search(r"'([A-Za-z0-9_./\-]{6,40})'", code)
    if not m:
        return code
    s = m.group(1)
    mid = len(s) // 2
    return code.replace(f"'{s}'", f"'{s[:mid]}' + '{s[mid:]}'", 1)


def add_trailing_comments(code: str) -> str:
    return "\n".join(ln + ("  # x" if random.random() < 0.3 else "") for ln in code.split("\n"))


def truncate_tail(code: str) -> str:
    lines = code.split("\n")
    return "\n".join(lines[:-1]) if len(lines) > 1 else code


_OPERATORS = [
    add_comment_padding,
    change_whitespace,
    rename_identifiers,
    add_trailing_comments,
    split_string,
    swap_requests_urllib,
]


def mutate(code: str, language: str = "unknown", n: int | None = None,
           rng: random.Random | None = None, structural: bool = True) -> str:
    """Apply 0..3 random operators (plus optional structural embedding)."""
    rng = rng or random
    ops = list(_OPERATORS)
    k = rng.randint(0, 3) if n is None else n
    rng.shuffle(ops)
    out = code
    for op in ops[:k]:
        try:
            out = op(out)
        except Exception:
            pass
    if structural:
        if rng.random() < 0.2:
            out = wrap_function(out, language)
        if rng.random() < 0.15:
            out = embed_markdown_fence(out, language)
        if rng.random() < 0.15:
            out = embed_yaml_run(out, language)
    return out
