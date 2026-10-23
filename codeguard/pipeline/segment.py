"""
pipeline/segment.py — split a snippet into comments, strings and embedded
code blocks, each carrying its original 1-based start line.

Embedded blocks: Markdown fences, YAML script fields, bash heredocs,
`bash -c` / `sh -c` arguments, and `eval(...)` / `exec(...)` arguments.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from codeguard.pipeline.preprocess import preprocess


@dataclass
class Segment:
    kind: str                 # comment | string | docstring | fence | yaml_script |
                              # heredoc | shell_c | eval_arg | prose
    text: str
    line: int                 # 1-based original line
    language: str = ""
    meta: dict = field(default_factory=dict)


def _line_of(code: str, idx: int) -> int:
    return code[:idx].count("\n") + 1


# ── Patterns ─────────────────────────────────────────────────────────────────
_FENCE = re.compile(r"^```\s*([\w+-]*)[ \t]*\n(.*?)(?:\n```|$)", re.MULTILINE | re.DOTALL)
_YAML_SCRIPT_INLINE = re.compile(
    r"^[ \t-]*(run|script|command|runcmd|entrypoint|args|shell)\s*:\s*(\S.*)$",
    re.MULTILINE | re.IGNORECASE,
)
_YAML_BLOCK = re.compile(
    r"^[ \t-]*(run|script|command|runcmd|entrypoint|args)\s*:\s*[|>][-+]?\s*\n((?:[ \t]+.*\n?)+)",
    re.MULTILINE | re.IGNORECASE,
)
_HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?\s*\n(.*?)\n\s*\1\b", re.DOTALL)
_SHELL_C = re.compile(r"\b(?:ba)?sh\s+-c\s+(['\"])(.*?)\1", re.DOTALL)
_EVAL_ARG = re.compile(r"\b(?:eval|exec)\s*\(\s*([ru]?['\"])(.*?)\1", re.DOTALL)
_COMMENT_HASH = re.compile(r"(?m)^[ \t]*#.*$|[ \t]#[ \t].*$")
_COMMENT_SLASH = re.compile(r"(?<!:)//[^\n]*$", re.MULTILINE)
_COMMENT_C = re.compile(r"/\*.*?\*/", re.DOTALL)
_COMMENT_HTML = re.compile(r"<!--.*?-->", re.DOTALL)
_TRIPLE_STR = re.compile(r"(\"\"\".*?\"\"\"|'''.*?''')", re.DOTALL)
_STRING = re.compile(r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')")


def segment(code: str, language: str = "unknown") -> list[Segment]:
    """Return a list of Segment objects with original line numbers."""
    try:
        code, _ = preprocess(code)
    except Exception:
        pass

    segments: list[Segment] = []

    # ── Markdown fenced code blocks ──────────────────────────────────────────
    for m in _FENCE.finditer(code):
        lang = (m.group(1) or "").strip().lower()
        body = m.group(2) or ""
        if lang in ("", "bash", "sh", "shell"):
            seg_lang = "bash" if lang else ""
        elif lang in ("python", "py"):
            seg_lang = "python"
        elif lang in ("javascript", "js", "node"):
            seg_lang = "javascript"
        elif lang in ("yaml", "yml"):
            seg_lang = "yaml"
        elif lang == "sql":
            seg_lang = "sql"
        else:
            seg_lang = lang
        segments.append(Segment("fence", body, _line_of(code, m.start()), seg_lang))

    # ── YAML script fields ───────────────────────────────────────────────────
    for m in _YAML_BLOCK.finditer(code):
        segments.append(Segment("yaml_script", m.group(2), _line_of(code, m.start()), "bash",
                                {"field": m.group(1)}))
    for m in _YAML_SCRIPT_INLINE.finditer(code):
        val = m.group(2).strip()
        if val.startswith(("|", ">")):
            continue
        segments.append(Segment("yaml_script", val, _line_of(code, m.start()), "bash",
                                {"field": m.group(1)}))

    # ── bash heredocs ────────────────────────────────────────────────────────
    for m in _HEREDOC.finditer(code):
        segments.append(Segment("heredoc", m.group(2), _line_of(code, m.start()), "bash"))

    # ── bash -c / sh -c ──────────────────────────────────────────────────────
    for m in _SHELL_C.finditer(code):
        segments.append(Segment("shell_c", m.group(2), _line_of(code, m.start()), "bash"))

    # ── eval()/exec() string arguments ───────────────────────────────────────
    for m in _EVAL_ARG.finditer(code):
        segments.append(Segment("eval_arg", m.group(2), _line_of(code, m.start()), "python"))

    # ── Comments (all syntaxes) ──────────────────────────────────────────────
    for pat in (_COMMENT_HASH, _COMMENT_SLASH, _COMMENT_C, _COMMENT_HTML):
        for m in pat.finditer(code):
            segments.append(Segment("comment", m.group(0), _line_of(code, m.start())))

    # ── Docstrings then plain strings ────────────────────────────────────────
    for m in _TRIPLE_STR.finditer(code):
        segments.append(Segment("docstring", m.group(1), _line_of(code, m.start())))
    for m in _STRING.finditer(code):
        segments.append(Segment("string", m.group(1), _line_of(code, m.start())))

    return segments


def text_of(segments: list[Segment], kinds: tuple[str, ...]) -> str:
    """Concatenate the text of segments whose kind is in `kinds`."""
    return "\n".join(s.text for s in segments if s.kind in kinds)
