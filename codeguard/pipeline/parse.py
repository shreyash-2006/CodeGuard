"""
pipeline/parse.py — best-effort structured parsing.

Every parser is optional and defensive: if a library is missing or the input
does not parse — or is too large / too complex to be worth parsing — we return
None and the detectors fall back to regex/token mode. Parsing failure NEVER
downgrades a snippet to allow on its own.
"""
from __future__ import annotations

import ast
import logging
import re
from typing import Any

# sqlglot is chatty about unsupported dialects; keep stdout clean.
logging.getLogger("sqlglot").setLevel(logging.CRITICAL)
try:
    logging.getLogger("sqlglot.parser").setLevel(logging.CRITICAL)
    logging.getLogger("sqlglot.generator").setLevel(logging.CRITICAL)
except Exception:
    pass

# Cheap "does this look like …" gates so we don't run expensive parsers blindly.
_LOOKS_SQL = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|GRANT|ALTER|TRUNCATE|COPY)\b", re.IGNORECASE)
_LOOKS_YAML = re.compile(r"(?m)^[ \t-]*\w[\w -]{0,80}:\s")
_LOOKS_MD = re.compile(r"(?m)^(#{1,6} |```|\s*[-*] |\[.+\]\()")
_SQL_COMPLEX = re.compile(r"\b(DECLARE|BEGIN|PROCEDURE|FUNCTION|TRIGGER|CURSOR)\b", re.IGNORECASE)

_SQL_MAX_LEN = 6000
_YAML_MAX_LEN = 20000
_MD_MAX_LEN = 50000

_MD_INSTANCE = None


def _markdown():
    global _MD_INSTANCE
    if _MD_INSTANCE is None:
        try:
            from markdown_it import MarkdownIt  # type: ignore
            _MD_INSTANCE = MarkdownIt("commonmark")
        except Exception:
            _MD_INSTANCE = False
    return _MD_INSTANCE or None


def parse_python(code: str):
    try:
        return ast.parse(code)
    except Exception:
        return None


def parse_sql(code: str):
    if len(code) > _SQL_MAX_LEN or _SQL_COMPLEX.search(code):
        return None  # regex fallback for complex/large SQL (keeps latency low)
    try:
        import sqlglot  # type: ignore
        return sqlglot.parse(code)
    except Exception:
        return None


def parse_yaml(code: str):
    if len(code) > _YAML_MAX_LEN:
        return None
    try:
        import yaml  # type: ignore
        return list(yaml.compose_all(code))  # compose_all, never yaml.load
    except Exception:
        return None


def parse_markdown(code: str):
    if len(code) > _MD_MAX_LEN:
        return None
    md = _markdown()
    if md is None:
        return None
    try:
        return md.parse(code)
    except Exception:
        return None


def parse_all(code: str, language: str = "unknown") -> dict[str, Any]:
    """Parse what is plausible for the detected language; None on failure."""
    out: dict[str, Any] = {"python": None, "sql": None, "yaml": None, "markdown": None}
    if language in ("python", "unknown"):
        out["python"] = parse_python(code)
    if language == "sql" or _LOOKS_SQL.search(code):
        out["sql"] = parse_sql(code)
    if language == "yaml" or _LOOKS_YAML.search(code):
        out["yaml"] = parse_yaml(code)
    if language == "markdown" or _LOOKS_MD.search(code):
        out["markdown"] = parse_markdown(code)
    return out


# ── AST helpers ──────────────────────────────────────────────────────────────
def ast_walk(tree) -> list:
    if tree is None:
        return []
    try:
        return list(ast.walk(tree))
    except Exception:
        return []


def ast_calls(tree):
    for node in ast_walk(tree):
        if isinstance(node, ast.Call):
            yield node


def call_name(call) -> str:
    try:
        f = call.func
        parts = []
        while isinstance(f, ast.Attribute):
            parts.append(f.attr)
            f = f.value
        if isinstance(f, ast.Name):
            parts.append(f.id)
        return ".".join(reversed(parts))
    except Exception:
        return ""


def literal_strings(tree) -> list[tuple[int, str]]:
    out = []
    for node in ast_walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append((getattr(node, "lineno", 0), node.value))
    return out
