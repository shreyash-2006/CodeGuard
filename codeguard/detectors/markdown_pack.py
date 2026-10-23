"""
detectors/markdown_pack.py — Markdown-specific risks.

Fenced code blocks are already scanned by the language-agnostic detectors
(their content is part of the document). This pack adds link-level checks:
dangerous schemes and link-text/href mismatch (phishing).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from codeguard.detectors.base import Context, Evidence, lines_matching

_MD_LINK = re.compile(r"\[([^\]]{0,200})\]\s*\(\s*([^)\s]{1,200})")
_DANGEROUS_LINK = re.compile(r"\]\(\s*(javascript:|data:text/html|vbscript:|file:)", re.IGNORECASE)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def detect_markdown_pack(ctx: Context) -> list[Evidence]:
    if ctx.language != "markdown" and not _MD_LINK.search(ctx.code):
        return []
    code = ctx.code
    results: list[Evidence] = []

    if _DANGEROUS_LINK.search(code):
        results.append(Evidence("obfuscated_execution", 0.85, lines_matching(_DANGEROUS_LINK, code),
                                "Markdown link with a dangerous scheme (javascript:/data:) (T1204)",
                                rule_id="MD_DANGEROUS_LINK"))

    # Link text shows one URL but href points elsewhere
    for m in _MD_LINK.finditer(code):
        text, href = m.group(1), m.group(2)
        text_host = _host(text) if "//" in text else ""
        href_host = _host(href)
        if text_host and href_host and text_host != href_host:
            line = code[: m.start()].count("\n") + 1
            results.append(Evidence("data_exfiltration", 0.75, [line],
                                    f"Markdown link text ({text_host}) does not match href ({href_host}) (phishing)",
                                    rule_id="MD_LINK_MISMATCH"))
            break
    return results
