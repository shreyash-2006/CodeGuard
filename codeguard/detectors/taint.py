"""
detectors/taint.py — lightweight intra-snippet data-flow (source → sink).

Python: AST-based. A sensitive source (credential/env read) assigned to a
variable that later reaches a network sink emits data_exfiltration at the sink
line and secret_access at the source line.
"""
from __future__ import annotations

import ast
import re

from codeguard.detectors.base import Context, Evidence
from codeguard.pipeline.parse import ast_calls, call_name

_SENSITIVE_PATH = re.compile(
    r"(\.aws/credentials|\.ssh/id_rsa|\.docker/config\.json|\.kube/config|"
    r"\.netrc|\.git-credentials|/etc/shadow|/etc/passwd|/proc/.*/environ|"
    r"\.env\b|credentials\.json|service-account\.json|wallet\.dat)",
    re.IGNORECASE,
)
_NET_SINKS = {
    "requests.post", "requests.put", "requests.patch", "requests.request",
    "urlopen", "urlretrieve", "httpx.post", "httpx.put", "aiohttp.post",
    "socket.send", "socket.sendall", "smtplib.smtp.sendmail", "sendmail",
}
_SHELL_SINKS = {"os.system", "subprocess.run", "subprocess.call", "subprocess.popen"}
_SOURCE_NAMES = {"environ", "getenv"}


def _node_has_source(node) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and _SENSITIVE_PATH.search(sub.value):
            return True
        if isinstance(sub, ast.Call):
            name = call_name(sub)
            if name in ("open", "read", "read_text", "readlines") and sub.args:
                a = sub.args[0]
                if isinstance(a, ast.Constant) and isinstance(a.value, str) and _SENSITIVE_PATH.search(a.value):
                    return True
            if name.endswith("environ.get") or name in ("environ", "getenv", "os.environ"):
                return True
        if isinstance(sub, ast.Attribute) and sub.attr in ("environ",):
            return True
    return False


def _references(node, names: set[str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in names:
            return True
    return False


def _sink_kind(call) -> str:
    name = call_name(call).lower()
    if name in _NET_SINKS or any(name.endswith(s) for s in ("requests.post", "requests.put", "requests.patch", "urlopen")):
        return "net"
    if name in _SHELL_SINKS:
        # only a sink if a curl/wget-like exfil is present
        for sub in ast.walk(call):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and re.search(r"(curl|wget|nc)\b", sub.value):
                return "shell"
    return ""


def detect_taint(ctx: Context) -> list[Evidence]:
    if ctx.language not in ("python", "unknown"):
        return []
    tree = ctx.parsed.get("python")
    if tree is None:
        return []

    tainted: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _node_has_source(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    tainted[tgt.id] = getattr(node, "lineno", 1)

    if not tainted:
        return []

    results: list[Evidence] = []
    for call in ast_calls(tree):
        kind = _sink_kind(call)
        if not kind:
            continue
        if not _references(call, set(tainted)):
            continue
        sink_line = getattr(call, "lineno", 1)
        src_line = min(tainted.values())
        results.append(Evidence("data_exfiltration", 0.9, [sink_line],
                                "Tainted sensitive source flows to a network sink (T1048)",
                                rule_id="TAINT_NET"))
        results.append(Evidence("secret_access", 0.8, [src_line],
                                "Sensitive source feeding an exfiltration flow (T1552)",
                                rule_id="TAINT_SOURCE"))
        break
    return results
