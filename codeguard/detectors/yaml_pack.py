"""
detectors/yaml_pack.py — YAML / CI / Kubernetes-specific risks.
"""
from __future__ import annotations

import re

from codeguard.detectors.base import Context, Evidence, lines_matching

_K8S_PRIV = re.compile(
    r"(privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true|hostNetwork\s*:\s*true|"
    r"hostPID\s*:\s*true|hostIPC\s*:\s*true|hostPath\s*:\s*(?:$|\n)|runAsUser\s*:\s*0\b|"
    r"(?:add|capabilities)\s*:\s*(?:\[|\n)?[^\n]*(SYS_ADMIN|NET_ADMIN|SYS_PTRACE))",
    re.IGNORECASE | re.MULTILINE,
)
_GH_EXPR_INJECT = re.compile(r"^\s*(?:-\s*)?run\s*:\s*[^\n]*\$\{\{\s*github\.event", re.IGNORECASE | re.MULTILINE)
_PULL_TARGET = re.compile(r"\bpull_request_target\b", re.IGNORECASE)
_PR_HEAD_CHECKOUT = re.compile(
    r"(github\.event\.pull_request\.head|ref:\s*\$\{\{\s*github\.head_ref)",
    re.IGNORECASE,
)
_YAML_PYOBJECT = re.compile(r"!!python/object/apply", re.IGNORECASE)
_ALIAS_REF = re.compile(r"\*\w+")
_ANCHOR = re.compile(r"&\w+")


def detect_yaml_pack(ctx: Context) -> list[Evidence]:
    code = ctx.code
    looks_yaml = ctx.language == "yaml" or bool(_GH_EXPR_INJECT.search(code)) or bool(_K8S_PRIV.search(code))
    if not looks_yaml:
        return []
    results: list[Evidence] = []

    if _K8S_PRIV.search(code):
        results.append(Evidence("persistence_or_privesc", 0.85, lines_matching(_K8S_PRIV, code),
                                "Privileged container / host namespace escalation (T1611)",
                                rule_id="YAML_K8S_PRIV"))
    if _GH_EXPR_INJECT.search(code):
        results.append(Evidence("destructive_command", 0.9, lines_matching(_GH_EXPR_INJECT, code),
                                "Untrusted github.event data interpolated into run: (T1059)",
                                rule_id="YAML_GH_EXPR"))
    if _PULL_TARGET.search(code) and _PR_HEAD_CHECKOUT.search(code):
        results.append(Evidence("persistence_or_privesc", 0.85, lines_matching(_PULL_TARGET, code),
                                "pull_request_target checks out untrusted PR head (T1195)",
                                rule_id="YAML_PULL_TARGET"))
    if _YAML_PYOBJECT.search(code):
        results.append(Evidence("obfuscated_execution", 0.97, lines_matching(_YAML_PYOBJECT, code),
                                "YAML python/object/apply tag executes Python (T1059)",
                                rule_id="YAML_PYOBJECT", hard_block=True))

    # Alias bomb (billion laughs)
    if len(_ALIAS_REF.findall(code)) > 30 and _ANCHOR.search(code):
        results.append(Evidence("resource_exhaustion", 0.8, lines_matching(_ALIAS_REF, code),
                                "YAML alias bomb (billion laughs) (T1499)", rule_id="YAML_ALIAS_BOMB"))
    return results
