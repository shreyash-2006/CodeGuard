"""
detectors/bash_pack.py — shell-specific persistence / anti-forensics / history.
"""
from __future__ import annotations

import re

from codeguard.detectors.base import Context, Evidence, lines_matching

_HISTORY_TAMPER = re.compile(
    r"(history\s+-c\b|unset\s+HISTFILE|export\s+HISTFILE=/dev/null|HISTSIZE=0|"
    r"shred[^\n]*\.bash_history|rm[^\n]*\.bash_history)",
    re.IGNORECASE,
)
_DISABLE_SECURITY = re.compile(
    r"(setenforce\s+0|systemctl\s+(stop|disable)\s+(firewalld|apparmor|selinux)|"
    r"iptables\s+-F\b|ufw\s+disable)",
    re.IGNORECASE,
)
_SCHEDULED_PERSIST = re.compile(
    r"(echo[^\n]*\|\s*crontab\s+-|>\s*/etc/cron\.(d|daily|hourly)|"
    r"at\s+now\s*\+|>\s*/etc/rc\.local)",
    re.IGNORECASE,
)


def detect_bash_pack(ctx: Context) -> list[Evidence]:
    if ctx.language not in ("bash", "unknown"):
        return []
    code = ctx.code
    results: list[Evidence] = []

    if _HISTORY_TAMPER.search(code):
        results.append(Evidence("persistence_or_privesc", 0.75, lines_matching(_HISTORY_TAMPER, code),
                                "Shell-history tampering / anti-forensics (T1070.003)",
                                rule_id="BASH_HISTORY_TAMPER"))
    if _DISABLE_SECURITY.search(code):
        results.append(Evidence("persistence_or_privesc", 0.8, lines_matching(_DISABLE_SECURITY, code),
                                "Disabling host security controls (T1562.001)",
                                rule_id="BASH_DISABLE_SECURITY"))
    if _SCHEDULED_PERSIST.search(code):
        results.append(Evidence("persistence_or_privesc", 0.8, lines_matching(_SCHEDULED_PERSIST, code),
                                "Scheduled-task persistence (T1053.003)",
                                rule_id="BASH_SCHED_PERSIST"))
    return results
