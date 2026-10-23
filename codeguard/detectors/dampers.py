"""
detectors/dampers.py — benign-damper multipliers.

A damper suppresses a category's rule confidence for code that *looks* like an
attack but is a known benign pattern (parameterized SQL, ast.literal_eval,
read-only crontab, allowlisted hosts, docstring credentials, …).

0.0 = fully suppressed, 1.0 = no dampening.
"""
from __future__ import annotations

import re

# Parameterized SQL — safe execute() calls (literal SQL string with tuple args)
_SQL_PARAM = re.compile(r"execute\s*\(\s*['\"][^'\"]+['\"],\s*\(", re.IGNORECASE)
_SQL_PARAM_VAR = re.compile(r"execute\s*\(\s*\w+,\s*\(", re.IGNORECASE)
_FSTRING_SQL_PLACEHOLDER = re.compile(r"\w{1,64}\s*=\s*f['\"]", re.IGNORECASE)
_AST_LITERAL = re.compile(r"\bast\.literal_eval\b")
_CRONTAB_LIST = re.compile(r"crontab\s+-l\b")
_THREAD_POOL_BOUNDED = re.compile(r"MAX_WORKERS\s*=\s*\d+|ThreadPoolExecutor\s*\(\s*max_workers")
_OWN_HOST = re.compile(
    r"(api\.\w+\.com|myservice\.|localhost(?!.*attacker)|127\.0\.0\.1(?!.*redis|.*gopher)|partner-service)",
    re.IGNORECASE,
)
_ALLOWLIST_VALIDATE = re.compile(r"(startswith|in ALLOWED|allowlist)", re.IGNORECASE)
_SAFE_DELETE = re.compile(r"(DELETE|UPDATE).{0,80}WHERE.{0,40}(\?|%s|\$\d+)", re.IGNORECASE | re.DOTALL)
_DOCSTRING_CRED = re.compile(r'""".*?(password|hunter2|credential).*?"""', re.DOTALL | re.IGNORECASE)
_SETATTR_SAFE = re.compile(r"setattr.+allowed_fields|allowed_fields.+setattr", re.DOTALL | re.IGNORECASE)
_CORRECT_PKG = re.compile(r"(colorama|numpy|requests==\d|click|tabulate|rich)", re.IGNORECASE)
_FSTRING_SQL_SAFE = re.compile(
    r"f['\"]SELECT.+FROM.+WHERE.+%s['\"]|query_template\s*=\s*f['\"]", re.IGNORECASE
)
_CONFIG_SETTINGS = re.compile(
    r"~/\.config/[\w.-]+/(settings|config|preferences|options)\.(json|ya?ml|toml|ini)",
    re.IGNORECASE,
)
_OWN_LOG_API = re.compile(
    r"(LOG_ENDPOINT|/logs|/events|/metrics).*requests\.post|requests\.post.*(/logs|/events|/metrics)",
    re.IGNORECASE | re.DOTALL,
)


def apply_dampers(code: str) -> dict[str, float]:
    dampers: dict[str, float] = {}

    if _SQL_PARAM.search(code):
        _FORMAT_INJECTION = re.compile(
            r"['\"].*(SELECT|DELETE|UPDATE|INSERT).*['\"]\.format\s*\(", re.IGNORECASE
        )
        if not _FORMAT_INJECTION.search(code):
            dampers["destructive_command"] = 0.05
        dampers["data_exfiltration"] = 0.1

    if _FSTRING_SQL_PLACEHOLDER.search(code) and (_SQL_PARAM.search(code) or _SQL_PARAM_VAR.search(code)):
        dampers["data_exfiltration"] = min(dampers.get("data_exfiltration", 1.0), 0.02)

    if _AST_LITERAL.search(code):
        dampers["obfuscated_execution"] = 0.05

    if _CRONTAB_LIST.search(code) and "crontab" in code and "-e" not in code and "-r" not in code:
        dampers["persistence_or_privesc"] = 0.05

    if _THREAD_POOL_BOUNDED.search(code):
        dampers["resource_exhaustion"] = 0.1

    if _SAFE_DELETE.search(code):
        dampers["destructive_command"] = min(dampers.get("destructive_command", 1.0), 0.05)

    if _DOCSTRING_CRED.search(code):
        dampers["secret_access"] = min(dampers.get("secret_access", 1.0), 0.1)

    if _SETATTR_SAFE.search(code):
        dampers["obfuscated_execution"] = min(dampers.get("obfuscated_execution", 1.0), 0.05)

    if _CONFIG_SETTINGS.search(code):
        dampers["secret_access"] = min(dampers.get("secret_access", 1.0), 0.05)

    if _OWN_LOG_API.search(code):
        dampers["data_exfiltration"] = min(dampers.get("data_exfiltration", 1.0), 0.05)
        dampers["ssrf_network_exfil"] = min(dampers.get("ssrf_network_exfil", 1.0), 0.1)

    return dampers
