"""
detectors/universal.py — language-agnostic detector packs.

Covers the categories whose stories are not tied to one language:
secret_access, data_exfiltration, destructive_command, obfuscated_execution,
persistence_or_privesc.
"""
from __future__ import annotations

import re

from codeguard.detectors.base import Context, Evidence, lines_matching


# ════════════════════════════════════════════════════════════════════════════
# SECRET_ACCESS  (T1552.x)
# ════════════════════════════════════════════════════════════════════════════
_SECRET_FILE_READ = re.compile(
    r"(~/\.aws/credentials|~/\.ssh|~/\.docker/config\.json|"
    r"/etc/passwd|/etc/shadow|~/.gnupg|PRIVATE KEY|client_secret|"
    r"\bid_rsa\b|AWS_SHARED_CREDENTIALS_FILE|~/\.git-credentials|~/\.netrc|~/\.kube/config)",
    re.IGNORECASE,
)
_GREP_SECRET = re.compile(r"grep\s+-[rR]?[^\n]*(password|secret|token|api[_-]?key)", re.IGNORECASE)
_HARDCODED_KEY = re.compile(
    r"(AKIA[0-9A-Z]{16}"
    r"|xox[bpoa]-\w{10,}"
    r"|aws_secret_access_key\s*=\s*['\"][^'\"]{16,}['\"]"
    r"|aws_access_key_id\s*=\s*['\"]AKIA[0-9A-Z]+['\"]"
    r"|password\s*=\s*['\"][^'\"]{4,}['\"])",
    re.IGNORECASE,
)
_NET_POST = re.compile(r"requests\.(post|put|patch)\s*\(", re.IGNORECASE)
_TELEMETRY_HOST = re.compile(
    r"(attacker\.|evil\.|c2\.|webhook\.|hooks\.attacker|example\.invalid|198\.51\.100\.|203\.0\.113\.)",
    re.IGNORECASE,
)


def detect_secret_access(ctx: Context) -> list[Evidence]:
    code = ctx.code
    results: list[Evidence] = []

    if _SECRET_FILE_READ.search(code):
        _ICMP_CONTEXT = re.compile(r"ping|icmp|hex\(\)|block\.hex", re.IGNORECASE)
        is_icmp_story = _ICMP_CONTEXT.search(code) and not _NET_POST.search(code)
        _AI_CONTEXT = re.compile(r"#.*id_rsa|NOTE TO.*AI|Ignore.*previous.*instruct", re.IGNORECASE | re.DOTALL)
        is_ai_comment = _AI_CONTEXT.search(code)

        if not is_icmp_story and not is_ai_comment:
            lines = lines_matching(_SECRET_FILE_READ, code)
            conf = 0.75
            if _NET_POST.search(code):
                conf = 0.95
            results.append(Evidence("secret_access", conf, lines,
                                    "Reads a sensitive credential file (T1552)",
                                    rule_id="SECRET_FILE_READ"))

    if _HARDCODED_KEY.search(code):
        _DOCSTRING_CTX = re.compile(r'""".{0,500}(password|hunter2|credential).{0,500}"""', re.DOTALL | re.IGNORECASE)
        if not _DOCSTRING_CTX.search(code):
            lines = lines_matching(_HARDCODED_KEY, code)
            results.append(Evidence("secret_access", 0.9, lines,
                                    "Hardcoded credential/API key found in source (T1552.001)",
                                    rule_id="HARDCODED_KEY"))

    # grep for secrets + a network sink
    if _GREP_SECRET.search(code) and (_NET_POST.search(code) or re.search(r"\b(nc|ncat|curl|wget)\b", code, re.IGNORECASE)):
        results.append(Evidence("secret_access", 0.8, lines_matching(_GREP_SECRET, code),
                                "Greps for secrets and sends them over the network (T1552)",
                                rule_id="GREP_SECRET"))

    return results


# ════════════════════════════════════════════════════════════════════════════
# DATA_EXFILTRATION  (T1048.x)
# ════════════════════════════════════════════════════════════════════════════
_ENV_SECRET_READ = re.compile(
    r"os\.environ\.items\(\)|os\.environ\.get\(['\"](?:TOKEN|KEY|SECRET|PASSWORD|API)",
    re.IGNORECASE,
)
_ICMP_EXFIL = re.compile(r"ping\b.+-p\b|icmp.*payload|ping.*hex|block\.hex\(\)", re.IGNORECASE)
_SQL_INJECTION = re.compile(
    r"""(["'].*(SELECT|INSERT|UPDATE|DELETE).*["']\s*%\s*\w|
         ["'].*(SELECT|INSERT|UPDATE|DELETE).*["']\s*\.format\s*\(|
         f["']SELECT.+%s)""",
    re.VERBOSE | re.IGNORECASE,
)
_ATTACKER_ENDPOINT = re.compile(
    r"https?://(attacker\.|evil\.|hooks\.attacker|c2\.example|malicious)",
    re.IGNORECASE,
)
_SQL_PARAM = re.compile(r"execute\s*\(\s*['\"][^'\"]+['\"],\s*\(", re.IGNORECASE)

# Additional exfiltration sinks
_SMTP_SINK = re.compile(r"smtplib\.SMTP|\.sendmail\s*\(", re.IGNORECASE)
_CURL_DATA = re.compile(r"curl\b[^\n]*(-d|--data(?:-binary|-raw)?)\s+@?[\w./~$-]+[^\n]*https?://", re.IGNORECASE)
_NC_REDIRECT = re.compile(r"\b(?:nc|ncat)\b[^\n]*<\s*[\w./~$-]+", re.IGNORECASE)
_DEV_TCP = re.compile(r">\s*/dev/tcp/[\w.\-]+/\d+", re.IGNORECASE)
_SOCKET_SEND = re.compile(r"socket[\s\S]{0,60}\.send(?:all)?\s*\(", re.IGNORECASE)
_HAS_FILE_READ = re.compile(r"open\s*\(|\.read\s*\(|<\s*[\w./~$-]+", re.IGNORECASE)


def detect_data_exfiltration(ctx: Context) -> list[Evidence]:
    code = ctx.code
    results: list[Evidence] = []

    if _ICMP_EXFIL.search(code):
        lines = lines_matching(_ICMP_EXFIL, code)
        results.append(Evidence("data_exfiltration", 0.95, lines,
                                "ICMP data exfiltration via ping payload (T1048.003)",
                                rule_id="ICMP_EXFIL"))

    if _ENV_SECRET_READ.search(code) and (_ATTACKER_ENDPOINT.search(code) or _TELEMETRY_HOST.search(code)):
        lines = lines_matching(_ENV_SECRET_READ, code)
        results.append(Evidence("data_exfiltration", 0.95, lines,
                                "Env secrets harvested and POSTed to external webhook (T1048.003)",
                                rule_id="ENV_WEBHOOK"))
    elif _ATTACKER_ENDPOINT.search(code) and _NET_POST.search(code):
        lines = lines_matching(_ATTACKER_ENDPOINT, code)
        results.append(Evidence("data_exfiltration", 0.85, lines,
                                "Data POSTed to attacker-controlled endpoint (T1048)",
                                rule_id="ATTACKER_POST"))

    if _SQL_INJECTION.search(code):
        if not _SQL_PARAM.search(code):
            lines = lines_matching(_SQL_INJECTION, code)
            results.append(Evidence("data_exfiltration", 0.85, lines,
                                    "SQL injection pattern via string formatting (T1048)",
                                    rule_id="SQL_INJECTION"))

    if _SMTP_SINK.search(code):
        results.append(Evidence("data_exfiltration", 0.8, lines_matching(_SMTP_SINK, code),
                                "Data sent via email (smtplib/sendmail) (T1048)", rule_id="SMTP_EXFIL"))
    if _CURL_DATA.search(code):
        results.append(Evidence("data_exfiltration", 0.85, lines_matching(_CURL_DATA, code),
                                "curl uploads a file to an external URL (T1048)", rule_id="CURL_DATA"))
    if _NC_REDIRECT.search(code):
        results.append(Evidence("data_exfiltration", 0.85, lines_matching(_NC_REDIRECT, code),
                                "File piped to a remote host over netcat (T1048)", rule_id="NC_REDIRECT"))
    if _DEV_TCP.search(code):
        results.append(Evidence("data_exfiltration", 0.9, lines_matching(_DEV_TCP, code),
                                "File sent to /dev/tcp (raw socket exfil) (T1048)", rule_id="DEV_TCP"))
    if _SOCKET_SEND.search(code) and _HAS_FILE_READ.search(code):
        results.append(Evidence("data_exfiltration", 0.8, lines_matching(_SOCKET_SEND, code),
                                "File contents sent over a raw socket (T1048)", rule_id="SOCKET_SEND"))

    return results


# ════════════════════════════════════════════════════════════════════════════
# DESTRUCTIVE_COMMAND  (T1485, T1059.x)
# ════════════════════════════════════════════════════════════════════════════
_RM_RF_TAINT = re.compile(
    r"""(os\.system\s*\(\s*f?['"]rm\s+-rf|subprocess\.run\s*\(\s*['"]\s*rm\s+-rf|
         os\.system\s*\(\s*f['"](.*rm))""",
    re.VERBOSE | re.IGNORECASE,
)
_RM_SAFE_PATH = re.compile(r"rm\s+-rf\s+(/tmp/|/var/tmp/|/srv/releases/)", re.IGNORECASE)
_BARE_RM_RF = re.compile(
    r"\brm\s+(?:-[a-zA-Z]+\s+)*-(?=[a-zA-Z]*r)(?=[a-zA-Z]*f)[a-zA-Z]+\s+"
    r"(?:/\*?|~/?|\$HOME|\*)(?=\s|$|[;&|])",
    re.IGNORECASE,
)
_RM_NO_PRESERVE = re.compile(r"--no-preserve-root", re.IGNORECASE)
_DESTRUCTIVE_EXTRA = re.compile(
    r"(?:\bmkfs(?:\.\w+)?\b"
    r"|\bdd\b[^\n]*\bof=/dev/(?:sd|nvme|hd|vd)"
    r"|\bwipefs\b"
    r"|\bshred\b"
    r"|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"
    r"|\bkill\s+-9\s+-1\b"
    r"|\bchmod\s+-R\s+0*00\s+/"
    r"|\bfind\s+/\s[^\n]*-delete\b"
    r"|\bgit\s+clean\s+-[a-z]*f[a-z]*d"
    r"|\bdocker\s+system\s+prune\s+-a\b"
    r"|shutil\.rmtree\s*\(\s*['\"]/"
    r"|fs\.rmSync\s*\([^)]*\{[^}]*recursive\s*:\s*true)",
    re.IGNORECASE,
)
_SQL_HAS_WHERE = re.compile(r"WHERE\s+\w", re.IGNORECASE)
_SHELL_USER_INPUT = re.compile(r"subprocess\.(run|call|Popen)\s*\(.+shell\s*=\s*True", re.IGNORECASE | re.DOTALL)
_USER_SUPPLIED = re.compile(r"request\.(get_json|form|args|data|json)\b", re.IGNORECASE)
_EVAL_SELF = re.compile(r"eval\s*\(\s*self\.\w+\s*\)", re.IGNORECASE)
_DEL_FORMAT = re.compile(r"DELETE\s+FROM\s+\w+\s+WHERE.{0,60}\.format\(", re.IGNORECASE | re.DOTALL)
_STMT_SPLIT = re.compile(r'(UPDATE\s+\w+\s+SET[^;]+|DELETE\s+FROM\s+\w+[^;]*)', re.IGNORECASE | re.DOTALL)


def detect_destructive_command(ctx: Context) -> list[Evidence]:
    code = ctx.code
    results: list[Evidence] = []

    for m in _BARE_RM_RF.finditer(code):
        line_no = code[: m.start()].count("\n") + 1
        line_text = code.splitlines()[line_no - 1] if code.splitlines() else ""
        if _RM_SAFE_PATH.search(line_text):
            continue
        results.append(Evidence("destructive_command", 0.9, [line_no],
                                "Bare 'rm -rf' on a dangerous target (T1485)",
                                rule_id="BARE_RM_RF"))
        break

    if _RM_NO_PRESERVE.search(code):
        lines = lines_matching(_RM_NO_PRESERVE, code)
        results.append(Evidence("destructive_command", 0.95, lines,
                                "rm with --no-preserve-root (T1485)", rule_id="RM_NO_PRESERVE"))

    if _DESTRUCTIVE_EXTRA.search(code):
        lines = lines_matching(_DESTRUCTIVE_EXTRA, code)
        results.append(Evidence("destructive_command", 0.9, lines,
                                "Destructive system command (mkfs/dd/wipefs/fork-bomb/prune) (T1485)",
                                rule_id="DESTRUCTIVE_EXTRA"))

    if _RM_RF_TAINT.search(code):
        if not _RM_SAFE_PATH.search(code):
            lines = lines_matching(_RM_RF_TAINT, code)
            results.append(Evidence("destructive_command", 0.9, lines,
                                    "Unchecked path interpolated into rm -rf (T1485)",
                                    rule_id="RM_RF_TAINT"))
        else:
            lines = lines_matching(_RM_RF_TAINT, code)
            results.append(Evidence("destructive_command", 0.65, lines,
                                    "rm -rf on interpolated path (possible build artifact) (T1485)",
                                    rule_id="RM_RF_TAINT_SAFEPATH"))

    for m in _STMT_SPLIT.finditer(code):
        stmt = m.group(0)
        if _SQL_HAS_WHERE.search(stmt):
            continue
        if _SQL_PARAM.search(stmt):
            continue
        lines = [code[:m.start()].count("\n") + 1]
        results.append(Evidence("destructive_command", 0.9, lines,
                                "SQL UPDATE/DELETE with no WHERE clause in this statement (T1485)",
                                rule_id="SQL_NO_WHERE"))
        break

    if _SHELL_USER_INPUT.search(code) and _USER_SUPPLIED.search(code):
        lines = lines_matching(_SHELL_USER_INPUT, code)
        results.append(Evidence("destructive_command", 0.95, lines,
                                "User input passed to shell=True subprocess (T1059.004)",
                                rule_id="SHELL_TRUE"))
    if _EVAL_SELF.search(code):
        lines = lines_matching(_EVAL_SELF, code)
        results.append(Evidence("destructive_command", 0.9, lines,
                                "eval(self._expr) in property — attacker-controlled expression (T1059.006)",
                                rule_id="EVAL_SELF"))
    if _DEL_FORMAT.search(code):
        lines = lines_matching(_DEL_FORMAT, code)
        results.append(Evidence("destructive_command", 0.9, lines,
                                "SQL injection via .format() in DELETE (T1485)",
                                rule_id="DEL_FORMAT"))

    return results


# ════════════════════════════════════════════════════════════════════════════
# OBFUSCATED_EXECUTION  (T1059.006, T1027, T1620)
# ════════════════════════════════════════════════════════════════════════════
_DYNAMIC_IMPORT = re.compile(
    r"(__import__\s*\(|importlib\.import_module\s*\(|"
    r"__import__\s*\(['\"][^'\"]+['\"]\.?\s*\+)",
    re.IGNORECASE,
)
_COMPILE_EVAL = re.compile(r"compile\s*\(.+['\"]eval['\"]", re.IGNORECASE | re.DOTALL)
_EXEC_SOURCE = re.compile(r"\bexec\s*\(.+getsource|getsource.+\bexec\b", re.IGNORECASE | re.DOTALL)
_SHELVE_UNTRUSTED = re.compile(r"shelve\.open\s*\(\s*['\"].*(untrusted|/tmp/|attacker)", re.IGNORECASE)
_PICKLE_LOAD = re.compile(r"pickle\.(load|loads)\s*\(", re.IGNORECASE)
_MARSHAL_LOAD = re.compile(r"marshal\.(load|loads)\s*\(", re.IGNORECASE)
_YAML_LOAD = re.compile(r"\byaml\.load\s*\(", re.IGNORECASE)
_IMPORT_ALIAS_SYSTEM = re.compile(r"import\s+os\s+as\s+\w+.{0,200}\.system\(", re.DOTALL)
_CONCAT_IMPORT = re.compile(r"__import__\s*\(['\"]sub['\"\s]*\+['\"\s]*process['\"]|'sub'\s*\+\s*'process'", re.IGNORECASE)


def detect_obfuscated_execution(ctx: Context) -> list[Evidence]:
    code, deob = ctx.code, ctx.deob_code or ctx.code
    results: list[Evidence] = []

    if _COMPILE_EVAL.search(code) or (_COMPILE_EVAL.search(deob) and "eval" in code):
        lines = lines_matching(re.compile(r"compile\("), code)
        results.append(Evidence("obfuscated_execution", 0.9, lines,
                                "compile(expr,'eval')+eval — runtime rule engine (T1059.006)",
                                rule_id="COMPILE_EVAL"))

    if _DYNAMIC_IMPORT.search(code) or _DYNAMIC_IMPORT.search(deob):
        lines = lines_matching(_DYNAMIC_IMPORT, code)
        conf = 0.85
        if _EXEC_SOURCE.search(code):
            conf = 0.95
        results.append(Evidence("obfuscated_execution", conf, lines,
                                "Dynamic module import (importlib/__import__) (T1059.006)",
                                rule_id="DYNAMIC_IMPORT"))

    if _SHELVE_UNTRUSTED.search(code):
        lines = lines_matching(_SHELVE_UNTRUSTED, code)
        results.append(Evidence("obfuscated_execution", 0.9, lines,
                                "shelve.open on untrusted path — pickle deserialization (T1620)",
                                rule_id="SHELVE_UNTRUSTED"))
    if _PICKLE_LOAD.search(code) and "safe" not in code.lower():
        lines = lines_matching(_PICKLE_LOAD, code)
        results.append(Evidence("obfuscated_execution", 0.8, lines,
                                "pickle.load/loads on potentially untrusted data (T1620)",
                                rule_id="PICKLE_LOAD"))
    if _MARSHAL_LOAD.search(code):
        lines = lines_matching(_MARSHAL_LOAD, code)
        results.append(Evidence("obfuscated_execution", 0.8, lines,
                                "marshal.load/loads — unsafe deserialization (T1620)",
                                rule_id="MARSHAL_LOAD"))
    if _YAML_LOAD.search(code) and "safe_load" not in code:
        lines = lines_matching(_YAML_LOAD, code)
        results.append(Evidence("obfuscated_execution", 0.7, lines,
                                "yaml.load without SafeLoader (T1620)",
                                rule_id="YAML_LOAD"))

    if _IMPORT_ALIAS_SYSTEM.search(code) or _IMPORT_ALIAS_SYSTEM.search(deob):
        lines = lines_matching(re.compile(r"import\s+os\s+as\s+"), code)
        results.append(Evidence("obfuscated_execution", 0.9, lines,
                                "Aliased os import used to call system() (T1027)",
                                rule_id="IMPORT_ALIAS_SYSTEM"))

    if _CONCAT_IMPORT.search(code) or _CONCAT_IMPORT.search(deob):
        lines = lines_matching(re.compile(r"__import__"), code)
        results.append(Evidence("obfuscated_execution", 0.85, lines,
                                "String-concatenated module name in __import__ (T1059.006)",
                                rule_id="CONCAT_IMPORT"))

    # decoders → execution chain
    _DECODE_EXEC = re.compile(
        r"(eval|exec|Function|compile)\s*\([^)]*(b64decode|atob|fromCharCode|decompress|unhexlify|codecs\.decode|base64\.b64)",
        re.IGNORECASE | re.DOTALL,
    )
    if _DECODE_EXEC.search(code) or _DECODE_EXEC.search(deob):
        lines = lines_matching(re.compile(r"eval|exec|Function|compile", re.IGNORECASE), code)
        results.append(Evidence("obfuscated_execution", 0.95, lines,
                                "Decode-then-execute chain (base64/atob → eval/exec) (T1059.006)",
                                rule_id="DECODE_EXEC"))

    # shell decode pipe: `... | base64 -d | bash`
    _B64_PIPE_BASH = re.compile(r"base64\s+(-d|--decode)\b[\s\S]{0,40}\|\s*(ba)?sh\b", re.IGNORECASE)
    if _B64_PIPE_BASH.search(code):
        lines = lines_matching(_B64_PIPE_BASH, code)
        results.append(Evidence("obfuscated_execution", 0.95, lines,
                                "base64-decoded payload piped to a shell (T1027)",
                                rule_id="B64_PIPE_BASH"))

    # eval/exec of a chr()/concatenated string
    _OBF_EVAL_CHR = re.compile(r"\b(eval|exec)\s*\([^)]*(chr\s*\(|['\"]\s*\+\s*['\"]|\+\s*['\"])", re.IGNORECASE)
    if _OBF_EVAL_CHR.search(code) or _OBF_EVAL_CHR.search(deob):
        results.append(Evidence("obfuscated_execution", 0.9, lines_matching(re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE), code),
                                "eval/exec of a constructed (chr/concat) string (T1027)",
                                rule_id="OBF_EVAL_CHR"))

    # shell: eval "$(echo ... | base64 -d)"
    _SHELL_EVAL_B64 = re.compile(r"eval\s+[\"']?\$\([^)]*base64\s+-d", re.IGNORECASE)
    if _SHELL_EVAL_B64.search(code):
        results.append(Evidence("obfuscated_execution", 0.95, lines_matching(_SHELL_EVAL_B64, code),
                                "eval of a base64-decoded shell payload (T1027)", rule_id="SHELL_EVAL_B64"))

    # JS Buffer.from(..., 'base64') / atob feeding execution
    _BUFFER_B64 = re.compile(r"Buffer\.from\s*\([^)]*['\"]base64['\"]|atob\s*\(", re.IGNORECASE)
    if _BUFFER_B64.search(code):
        results.append(Evidence("obfuscated_execution", 0.8, lines_matching(_BUFFER_B64, code),
                                "base64 decoding in JS (atob/Buffer.from) (T1027)", rule_id="BUFFER_B64"))

    return results


# ════════════════════════════════════════════════════════════════════════════
# PERSISTENCE_OR_PRIVESC  (T1543, T1548)
# ════════════════════════════════════════════════════════════════════════════
_SYSTEMD_WRITE = re.compile(r"(/etc/systemd/system|\.service).{0,300}ExecStart", re.DOTALL | re.IGNORECASE)
_CURL_PIPE_BASH = re.compile(r"curl.+\|\s*(ba)?sh|wget.+\|\s*(ba)?sh", re.IGNORECASE)
_SUDOERS_WRITE = re.compile(r"(/etc/sudoers|sudoers\.d/).{0,200}(NOPASSWD|ALL\s*=\s*\(ALL\))", re.DOTALL | re.IGNORECASE)
_SUDOERS_OPEN = re.compile(r"open\s*\(\s*['\"]\/etc\/sudoers", re.IGNORECASE)
_CRONTAB_WRITE = re.compile(r"crontab\s+(-e|\w*\.write|open)", re.IGNORECASE)
_STARTUP_WRITE = re.compile(r"(~\/\.bashrc|~\/\.profile|~\/\.bash_profile|\/etc\/profile)", re.IGNORECASE)
_AUTHORIZED_KEYS = re.compile(r"authorized_keys", re.IGNORECASE)
_LD_PRELOAD = re.compile(r"\bLD_PRELOAD\b|\bld\.so\.preload\b", re.IGNORECASE)
_NPM_POSTINSTALL = re.compile(r'"(postinstall|preinstall)"\s*:', re.IGNORECASE)
_WIN_RUN_KEY = re.compile(r"(CurrentVersion\\\\Run|HKCU.*\\\\Run|HKLM.*\\\\Run)", re.IGNORECASE)
_SUDO_NOPASSWD = re.compile(r"sudo\s+.*NOPASSWD|NOPASSWD\s*:", re.IGNORECASE)
_CHMOD_SETUID = re.compile(r"chmod\s+(u\+s|[24][0-7]{3})\b", re.IGNORECASE)
_ADDGROUP_SUDO = re.compile(r"usermod\s+.*(-aG|--append\s+--groups)\s+(sudo|docker|wheel)", re.IGNORECASE)
_DOCKER_PRIVILEGED = re.compile(r"docker\s+run\b[^\n]*--privileged|--cap-add[= ]SYS_ADMIN", re.IGNORECASE)
_DOCKER_SOCK = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)


def detect_persistence_or_privesc(ctx: Context) -> list[Evidence]:
    code = ctx.code
    results: list[Evidence] = []

    if _SYSTEMD_WRITE.search(code) and _CURL_PIPE_BASH.search(code):
        lines = lines_matching(re.compile(r"ExecStart|curl.*bash", re.IGNORECASE), code)
        results.append(Evidence("persistence_or_privesc", 0.95, lines,
                                "Writes systemd unit with curl|bash ExecStart (T1543.002)",
                                rule_id="SYSTEMD_CURL_BASH"))
    elif _SYSTEMD_WRITE.search(code):
        lines = lines_matching(re.compile(r"/etc/systemd"), code)
        results.append(Evidence("persistence_or_privesc", 0.75, lines,
                                "Writes systemd unit file (T1543.002)", rule_id="SYSTEMD_WRITE"))

    if _SUDOERS_WRITE.search(code) or (_SUDOERS_OPEN.search(code) and "NOPASSWD" in code):
        lines = lines_matching(re.compile(r"sudoers|NOPASSWD", re.IGNORECASE), code)
        results.append(Evidence("persistence_or_privesc", 0.97, lines,
                                "Grants passwordless sudo via /etc/sudoers (T1548.003)",
                                rule_id="SUDOERS_NOPASSWD", hard_block=True))

    if _CRONTAB_WRITE.search(code) and "crontab -l" not in code:
        lines = lines_matching(_CRONTAB_WRITE, code)
        results.append(Evidence("persistence_or_privesc", 0.8, lines,
                                "Crontab modification detected (T1053)", rule_id="CRONTAB_WRITE"))

    if _AUTHORIZED_KEYS.search(code) and re.search(r"(>>?|write|append|open)\s*\(?['\"]?[^\n]*authorized_keys", code, re.IGNORECASE):
        lines = lines_matching(_AUTHORIZED_KEYS, code)
        results.append(Evidence("persistence_or_privesc", 0.9, lines,
                                "Writes to authorized_keys (T1098.004)", rule_id="AUTHORIZED_KEYS"))

    if _LD_PRELOAD.search(code):
        results.append(Evidence("persistence_or_privesc", 0.8, lines_matching(_LD_PRELOAD, code),
                                "LD_PRELOAD injection (T1574.006)", rule_id="LD_PRELOAD"))
    if _NPM_POSTINSTALL.search(code):
        results.append(Evidence("persistence_or_privesc", 0.75, lines_matching(_NPM_POSTINSTALL, code),
                                "npm lifecycle hook could execute code on install (T1195.001)",
                                rule_id="NPM_POSTINSTALL"))
    if _WIN_RUN_KEY.search(code):
        results.append(Evidence("persistence_or_privesc", 0.85, lines_matching(_WIN_RUN_KEY, code),
                                "Windows Run-key persistence (T1547.001)", rule_id="WIN_RUN_KEY"))
    if _SUDO_NOPASSWD.search(code) and "sudoers" not in code:
        results.append(Evidence("persistence_or_privesc", 0.7, lines_matching(_SUDO_NOPASSWD, code),
                                "Passwordless sudo usage (T1548.003)", rule_id="SUDO_NOPASSWD"))
    if _CHMOD_SETUID.search(code):
        results.append(Evidence("persistence_or_privesc", 0.85, lines_matching(_CHMOD_SETUID, code),
                                "chmod setuid bit (T1548.001)", rule_id="CHMOD_SETUID"))
    if _ADDGROUP_SUDO.search(code):
        results.append(Evidence("persistence_or_privesc", 0.85, lines_matching(_ADDGROUP_SUDO, code),
                                "User added to sudo/docker group (T1548.003)", rule_id="ADDGROUP_SUDO"))
    if _DOCKER_PRIVILEGED.search(code) or _DOCKER_SOCK.search(code):
        pat = _DOCKER_PRIVILEGED if _DOCKER_PRIVILEGED.search(code) else _DOCKER_SOCK
        results.append(Evidence("persistence_or_privesc", 0.85, lines_matching(pat, code),
                                "Privileged container / docker.sock mount (T1611)", rule_id="DOCKER_PRIVILEGED"))

    if _STARTUP_WRITE.search(code) and re.search(r"open\s*\(|>>?\s*['\"]?~?/", code):
        lines = lines_matching(_STARTUP_WRITE, code)
        results.append(Evidence("persistence_or_privesc", 0.7, lines,
                                "Appends to a shell startup profile (T1546.004)", rule_id="STARTUP_WRITE"))

    return results
