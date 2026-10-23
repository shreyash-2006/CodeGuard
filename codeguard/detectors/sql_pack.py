"""
detectors/sql_pack.py — SQL statement analysis (sqlglot AST + regex fallback).
"""
from __future__ import annotations

import re

from codeguard.detectors.base import Context, Evidence, lines_matching

_SQL_ANY = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|GRANT|COPY)\b", re.IGNORECASE)
_DANGEROUS_FUNCS = re.compile(
    r"\b(xp_cmdshell|xp_dirtree|xp_fileexist|xp_regread|sp_OACreate|sp_configure|"
    r"pg_read_file|pg_read_binary_file|pg_ls_dir|pg_sleep|load_file|"
    r"utl_http|utl_file|dbms_lock\.sleep|openrowset|opendatasource)\b",
    re.IGNORECASE,
)
_INTO_FILE = re.compile(r"\bINTO\s+(OUTFILE|DUMPFILE)\b", re.IGNORECASE)
_DDL_DESTRUCTIVE = re.compile(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE|ALTER\s+TABLE[^;]*DROP\s+COLUMN)\b", re.IGNORECASE)
_GRANT_SUPER = re.compile(
    r"\b(GRANT\s+ALL\b|CREATE\s+USER[^;]{0,80}SUPERUSER|ALTER\s+USER[^;]{0,80}SUPERUSER|"
    r"GRANT\s+ALL\s+PRIVILEGES)\b",
    re.IGNORECASE,
)
_COPY_PROGRAM = re.compile(r"\bCOPY\b[^;]*\bPROGRAM\b", re.IGNORECASE)
_NO_WHERE = re.compile(r"\b(DELETE\s+FROM|UPDATE)\b", re.IGNORECASE)
_HAS_WHERE = re.compile(r"\bWHERE\b", re.IGNORECASE)


def _statement_count(ctx: Context) -> int:
    parsed = ctx.parsed.get("sql")
    if parsed:
        try:
            return sum(1 for s in parsed if s is not None)
        except Exception:
            pass
    return 0


def detect_sql_pack(ctx: Context) -> list[Evidence]:
    code = ctx.code
    if ctx.language != "sql" and not _SQL_ANY.search(code):
        return []
    results: list[Evidence] = []

    if _DANGEROUS_FUNCS.search(code):
        results.append(Evidence("destructive_command", 0.95, lines_matching(_DANGEROUS_FUNCS, code),
                                "Dangerous SQL function (command/file access) (T1059)",
                                rule_id="SQL_DANGEROUS_FUNC", hard_block=True))
    if _COPY_PROGRAM.search(code):
        results.append(Evidence("destructive_command", 0.95, lines_matching(_COPY_PROGRAM, code),
                                "SQL COPY … PROGRAM executes a shell command (T1059)",
                                rule_id="SQL_COPY_PROGRAM", hard_block=True))
    if _INTO_FILE.search(code):
        results.append(Evidence("data_exfiltration", 0.85, lines_matching(_INTO_FILE, code),
                                "SQL writes query results to a file (INTO OUTFILE) (T1048)",
                                rule_id="SQL_INTO_FILE"))
    if _DDL_DESTRUCTIVE.search(code):
        results.append(Evidence("destructive_command", 0.85, lines_matching(_DDL_DESTRUCTIVE, code),
                                "Destructive DDL (DROP/TRUNCATE) (T1485)", rule_id="SQL_DDL"))
    if _GRANT_SUPER.search(code):
        results.append(Evidence("persistence_or_privesc", 0.85, lines_matching(_GRANT_SUPER, code),
                                "Privilege escalation via SQL GRANT/SUPERUSER (T1548)",
                                rule_id="SQL_GRANT_SUPER"))

    # Stacked queries: more than one statement, at least one dangerous
    n_stmts = _statement_count(ctx)
    if n_stmts == 0:
        # regex fallback: count ';'-separated statements
        n_stmts = len([s for s in code.split(";") if s.strip() and _SQL_ANY.search(s)])
    if n_stmts > 1 and (results or _NO_WHERE.search(code)):
        results.append(Evidence("destructive_command", 0.8, lines_matching(_SQL_ANY, code),
                                "Stacked SQL statements (T1505)", rule_id="SQL_STACKED"))
    return results
