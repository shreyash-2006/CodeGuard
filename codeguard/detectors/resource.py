"""
detectors/resource.py — resource_exhaustion (T1499.x).
"""
from __future__ import annotations

import re

from codeguard.detectors.base import Context, Evidence, lines_matching

_DD_FILL = re.compile(r"dd\s+if=/dev/(zero|urandom|random).{0,80}of=", re.IGNORECASE)
_DD_NO_COUNT = re.compile(r"dd\s+if=/dev/\w+\s+of=\S+\s+bs=", re.IGNORECASE)
_SOCKET_UNBOUNDED = re.compile(r"socket\.socket\(\)\.connect.{0,200}range\s*\(\s*\d{3,}\s*\)", re.DOTALL)
_THREAD_UNBOUNDED = re.compile(
    r"Thread.{0,200}while\s+True|for\s+_\s+in\s+range\s*\(\s*(\d+)\s*\).{0,200}Thread", re.DOTALL
)
_FORK_BOMB = re.compile(r"os\.fork\(\)|multiprocessing\.Process.{0,200}while True", re.DOTALL)
_FORK_BOMB_BASH = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE)
_LARGE_COUNT = re.compile(r"range\s*\(\s*(\d+)\s*\)")
_BUSY_LOOP = re.compile(r"while\s+True\s*:|while\s+1\s*:", re.IGNORECASE)
_THREAD_SPAWN = re.compile(r"Thread\s*\(.*target=\w+|threading\.Thread", re.IGNORECASE | re.DOTALL)
_BIG_VAR_COUNT = re.compile(r"WORKER_COUNT\s*=\s*([1-9]\d{2,})|COUNT\s*=\s*([1-9]\d{2,})", re.IGNORECASE)

# ── Additions ────────────────────────────────────────────────────────────────
_HUGE_ALLOC = re.compile(r"(\*\s*10\s*\*\*\s*[6-9]|\*\s*(?:1_?000_?000_?000|1000000000)\b|\bbytearray\s*\(\s*10\s*\*\*\s*\d)", re.IGNORECASE)
_ZIP_BOMB = re.compile(r"(zlib\.decompress|gzip\.decompress|bz2\.decompress|zipfile[^\n]*read\()[^\n]*while\s+True", re.IGNORECASE)
_MINING = re.compile(
    r"(stratum\+tcp://|xmrig|minerd|coinhive|cryptonight|monero|--donate-level|nicehash)"
    r"|(wallet\s*=\s*['\"](?:4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|0x[0-9a-fA-F]{40})['\"])",
    re.IGNORECASE,
)
_SQL_SLEEP = re.compile(r"\b(pg_sleep|sleep\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|dbms_pipe\.receive_message)\b", re.IGNORECASE)
# sleep() only counts as a SQL DoS when the snippet is actually SQL
_SQL_CTX = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|UNION|EXEC|DECLARE|STRAIGHT_JOIN)\b", re.IGNORECASE)
_HUGE_ALLOC2 = re.compile(r"(1e9|1e10|10\s*\*\*\s*[6-9]|Buffer\.alloc\s*\(\s*1e|new\s+Array\s*\(\s*1e|Array\s*\(\s*1e\d)", re.IGNORECASE)
_INF_LOOP = re.compile(r"(while\s+True\s*:|while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\))", re.IGNORECASE)
_LOOP_CONTROL = re.compile(
    r"\b(break|sleep|await|input|yield|return|recv|read|select|join|asyncio)\b", re.IGNORECASE
)


def detect_resource_exhaustion(ctx: Context) -> list[Evidence]:
    code = ctx.code
    results: list[Evidence] = []

    if _DD_NO_COUNT.search(code) and "count=" not in code.lower():
        lines = lines_matching(_DD_FILL, code)
        results.append(Evidence("resource_exhaustion", 0.95, lines,
                                "dd fills disk with no count limit (T1499.001)", rule_id="DD_FILL"))

    if _SOCKET_UNBOUNDED.search(code):
        lines = lines_matching(re.compile(r"socket\.socket"), code)
        results.append(Evidence("resource_exhaustion", 0.95, lines,
                                "Thousands of unclosed sockets exhaust connection table (T1499.002)",
                                rule_id="SOCKET_UNBOUNDED"))
    else:
        for m in _LARGE_COUNT.finditer(code):
            if int(m.group(1)) >= 10000 and "socket" in code:
                lines = [code[:m.start()].count("\n") + 1]
                results.append(Evidence("resource_exhaustion", 0.9, lines,
                                        "Large-scale socket/connection loop (T1499.002)",
                                        rule_id="SOCKET_LOOP"))
                break

    if _THREAD_UNBOUNDED.search(code):
        for m in _LARGE_COUNT.finditer(code):
            if int(m.group(1)) >= 100:
                lines = lines_matching(re.compile(r"Thread|threading"), code)
                results.append(Evidence("resource_exhaustion", 0.9, lines,
                                        "Large thread pool with infinite busy loop (T1499.003)",
                                        rule_id="THREAD_UNBOUNDED"))
                break

    if _BUSY_LOOP.search(code) and _THREAD_SPAWN.search(code) and _BIG_VAR_COUNT.search(code):
        m_count = _BIG_VAR_COUNT.search(code)
        count_val = int(m_count.group(1) or m_count.group(2))
        if count_val >= 100:
            lines = lines_matching(_THREAD_SPAWN, code)
            results.append(Evidence("resource_exhaustion", 0.9, lines,
                                    f"Thread pool of {count_val} with infinite busy loop (T1499.003)",
                                    rule_id="THREAD_VAR_COUNT"))

    if _FORK_BOMB.search(code):
        results.append(Evidence("resource_exhaustion", 0.9, lines_matching(_FORK_BOMB, code),
                                "Fork bomb (T1499.003)", rule_id="FORK_BOMB"))
    if _FORK_BOMB_BASH.search(code):
        results.append(Evidence("resource_exhaustion", 0.95, lines_matching(_FORK_BOMB_BASH, code),
                                "Shell fork bomb (T1499.003)", rule_id="FORK_BOMB_BASH"))
    if _HUGE_ALLOC.search(code):
        results.append(Evidence("resource_exhaustion", 0.8, lines_matching(_HUGE_ALLOC, code),
                                "Huge memory allocation (T1499.004)", rule_id="HUGE_ALLOC"))
    if _ZIP_BOMB.search(code):
        results.append(Evidence("resource_exhaustion", 0.8, lines_matching(_ZIP_BOMB, code),
                                "Decompression bomb loop (T1499.004)", rule_id="ZIP_BOMB"))
    if _MINING.search(code):
        results.append(Evidence("resource_exhaustion", 0.9, lines_matching(_MINING, code),
                                "Cryptomining indicator (T1496)", rule_id="MINING"))
    if (ctx.language == "sql" or _SQL_CTX.search(code)) and _SQL_SLEEP.search(code):
        results.append(Evidence("resource_exhaustion", 0.7, lines_matching(_SQL_SLEEP, code),
                                "SQL time-delay function (DoS / blind injection) (T1499)",
                                rule_id="SQL_SLEEP"))

    if _HUGE_ALLOC2.search(code):
        results.append(Evidence("resource_exhaustion", 0.8, lines_matching(_HUGE_ALLOC2, code),
                                "Huge allocation / unbounded buffer (T1499.004)", rule_id="HUGE_ALLOC2"))
    if _INF_LOOP.search(code) and not _LOOP_CONTROL.search(code):
        results.append(Evidence("resource_exhaustion", 0.65, lines_matching(_INF_LOOP, code),
                                "Unbounded loop with no break/sleep/IO (T1499.003)", rule_id="INF_LOOP"))

    return results
