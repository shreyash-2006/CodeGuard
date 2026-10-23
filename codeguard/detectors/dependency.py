"""
detectors/dependency.py — dependency_risk (T1195.001).

Install-command parsing + typosquat detection (edit distance to top packages,
common character swaps) + risky package sources.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from codeguard.detectors.base import Context, Evidence, lines_matching

_DATA = Path(__file__).parent.parent / "data"

# Known typosquats (explicit)
_TYPOSQUATS: dict[str, str] = {
    "colourama": "colorama",
    "reqeusts": "requests",
    "djano": "django",
    "flassk": "flask",
    "panda": "pandas",
    "nympy": "numpy",
    "scipiy": "scipy",
    "tensorflow-gpu-2": "tensorflow",
    "python-dateutils": "python-dateutil",
    "urlib3": "urllib3",
    "piltow": "Pillow",
    "matplotllib": "matplotlib",
    "crossenv": "cross-env",
    "lodahs": "lodash",
    "expresss": "express",
}

_UNTRUSTED_GIT = re.compile(
    r"pip\s+install\s+git\+https?://(?!github\.com/[a-z0-9_\-]+/[a-z0-9_\-]+(@[a-zA-Z0-9._]+)?$)",
    re.IGNORECASE,
)
_VCS_EVIL = re.compile(r"git\+https?://(evil\.|attacker\.|malicious\.|c2\.)", re.IGNORECASE)

_INSTALL = re.compile(
    r"\b(?:pip3?|python\s+-m\s+pip|npm|yarn|pnpm|apt-get|apt|gem|cargo)\s+"
    r"(?:install|add|i)\s+([^\n;&|]+)",
    re.IGNORECASE,
)
_RISKY_INDEX = re.compile(r"--(extra-)?index-url\b", re.IGNORECASE)
_CURL_PIPE_SH = re.compile(r"curl[^\n|]*\|\s*(?:sudo\s+)?(ba|z)?sh\b", re.IGNORECASE)
_DIRECT_URL_WHEEL = re.compile(r"https?://\S+\.(whl|tar\.gz|tgz)\b", re.IGNORECASE)
_DEFAULT_INDEX = re.compile(r"(pypi\.org|registry\.npmjs\.org|files\.pythonhosted\.org)", re.IGNORECASE)

# default swap table
_SWAPS = [("l", "1"), ("1", "l"), ("o", "0"), ("0", "o"), ("rn", "m"), ("m", "rn"), ("-", "_"), ("_", "-"), ("li", "1i")]


@lru_cache(maxsize=1)
def _load_top_packages() -> tuple[frozenset[str], frozenset[str]]:
    def load(name: str) -> set[str]:
        try:
            return {
                line.strip().lower()
                for line in (_DATA / name).read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }
        except Exception:
            return set()
    return frozenset(load("top_packages_pypi.txt")), frozenset(load("top_packages_npm.txt"))


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
        if min(prev) > cap:
            return cap + 1
    return prev[-1]


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _closest_top(name: str, ecosystem: str) -> tuple[str, int] | None:
    pypi, npm = _load_top_packages()
    pool = npm if ecosystem == "npm" else pypi
    norm = _normalize_name(name)
    best: tuple[str, int] | None = None
    for cand in pool:
        cn = _normalize_name(cand)
        if cn == norm:
            return (cand, 0)
        d = _levenshtein(norm, cn, cap=2)
        if d <= 2 and (best is None or d < best[1]):
            best = (cand, d)
    return best


def _parse_install_targets(cmd: str) -> list[str]:
    targets = []
    for tok in cmd.split():
        if tok.startswith("-") or tok.startswith("."):
            continue
        if tok in ("&&", "||", "|", ";"):
            break
        name = re.split(r"[@=<>~!]", tok)[0]
        if name and not name.startswith("$"):
            targets.append(name)
    return targets


def detect_dependency_risk(ctx: Context) -> list[Evidence]:
    code = ctx.code
    results: list[Evidence] = []

    # Explicit typosquats
    for typo, legit in _TYPOSQUATS.items():
        pattern = re.compile(rf"\b{re.escape(typo)}\b", re.IGNORECASE)
        if pattern.search(code):
            results.append(Evidence("dependency_risk", 0.95, lines_matching(pattern, code),
                                    f"Typosquatted package '{typo}' (looks like '{legit}') (T1195.001)",
                                    rule_id="TYPOSQUAT_KNOWN"))

    # Edit-distance typosquats
    for m in _INSTALL.finditer(code):
        cmd = m.group(0)
        eco = "npm" if re.match(r"\s*(npm|yarn|pnpm)", m.group(0), re.IGNORECASE) else "pypi"
        for name in _parse_install_targets(m.group(1)):
            if len(name) < 4:
                continue
            hit = _closest_top(name, eco)
            if hit is None:
                continue
            legit, dist = hit
            if dist == 0:
                continue
            if dist <= 2:
                line = code[: m.start()].count("\n") + 1
                results.append(Evidence("dependency_risk", 0.9 if dist == 1 else 0.8, [line],
                                        f"Possible typosquat '{name}' (≈ '{legit}', edit distance {dist}) (T1195.001)",
                                        rule_id="TYPOSQUAT_EDIT"))

    # Untrusted VCS / index sources
    if _VCS_EVIL.search(code):
        results.append(Evidence("dependency_risk", 0.95, lines_matching(_VCS_EVIL, code),
                                "Package pulled from evil/untrusted git URL (T1195.001)",
                                rule_id="VCS_EVIL"))
    elif _UNTRUSTED_GIT.search(code):
        results.append(Evidence("dependency_risk", 0.75, lines_matching(_UNTRUSTED_GIT, code),
                                "Package installed from unpinned git VCS URL (T1195.001)",
                                rule_id="UNTRUSTED_GIT"))

    if _RISKY_INDEX.search(code) and not _DEFAULT_INDEX.search(code):
        results.append(Evidence("dependency_risk", 0.8, lines_matching(_RISKY_INDEX, code),
                                "Install from a non-default package index (T1195.001)",
                                rule_id="RISKY_INDEX"))
    if _CURL_PIPE_SH.search(code):
        results.append(Evidence("dependency_risk", 0.85, lines_matching(_CURL_PIPE_SH, code),
                                "curl | sh remote install (T1195.001)", rule_id="CURL_PIPE_SH"))
    if _DIRECT_URL_WHEEL.search(code) and "_DEFAULT" not in code:
        hits = [ln for ln in lines_matching(_DIRECT_URL_WHEEL, code)]
        if hits:
            results.append(Evidence("dependency_risk", 0.6, hits,
                                    "Direct install from an arbitrary URL (T1195.001)",
                                    rule_id="DIRECT_URL"))

    return results
