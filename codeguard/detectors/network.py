"""
detectors/network.py — ssrf_network_exfil (T1090, T1559).

Extracts URLs/hosts/IPs from every layer, normalizes IP encodings
(decimal, hex, octal, IPv6-mapped, userinfo, trailing dot) and flags cloud
metadata, link-local, schemes, internal services and reverse shells.
"""
from __future__ import annotations

import ipaddress
import re

from codeguard.detectors.base import Context, Evidence, lines_matching

# ── Existing SSRF signals ────────────────────────────────────────────────────
_METADATA_URL = re.compile(
    r"(169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|instance-metadata|"
    r"metadata\.internal|fd00::ec2:|100\.100\.100\.200|100\.64\.)",
    re.IGNORECASE,
)
_GOPHER_SCHEME = re.compile(r"gopher://", re.IGNORECASE)
_REDIRECT_BYPASS = re.compile(
    r"(allow_redirects\s*=\s*True|Location:|301|302).{0,400}(169\.254|internal|metadata)",
    re.DOTALL | re.IGNORECASE,
)
_ALLOWLIST_BYPASS = re.compile(
    r"(validate|startswith|ALLOWED).{0,300}requests\.get\s*\(INTERNAL|"
    r"INTERNAL\s*=\s*['\"]http.{0,200}validate\(",
    re.DOTALL | re.IGNORECASE,
)
_INTERNAL_ADDR = re.compile(
    r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"::1|fd[0-9a-f]{2}:)",
    re.IGNORECASE,
)

# ── New: extraction + normalization ──────────────────────────────────────────
_URL_RE = re.compile(r"\b([a-z][a-z0-9+.\-]{0,20}://[^\s'\"<>|)\]}]+)", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SCHEME_DANGER = re.compile(r"\b(file|gopher|dict|ldap|tftp|jar|netdoc)://", re.IGNORECASE)
_METADATA_HOSTS = {
    "169.254.169.254", "169.254.170.2", "100.100.100.200",
    "metadata.google.internal", "metadata.internal", "instance-data",
}
_INTERNAL_HOSTNAMES = re.compile(
    r"(^|\.)localhost$|(^|\.)internal$|(^|\.)local$|kubernetes\.default|"
    r"(^|\.)localdomain$|docker\.internal|host\.docker\.internal",
    re.IGNORECASE,
)
_UNUSUAL_PORTS = {2375, 2376, 6443, 10250, 10255, 8500, 9200, 6379, 11211, 27017, 5432, 3306, 8080, 8443}
_REVERSE_SHELL = re.compile(
    r"(/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+|bash\s+-i\s*>&|nc\s+(-e|--exec)\b|"
    r"ncat\s+.*--exec|socat\s+.*exec:|python[^\n]*socket[^\n]*dup2|"
    r"mkfifo[^\n]*;\s*(ba)?sh\s+-i|0<&\d+|pty\.spawn)",
    re.IGNORECASE,
)
_ATTACKER_FETCH = re.compile(
    r"(requests\.(get|post|put)|urlopen|fetch|http\.request)\s*\(\s*['\"]https?://"
    r"(attacker|evil|c2|malicious|example\.invalid|198\.51\.100|203\.0\.113)",
    re.IGNORECASE,
)


def _int_to_ipv4(n: int) -> str | None:
    try:
        if 0 <= n <= 0xFFFFFFFF:
            return str(ipaddress.IPv4Address(n))
    except Exception:
        pass
    return None


def normalize_host(raw: str) -> str | None:
    """Normalize an encoded host into a canonical IP string or hostname."""
    if not raw:
        return None
    h = raw.strip().strip(".'\"")
    if not h:
        return None
    if "@" in h:                      # userinfo trick
        h = h.split("@")[-1]
    if h.startswith("["):             # [::1]:80
        h = h[1:h.index("]")] if "]" in h else h
    elif h.count(":") == 1:
        h = h.split(":")[0]
    h = h.strip(".")
    low = h.lower()
    if not low:
        return None
    try:
        return str(ipaddress.ip_address(low))
    except Exception:
        pass
    if low.startswith("0x"):
        try:
            return _int_to_ipv4(int(low, 16))
        except Exception:
            pass
    if low.isdigit():
        try:
            return _int_to_ipv4(int(low))
        except Exception:
            pass
    if re.fullmatch(r"(0[0-7]*\.){3}0[0-7]*", low):     # octal-dotted
        try:
            parts = [int(p, 8) for p in low.split(".")]
            if all(0 <= p <= 255 for p in parts):
                return str(ipaddress.IPv4Address(".".join(map(str, parts))))
        except Exception:
            pass
    return low


def classify_host(host: str) -> tuple[str, float]:
    """Return (kind, confidence) for a normalized host."""
    if host in _METADATA_HOSTS:
        return "metadata", 0.95
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local:
            return "link_local", 0.8
        if ip.is_loopback:
            return "loopback", 0.4
        if ip.is_private:
            return "private", 0.4
        if ip.is_reserved or ip.is_multicast:
            return "reserved", 0.4
        return "public", 0.0
    except ValueError:
        if _INTERNAL_HOSTNAMES.search(host):
            return "internal_hostname", 0.5
        return "hostname", 0.0


def _hosts_in(text: str) -> list[tuple[str, str]]:
    """Return (raw_host, normalized_host) pairs found in text."""
    out: list[tuple[str, str]] = []
    for m in _URL_RE.finditer(text):
        url = m.group(1)
        netloc = url.split("://", 1)[1]
        netloc = re.split(r"[/?#]", netloc)[0]
        norm = normalize_host(netloc)
        if norm:
            out.append((netloc, norm))
    for m in _IPV4_RE.finditer(text):
        norm = normalize_host(m.group(0))
        if norm:
            out.append((m.group(0), norm))
    return out


def detect_ssrf_network_exfil(ctx: Context) -> list[Evidence]:
    code, deob = ctx.code, ctx.deob_code or ctx.code
    results: list[Evidence] = []

    if _METADATA_URL.search(code):
        results.append(Evidence("ssrf_network_exfil", 0.95, lines_matching(_METADATA_URL, code),
                                "Fetches cloud instance metadata endpoint (T1090/T1552.005)",
                                rule_id="METADATA_URL"))

    if _GOPHER_SCHEME.search(code):
        results.append(Evidence("ssrf_network_exfil", 0.95, lines_matching(_GOPHER_SCHEME, code),
                                "Gopher:// scheme SSRF for internal service command injection (T1059+T1090)",
                                rule_id="GOPHER_SSRF"))

    if _ALLOWLIST_BYPASS.search(code) or _REDIRECT_BYPASS.search(code):
        results.append(Evidence("ssrf_network_exfil", 0.9,
                                lines_matching(re.compile(r"INTERNAL|169\.254", re.IGNORECASE), code),
                                "Allowlist bypass: validate URL then fetch internal address (T1090)",
                                rule_id="ALLOWLIST_BYPASS"))

    # Dangerous schemes
    if _SCHEME_DANGER.search(code):
        results.append(Evidence("ssrf_network_exfil", 0.9, lines_matching(_SCHEME_DANGER, code),
                                "Dangerous URL scheme (file/gopher/dict/…) (T1090)",
                                rule_id="DANGEROUS_SCHEME"))

    # Normalized host classification (all layers)
    seen: set[str] = set()
    best: dict[str, tuple[float, int]] = {}
    for text, layer_i in ((code, 0), (deob, 1)):
        for raw, norm in _hosts_in(text):
            kind, conf = classify_host(norm)
            if conf <= 0.0 or norm in seen:
                continue
            seen.add(norm)
            line = 1
            for probe in (raw, norm):
                lm = lines_matching(re.compile(re.escape(probe)), text)
                if lm:
                    line = lm[0]
                    break
            if kind not in best or conf > best[kind][0]:
                best[kind] = (conf, line)

    kind_labels = {
        "metadata": "Cloud metadata endpoint (normalized)",
        "link_local": "Link-local address (SSRF)",
        "internal_hostname": "Internal service hostname (SSRF)",
        "loopback": "Loopback address",
        "private": "Private-range address",
        "reserved": "Reserved/multicast address",
    }
    for kind, (conf, line) in best.items():
        results.append(Evidence("ssrf_network_exfil", conf, [line],
                                kind_labels.get(kind, kind), rule_id=f"HOST_{kind.upper()}", layer=1 if deob != code else 0))

    # Reverse shells → hard block
    if _REVERSE_SHELL.search(code):
        results.append(Evidence("ssrf_network_exfil", 0.97, lines_matching(_REVERSE_SHELL, code),
                                "Reverse shell / network shell (T1059+T1090)",
                                rule_id="REVERSE_SHELL", hard_block=True))

    # Fetch of a known attacker / placeholder host
    if _ATTACKER_FETCH.search(code):
        results.append(Evidence("ssrf_network_exfil", 0.75, lines_matching(_ATTACKER_FETCH, code),
                                "Request to a known attacker/placeholder host (T1090)",
                                rule_id="ATTACKER_FETCH"))

    return results
