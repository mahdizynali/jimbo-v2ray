import base64
import json
import re
import socket
import statistics
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse


# =========================
# Regex / Patterns
# =========================
VMESS_RE = re.compile(r"^vmess://([A-Za-z0-9+/=_-]+)")


# =========================
# Data Models
# =========================
@dataclass(frozen=True)
class Endpoint:
    scheme: str
    host: str
    port: int
    network: str
    tag: str
    raw_line: str


@dataclass(frozen=True)
class ScanResult:
    idx: int
    total: int
    ep: Endpoint
    tcp_avg_ms: Optional[float]
    tcp_fails: int
    udp_avg_ms: Optional[float]
    udp_status: str
    dl_ok: bool
    dl_reason: str
    dl_ms: Optional[float]
    http_status: Optional[int]

    @property
    def alive(self) -> bool:
        from .singbox_tools import has_singbox
        from .scanner import ENABLE_DOWNLOAD_TEST, TCP_TRIES

        if ENABLE_DOWNLOAD_TEST and has_singbox():
            return self.dl_ok
        return self.tcp_avg_ms is not None and self.tcp_fails < TCP_TRIES


# =========================
# Base64 helper
# =========================
def _b64_decode_any(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * ((-len(s)) % 4)
    return base64.b64decode(s)


def _clean_share_line(line: str) -> str:
    s = line.strip()
    if s.startswith("vmess://"):
        m = VMESS_RE.match(s)
        if m:
            return "vmess://" + m.group(1)
    return s


# =========================
# Parsers
# =========================
def parse_vmess(line: str) -> Optional[Endpoint]:
    line = _clean_share_line(line)
    m = VMESS_RE.match(line)
    if not m:
        return None
    try:
        data = json.loads(_b64_decode_any(m.group(1)).decode("utf-8", errors="replace"))
    except Exception:
        return None

    host = (data.get("add") or "").strip()
    port_str = str(data.get("port") or "").strip()
    net = (data.get("net") or "").strip() or "tcp"
    tag = (data.get("ps") or "").strip()

    if not host or host.startswith(("http://", "https://")):
        return None
    try:
        port = int(port_str)
    except Exception:
        return None

    return Endpoint("vmess", host, port, net, tag, raw_line=line)


def _parse_url_scheme(line: str, scheme: str) -> Optional[Endpoint]:
    try:
        u = urlparse(line.strip())
        if u.scheme != scheme:
            return None
        host = u.hostname
        port = u.port
        qs = parse_qs(u.query)
        net = (qs.get("type", ["tcp"])[0] or "tcp").strip()
        tag = (u.fragment or "").strip()
        if not host or not port:
            return None
        return Endpoint(scheme, host, int(port), net, tag, raw_line=line.strip())
    except Exception:
        return None


def parse_ss(line: str) -> Optional[Endpoint]:
    s = line.strip()
    if not s.startswith("ss://"):
        return None

    tag = ""
    if "#" in s:
        s, frag = s.split("#", 1)
        tag = unquote(frag).strip()

    body = s[len("ss://"):].strip().split("?", 1)[0]

    try:
        if "@" in body:
            _, right = body.split("@", 1)
            host, port_str = right.rsplit(":", 1)
            return Endpoint("ss", host.strip("[]"), int(port_str), "tcp", tag, raw_line=line.strip())

        dec = _b64_decode_any(body).decode("utf-8", errors="replace")
        _, addr = dec.rsplit("@", 1)
        host, port_str = addr.rsplit(":", 1)
        return Endpoint("ss", host.strip("[]"), int(port_str), "tcp", tag, raw_line=line.strip())
    except Exception:
        return None


def parse_any_line(line: str) -> Optional[Endpoint]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if line.startswith("vmess://"):
        return parse_vmess(line)
    if line.startswith("vless://"):
        return _parse_url_scheme(line, "vless")
    if line.startswith("trojan://"):
        return _parse_url_scheme(line, "trojan")
    if line.startswith("ss://"):
        return parse_ss(line)
    return None


def extract_endpoints(lines: Iterable[str]) -> List[Endpoint]:
    out: List[Endpoint] = []
    for ln in lines:
        ep = parse_any_line(ln)
        if ep:
            out.append(ep)
    return out


# =========================
# TCP / UDP probes
# =========================
def tcp_connect_ms(host: str, port: int, timeout: float) -> float:
    start = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout):
        pass
    return (time.perf_counter() - start) * 1000.0


def measure_tcp(host: str, port: int, tries: int, timeout: float) -> Tuple[Optional[float], int]:
    times: List[float] = []
    fails = 0
    for _ in range(tries):
        try:
            times.append(tcp_connect_ms(host, port, timeout))
        except Exception:
            fails += 1
    if not times:
        return None, fails
    return statistics.mean(times), fails


def measure_udp(host: str, port: int, timeout: float) -> Tuple[Optional[float], str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        start = time.perf_counter()
        s.send(b"\x00")
        try:
            _ = s.recv(1)
            return (time.perf_counter() - start) * 1000.0, "reply"
        except socket.timeout:
            return None, "no_reply"
        except OSError:
            return None, "oserror"
    finally:
        s.close()
