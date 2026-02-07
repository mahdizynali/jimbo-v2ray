import base64, json, os, re, socket, statistics, subprocess, time, tempfile
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import requests
from rich.console import Console
from rich.text import Text

console = Console()

DEFAULT_WORKERS = 4 
TCP_TRIES = 2
TCP_TIMEOUT = 3.0
UDP_TRIES = 1
UDP_TIMEOUT = 2.0

DOWNLOAD_TEST_URL = "https://www.google.com/generate_204"
DOWNLOAD_TIMEOUT = 12.0
SINGBOX_BIN = "sing-box"

VMESS_RE = re.compile(r"^vmess://([A-Za-z0-9+/=_-]+)")
VLESS_RE = re.compile(r"^vless://\S+")
TROJAN_RE = re.compile(r"^trojan://\S+")
SS_RE = re.compile(r"^ss://\S+")

PRINT_LOCK = threading.Lock()
PORT_LOCK = threading.Lock()
NEXT_PORT = 20000  # sequential socks ports per worker run

# -------- types --------
@dataclass(frozen=True)
class Endpoint:
    scheme: str
    host: str
    port: int
    network: str
    tag: str = ""
    raw_line: str = ""

@dataclass
class ScanResult:
    idx: int
    total: int
    ep: Endpoint
    tcp_avg: Optional[float]
    tcp_fails: int
    udp_avg: Optional[float]
    udp_status: str
    dl_ok: bool
    dl_reason: str
    dl_ms: Optional[float]
    http_status: Optional[int]
    alive: bool
    line_out: str

# -------- parsing --------
def _b64_decode_any(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * ((-len(s)) % 4)
    return base64.b64decode(s)

def _clean_share_line(line: str) -> str:
    s = line.strip()
    if s.startswith("vmess://"):
        m = re.search(r"^vmess://([A-Za-z0-9+/=_-]+)", s)
        if m:
            return "vmess://" + m.group(1)
    return s

def parse_vmess_line(line: str) -> Optional[Endpoint]:
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

def parse_vless_line(line: str) -> Optional[Endpoint]:
    s = line.strip()
    if not s.startswith("vless://"):
        return None
    try:
        u = urlparse(s)
        host = u.hostname
        port = u.port
        qs = parse_qs(u.query)
        net = (qs.get("type", ["tcp"])[0] or "tcp").strip()
        tag = (u.fragment or "").strip()
        if not host or not port:
            return None
        return Endpoint("vless", host, int(port), net, tag, raw_line=s)
    except Exception:
        return None

def parse_trojan_line(line: str) -> Optional[Endpoint]:
    s = line.strip()
    if not s.startswith("trojan://"):
        return None
    try:
        u = urlparse(s)
        host = u.hostname
        port = u.port
        qs = parse_qs(u.query)
        net = (qs.get("type", ["tcp"])[0] or "tcp").strip()
        tag = (u.fragment or "").strip()
        if not host or not port:
            return None
        return Endpoint("trojan", host, int(port), net, tag, raw_line=s)
    except Exception:
        return None

def parse_ss_line(line: str) -> Optional[Endpoint]:
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
        return parse_vmess_line(line)
    if line.startswith("vless://"):
        return parse_vless_line(line)
    if line.startswith("trojan://"):
        return parse_trojan_line(line)
    if line.startswith("ss://"):
        return parse_ss_line(line)
    return None

def extract_endpoints(lines: Iterable[str]) -> List[Endpoint]:
    out = []
    for ln in lines:
        ep = parse_any_line(ln)
        if ep:
            out.append(ep)
    return out

# -------- measurements --------
def tcp_connect_ms(host: str, port: int, timeout: float) -> float:
    start = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout):
        pass
    return (time.perf_counter() - start) * 1000.0

def measure_tcp(host: str, port: int) -> Tuple[Optional[float], int]:
    times, fails = [], 0
    for _ in range(TCP_TRIES):
        try:
            times.append(tcp_connect_ms(host, port, TCP_TIMEOUT))
        except Exception:
            fails += 1
    if not times:
        return None, fails
    return statistics.mean(times), fails

def udp_probe_ms(host: str, port: int, timeout: float) -> Tuple[Optional[float], str]:
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

def measure_udp(host: str, port: int) -> Tuple[Optional[float], str]:
    rtts, status = [], "no_reply"
    for _ in range(UDP_TRIES):
        rtt, st = udp_probe_ms(host, port, UDP_TIMEOUT)
        status = st
        if rtt is not None:
            rtts.append(rtt)
    if rtts:
        return statistics.mean(rtts), "reply"
    return None, status

# -------- sing-box engine --------
def has_singbox() -> bool:
    try:
        r = subprocess.run([SINGBOX_BIN, "version"], capture_output=True, text=True, timeout=3)
        return r.returncode == 0
    except Exception:
        return False

def _safe_int(v, default: int):
    try:
        return int(v)
    except Exception:
        return default

def _vmess_to_outbound(ep: Endpoint) -> dict:
    b64 = VMESS_RE.match(ep.raw_line).group(1)  # type: ignore
    data = json.loads(_b64_decode_any(b64).decode("utf-8", errors="replace"))
    server = (data.get("add") or "").strip()
    port = _safe_int(data.get("port"), ep.port)
    uuid_ = (data.get("id") or "").strip()
    security = (data.get("scy") or "auto").strip() or "auto"
    net = (data.get("net") or "tcp").strip() or "tcp"
    host = (data.get("host") or "").strip()
    path = (data.get("path") or "").strip() or "/"
    tls_val = (data.get("tls") or "").strip()
    sni = (data.get("sni") or "").strip() or (host if host else "")

    ob = {"type": "vmess", "tag": "proxy", "server": server, "server_port": port,
          "uuid": uuid_, "security": security, "alter_id": 0}

    tls_enabled = tls_val in ("tls", "reality") or (port == 443 and tls_val != "none")
    if tls_enabled:
        ob["tls"] = {"enabled": True}
        if sni:
            ob["tls"]["server_name"] = sni

    if net == "ws":
        ob["transport"] = {"type": "ws", "path": path}
        if host:
            ob["transport"]["headers"] = {"Host": host}
    elif net == "grpc":
        svc = (data.get("serviceName") or data.get("servicename") or "").strip()
        ob["transport"] = {"type": "grpc"}
        if svc:
            ob["transport"]["service_name"] = svc
    return ob

def _vless_to_outbound(ep: Endpoint) -> dict:
    u = urlparse(ep.raw_line)
    uuid_ = (u.username or "").strip()
    server = u.hostname or ep.host
    port = u.port or ep.port
    qs = parse_qs(u.query)
    transport = (qs.get("type", ["tcp"])[0] or "tcp").strip()
    security = (qs.get("security", [""])[0] or "").strip()
    sni = (qs.get("sni", [""])[0] or qs.get("host", [""])[0] or "").strip()
    path = (qs.get("path", [""])[0] or "/")
    host = (qs.get("host", [""])[0] or "").strip()
    service_name = (qs.get("serviceName", [""])[0] or "").strip()

    ob = {"type": "vless", "tag": "proxy", "server": server, "server_port": port, "uuid": uuid_}
    flow = (qs.get("flow", [""])[0] or "").strip()
    if flow:
        ob["flow"] = flow

    if security in ("tls", "reality"):
        ob["tls"] = {"enabled": True}
        if sni:
            ob["tls"]["server_name"] = sni

    if transport == "ws":
        ob["transport"] = {"type": "ws", "path": path}
        if host:
            ob["transport"]["headers"] = {"Host": host}
    elif transport == "grpc":
        ob["transport"] = {"type": "grpc"}
        if service_name:
            ob["transport"]["service_name"] = service_name
    return ob

def _trojan_to_outbound(ep: Endpoint) -> dict:
    u = urlparse(ep.raw_line)
    password = (u.username or "").strip()
    server = u.hostname or ep.host
    port = u.port or ep.port
    qs = parse_qs(u.query)
    sni = (qs.get("sni", [""])[0] or qs.get("peer", [""])[0] or "").strip()
    transport = (qs.get("type", ["tcp"])[0] or "tcp").strip()
    path = (qs.get("path", [""])[0] or "/")
    host = (qs.get("host", [""])[0] or "").strip()

    ob = {"type": "trojan", "tag": "proxy", "server": server, "server_port": port,
          "password": password, "tls": {"enabled": True}}
    if sni:
        ob["tls"]["server_name"] = sni
    if transport == "ws":
        ob["transport"] = {"type": "ws", "path": path}
        if host:
            ob["transport"]["headers"] = {"Host": host}
    return ob

def _ss_to_outbound(ep: Endpoint) -> dict:
    s = ep.raw_line.strip()
    if "#" in s:
        s = s.split("#", 1)[0]
    body = s[len("ss://"):].split("?", 1)[0]

    if "@" in body:
        left, right = body.split("@", 1)
        left_dec = _b64_decode_any(left).decode("utf-8", errors="replace") if ":" not in left else left
        method, password = left_dec.split(":", 1)
        host, port_str = right.rsplit(":", 1)
        server = host.strip("[]"); port = int(port_str)
    else:
        dec = _b64_decode_any(body).decode("utf-8", errors="replace")
        creds, addr = dec.rsplit("@", 1)
        method, password = creds.split(":", 1)
        host, port_str = addr.rsplit(":", 1)
        server = host.strip("[]"); port = int(port_str)

    return {"type": "shadowsocks", "tag": "proxy", "server": server, "server_port": port,
            "method": method.strip(), "password": password.strip()}

def make_singbox_config(ep: Endpoint, socks_port: int) -> dict:
    if ep.scheme == "vmess":
        outbound = _vmess_to_outbound(ep)
    elif ep.scheme == "vless":
        outbound = _vless_to_outbound(ep)
    elif ep.scheme == "trojan":
        outbound = _trojan_to_outbound(ep)
    elif ep.scheme == "ss":
        outbound = _ss_to_outbound(ep)
    else:
        raise ValueError("unsupported")

    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socks_port}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"inbound": "socks-in", "outbound": "proxy"}], "auto_detect_interface": True},
    }

def _alloc_socks_port() -> int:
    global NEXT_PORT
    with PORT_LOCK:
        p = NEXT_PORT
        NEXT_PORT += 1
        if NEXT_PORT > 39999:
            NEXT_PORT = 20000
        return p

def run_singbox(ep: Endpoint, socks_port: int) -> subprocess.Popen:
    cfg = make_singbox_config(ep, socks_port)
    tmpdir = tempfile.mkdtemp(prefix="scan_")
    cfg_path = os.path.join(tmpdir, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    return subprocess.Popen([SINGBOX_BIN, "run", "-c", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def _short_dl_reason(err: Exception) -> str:
    s = str(err)
    if "timed out" in s:
        return "timeout"
    if "Max retries exceeded" in s:
        return "retries"
    if "Connection refused" in s:
        return "refused"
    if "Name or service not known" in s or "Temporary failure in name resolution" in s:
        return "dns"
    return "failed"

def download_test_via_socks(socks_port: int) -> Tuple[bool, str, Optional[float], Optional[int]]:
    proxies = {"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"}
    start = time.perf_counter()
    try:
        r = requests.get(DOWNLOAD_TEST_URL, proxies=proxies, timeout=DOWNLOAD_TIMEOUT, allow_redirects=True)
        ms = (time.perf_counter() - start) * 1000.0
        ok = 200 <= r.status_code < 400
        return ok, ("ok" if ok else "bad_status"), ms, r.status_code
    except Exception as e:
        return False, _short_dl_reason(e), None, None

def real_download_test(ep: Endpoint) -> Tuple[bool, str, Optional[float], Optional[int]]:
    if not has_singbox():
        return False, "no_singbox", None, None
    socks_port = _alloc_socks_port()
    p = None
    try:
        p = run_singbox(ep, socks_port)
        time.sleep(0.8)
        return download_test_via_socks(socks_port)
    except Exception:
        return False, "engine_error", None, None
    finally:
        if p:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                pass

# -------- display helpers --------
def ms(v: Optional[float]) -> str:
    return f"{v:.1f}ms" if v is not None else "—"

def style_tcp(avg: Optional[float], fails: int) -> Text:
    if avg is None:
        return Text(f"TCP {ms(avg)}  fails={fails}", style="bold red")
    return Text(f"TCP {ms(avg)}  fails={fails}", style=("bold green" if fails == 0 else "bold yellow"))

def style_udp(avg: Optional[float], status: str) -> Text:
    if status == "reply" and avg is not None:
        return Text(f"UDP {ms(avg)}  {status}", style="bold green")
    if status == "no_reply":
        return Text(f"UDP {ms(avg)}  {status}", style="bold red")
    return Text(f"UDP {ms(avg)}  {status}", style="bold yellow")

def style_dl(ok: bool, dl_ms: Optional[float], http_status: Optional[int]) -> Text:
    if ok:
        s = f"Download ✓ {ms(dl_ms)}"
        if http_status is not None:
            s += f"  http={http_status}"
        return Text(s, style="bold green")
    return Text("Download ✗", style="bold red")

def ensure_scan_root() -> Tuple[str, str, str]:
    scan_root = "scan_results"
    os.makedirs(scan_root, exist_ok=True)
    whitelist_dir = os.path.join(scan_root, "whitelist")
    failed_dir = os.path.join(scan_root, "failed_configs")
    os.makedirs(whitelist_dir, exist_ok=True)
    os.makedirs(failed_dir, exist_ok=True)
    return scan_root, whitelist_dir, failed_dir

def _sep_line_white() -> Text:
    w = max(60, console.size.width - 2)
    return Text("─" * w, style="white")

def _print_block(idx: int, total: int, ep: Endpoint, tcp_avg: Optional[float], tcp_fails: int,
                 udp_avg: Optional[float], udp_status: str, dl_ok: bool, dl_ms: Optional[float], http_status: Optional[int]):
    with PRINT_LOCK:
        console.print(_sep_line_white())
        head = f"[{idx}/{total}] {ep.scheme.upper()} {ep.host}:{ep.port} ({ep.network})"
        if ep.tag:
            head += f"  {ep.tag}"
        console.print(Text(head, style="bold"))
        console.print(Text(ep.raw_line, style="white"))
        console.print(style_tcp(tcp_avg, tcp_fails))
        console.print(style_udp(udp_avg, udp_status))
        console.print(style_dl(dl_ok, dl_ms, http_status))

# -------- worker --------
def scan_one(idx: int, total: int, ep: Endpoint) -> ScanResult:
    tcp_avg, tcp_fails = measure_tcp(ep.host, ep.port)
    udp_avg, udp_status = measure_udp(ep.host, ep.port)
    dl_ok, dl_reason, dl_ms, http_status = real_download_test(ep)
    alive = bool(dl_ok)

    _print_block(idx, total, ep, tcp_avg, tcp_fails, udp_avg, udp_status, dl_ok, dl_ms, http_status)

    line_out = (
        f"{'ALIVE' if alive else 'DEAD'}\t{ep.scheme}\t{ep.network}\t{ep.host}\t{ep.port}\t"
        f"tcp_avg={tcp_avg if tcp_avg is not None else 'FAIL'}\t"
        f"udp={udp_status}\t"
        f"dl={dl_reason}\tms={dl_ms if dl_ms is not None else '—'}\thttp={http_status if http_status is not None else '—'}\n"
    )

    return ScanResult(
        idx=idx, total=total, ep=ep,
        tcp_avg=tcp_avg, tcp_fails=tcp_fails,
        udp_avg=udp_avg, udp_status=udp_status,
        dl_ok=dl_ok, dl_reason=dl_reason, dl_ms=dl_ms, http_status=http_status,
        alive=alive, line_out=line_out
    )

# -------- main entry used by app.py --------
def scan_file(input_txt: str, base_dir: str, today_str: str, day_dir: str, workers: int = DEFAULT_WORKERS):
    scan_root, whitelist_dir, failed_dir = ensure_scan_root()
    ts = datetime.now().strftime("%H%M%S")

    results_path = os.path.join(scan_root, f"results_{ts}.txt")
    whitelist_path = os.path.join(whitelist_dir, f"whitelist_{ts}.txt")
    failed_path = os.path.join(failed_dir, f"failed_{ts}.txt")

    with open(input_txt, "r", encoding="utf-8", errors="replace") as f:
        endpoints = extract_endpoints(f.read().splitlines())
    total = len(endpoints)

    console.print(Text("SCAN", style="bold cyan"), f"file={input_txt}")
    console.print(f"configs={total}  workers={workers}  engine={'sing-box ✅' if has_singbox() else 'sing-box ❌'}")
    console.print(f"out={results_path}\n")

    results: List[Optional[ScanResult]] = [None] * total

    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(scan_one, i + 1, total, ep) for i, ep in enumerate(endpoints)]
            for fut in as_completed(futs):
                r = fut.result()
                results[r.idx - 1] = r
    except KeyboardInterrupt:
        console.print(Text("\nStopped (Ctrl+C).", style="yellow"))

    alive_lines: List[str] = []
    failed_lines: List[str] = []

    with open(results_path, "w", encoding="utf-8") as out:
        for r in results:
            if r is None:
                continue
            out.write(r.line_out)
            if r.alive:
                alive_lines.append(r.ep.raw_line)
            else:
                failed_lines.append(r.ep.raw_line)

    if alive_lines:
        with open(whitelist_path, "w", encoding="utf-8") as wf:
            wf.write("\n".join(alive_lines) + "\n")
    else:
        whitelist_path = None

    if failed_lines:
        with open(failed_path, "w", encoding="utf-8") as ff:
            ff.write("\n".join(failed_lines) + "\n")
    else:
        failed_path = None

    console.print(_sep_line_white())
    console.print(Text(f"SUMMARY  ALIVE {len(alive_lines)}/{total}", style="bold green" if alive_lines else "bold red"))
    console.print(f"Whitelist: {whitelist_path or '(not created)'}")
    console.print(f"Failed:    {failed_path or '(not created)'}")
    console.print(f"Results:   {results_path}")
