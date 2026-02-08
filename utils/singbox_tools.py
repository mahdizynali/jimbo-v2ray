import hashlib
import json
import os
import subprocess
import tempfile
import time
from typing import Optional, Tuple
from urllib.parse import parse_qs, urlparse

import requests

from .scanner_core import Endpoint, VMESS_RE, _b64_decode_any


def has_singbox(bin_name: str = "sing-box") -> bool:
    try:
        r = subprocess.run([bin_name, "version"], capture_output=True, text=True, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


def _short_dl_reason(err: Exception) -> str:
    s = str(err).lower()
    if "timed out" in s:
        return "timeout"
    if "max retries exceeded" in s:
        return "retries"
    if "refused" in s:
        return "refused"
    if "name or service not known" in s or "temporary failure in name resolution" in s:
        return "dns"
    return "failed"


def _alloc_socks_port(ep: Endpoint) -> int:
    h = int(hashlib.sha1(ep.raw_line.encode("utf-8")).hexdigest()[:6], 16)
    return 20000 + (h % 15000)


def _safe_int(v, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


# =========================
# Outbound builders
# =========================
def _vmess_outbound(ep: Endpoint) -> dict:
    b64 = VMESS_RE.match(ep.raw_line).group(1)
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

    ob = {
        "type": "vmess",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "uuid": uuid_,
        "security": security,
        "alter_id": 0,
    }

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


def _vless_outbound(ep: Endpoint) -> dict:
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
    flow = (qs.get("flow", [""])[0] or "").strip()

    ob = {"type": "vless", "tag": "proxy", "server": server, "server_port": port, "uuid": uuid_}
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


def _trojan_outbound(ep: Endpoint) -> dict:
    u = urlparse(ep.raw_line)
    password = (u.username or "").strip()
    server = u.hostname or ep.host
    port = u.port or ep.port
    qs = parse_qs(u.query)

    sni = (qs.get("sni", [""])[0] or qs.get("peer", [""])[0] or "").strip()
    transport = (qs.get("type", ["tcp"])[0] or "tcp").strip()
    path = (qs.get("path", [""])[0] or "/")
    host = (qs.get("host", [""])[0] or "").strip()

    ob = {
        "type": "trojan",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "password": password,
        "tls": {"enabled": True},
    }
    if sni:
        ob["tls"]["server_name"] = sni
    if transport == "ws":
        ob["transport"] = {"type": "ws", "path": path}
        if host:
            ob["transport"]["headers"] = {"Host": host}

    return ob


def _ss_outbound(ep: Endpoint) -> dict:
    s = ep.raw_line.strip()
    if "#" in s:
        s = s.split("#", 1)[0]
    body = s[len("ss://"):].split("?", 1)[0]

    if "@" in body:
        left, right = body.split("@", 1)
        left_dec = _b64_decode_any(left).decode("utf-8", errors="replace") if ":" not in left else left
        method, password = left_dec.split(":", 1)
        host, port_str = right.rsplit(":", 1)
        server = host.strip("[]")
        port = int(port_str)
    else:
        dec = _b64_decode_any(body).decode("utf-8", errors="replace")
        creds, addr = dec.rsplit("@", 1)
        method, password = creds.split(":", 1)
        host, port_str = addr.rsplit(":", 1)
        server = host.strip("[]")
        port = int(port_str)

    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "method": method.strip(),
        "password": password.strip(),
    }


def make_singbox_config(ep: Endpoint, socks_port: int) -> dict:
    if ep.scheme == "vmess":
        outbound = _vmess_outbound(ep)
    elif ep.scheme == "vless":
        outbound = _vless_outbound(ep)
    elif ep.scheme == "trojan":
        outbound = _trojan_outbound(ep)
    elif ep.scheme == "ss":
        outbound = _ss_outbound(ep)
    else:
        raise ValueError("unsupported scheme")

    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socks_port}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"inbound": "socks-in", "outbound": "proxy"}], "auto_detect_interface": True},
    }


def real_download_test(
    ep: Endpoint,
    *,
    enabled: bool,
    bin_name: str,
    test_url: str,
    timeout: float,
) -> Tuple[bool, str, Optional[float], Optional[int]]:
    if not (enabled and has_singbox(bin_name)):
        return False, "skipped", None, None

    socks_port = _alloc_socks_port(ep)
    tmpdir = tempfile.mkdtemp(prefix="scan_")
    cfg_path = os.path.join(tmpdir, "config.json")

    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(make_singbox_config(ep, socks_port), f)

        p = subprocess.Popen([bin_name, "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.8)
            proxies = {
                "http": f"socks5h://127.0.0.1:{socks_port}",
                "https": f"socks5h://127.0.0.1:{socks_port}",
            }
            start = time.perf_counter()
            r = requests.get(test_url, proxies=proxies, timeout=timeout, allow_redirects=True)
            ms = (time.perf_counter() - start) * 1000.0
            ok = 200 <= r.status_code < 400
            return ok, ("ok" if ok else "bad_status"), ms, r.status_code
        except Exception as e:
            return False, _short_dl_reason(e), None, None
        finally:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                pass
    finally:
        try:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
            os.rmdir(tmpdir)
        except Exception:
            pass
