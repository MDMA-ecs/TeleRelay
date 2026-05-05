# tester.py
import asyncio
import base64
import html
import ipaddress
import json
import os
import random
import re
import socket
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import aiohttp


_INVISIBLES = [
    "\u200b", "\u200c", "\u200d", "\ufeff",
    "\u2060", "\u00ad",
    "\u200e", "\u200f",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
]


def _clean_linkish(s: str) -> str:
    s = str(s or "")
    for ch in _INVISIBLES:
        s = s.replace(ch, "")
    try:
        s = html.unescape(s)
    except Exception:
        pass
    return s.strip()


@dataclass
class TestResult:
    ok: bool
    latency_ms: Optional[int] = None
    exit_ip: Optional[str] = None
    ok_count: int = 0
    tries: int = 1
    stage: str = "ok"
    stage_detail: Optional[str] = None
    ok_endpoint: Optional[str] = None
    probe_results: Optional[List[Dict[str, Any]]] = None
    tls_telemetry: Optional[Dict[str, Any]] = None
    ws_probe: Optional[Dict[str, Any]] = None
    grpc_probe: Optional[Dict[str, Any]] = None
    ok_count_v4: int = 0
    ok_count_v6: int = 0
    ip_version: Optional[str] = None
    egress_consistent: Optional[bool] = None
    handshake_ok: Optional[bool] = None
    handshake_detail: Optional[Dict[str, Any]] = None


@dataclass
class EndpointProbeResult:
    endpoint: str
    ok: bool
    latency_ms: Optional[int] = None
    ip: Optional[str] = None
    ip_version: Optional[str] = None
    stage: str = "ok"
    detail: Optional[str] = None

    def as_dict(self, try_no: int) -> Dict[str, Any]:
        return {
            "try": int(try_no),
            "endpoint": self.endpoint,
            "ok": bool(self.ok),
            "latency_ms": self.latency_ms,
            "ip": self.ip,
            "ip_version": self.ip_version,
            "stage": self.stage,
            "detail": self.detail,
        }


RE_IP = re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3})|(?:[0-9A-Fa-f:]{2,})")

DEFAULT_IP_ECHO_ENDPOINTS: List[str] = [
    "https://api.ipify.org?format=json",
    "https://api64.ipify.org?format=json",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://ipinfo.io/ip",
]


def flag_emoji_from_cc(country_code: str) -> str:
    cc = (country_code or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return "🏳️"
    return chr(0x1F1E6 + (ord(cc[0]) - ord("A"))) + chr(0x1F1E6 + (ord(cc[1]) - ord("A")))


def grade_from_latency(latency_ms: int, good_ms: int, ok_ms: int) -> str:
    if latency_ms <= good_ms:
        return "AA"
    if latency_ms <= ok_ms:
        return "BB"
    return "CC"


def grade_label(code: str) -> Tuple[str, str]:
    code = (code or "").upper()
    if code == "AA":
        return "🟢", "Turbo"
    if code == "BB":
        return "🟡", "OK"
    return "🔴", "Meh"


def url_encode_name(name: str) -> str:
    return urllib.parse.quote(name, safe="")


def _safe_json_dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def normalize_config_for_fp(raw: str) -> str:
    raw = _clean_linkish(raw)

    if raw.startswith(("vless://", "trojan://", "ss://")):
        return raw.split("#", 1)[0]

    if raw.startswith("vmess://"):
        b64s = raw[len("vmess://") :].strip()
        b64s = b64s.replace("-", "+").replace("_", "/")
        try:
            pad = "=" * (-len(b64s) % 4)
            data = base64.b64decode(b64s + pad)
            j = json.loads(data.decode("utf-8", errors="ignore"))
            if isinstance(j, dict):
                j["ps"] = ""
                out = base64.b64encode(_safe_json_dumps(j).encode("utf-8")).decode("utf-8")
                return "vmess://" + out
        except Exception:
            return raw

    return raw


def apply_rename(raw: str, new_name: str) -> str:
    raw = _clean_linkish(raw)

    if raw.startswith(("vless://", "trojan://", "ss://")):
        base = raw.split("#", 1)[0]
        return f"{base}#{url_encode_name(new_name)}"

    if raw.startswith("vmess://"):
        b64s = raw[len("vmess://") :].strip()
        b64s = b64s.replace("-", "+").replace("_", "/")
        try:
            pad = "=" * (-len(b64s) % 4)
            data = base64.b64decode(b64s + pad)
            j = json.loads(data.decode("utf-8", errors="ignore"))
            if isinstance(j, dict):
                j["ps"] = new_name
                out = base64.b64encode(_safe_json_dumps(j).encode("utf-8")).decode("utf-8")
                return "vmess://" + out
        except Exception:
            pass
        return raw.split("#", 1)[0] + f"#{url_encode_name(new_name)}"

    return raw


def _pick_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def pick_socks_port() -> int:
    for _ in range(20):
        p = random.randint(20000, 45000)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return _pick_free_port()


async def geoip_ipapi_full(ip: str, timeout_sec: int = 6) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,as,org,isp"
    timeout = aiohttp.ClientTimeout(total=timeout_sec)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as resp:
            j = await resp.json(content_type=None)
            if j.get("status") == "success":
                cc = j.get("countryCode")
                country = j.get("country")
                asn = j.get("as")
                org = j.get("org") or j.get("isp")
                return cc, country, asn, org
    return None, None, None, None


def _normalize_endpoints(endpoints: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    seen = set()
    for e in (endpoints or DEFAULT_IP_ECHO_ENDPOINTS):
        s = str(e or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out or list(DEFAULT_IP_ECHO_ENDPOINTS)


def _extract_ip_from_output(text: str) -> Optional[str]:
    raw = (text or "").strip()
    if not raw:
        return None

    try:
        j = json.loads(raw)
        if isinstance(j, dict):
            v = j.get("ip")
            if v:
                raw = str(v).strip()
    except Exception:
        pass

    # Some endpoints may return values separated by commas/spaces.
    # Pick first valid IP token.
    for token in re.split(r"[\s,]+", raw):
        t = token.strip()
        if not t:
            continue
        try:
            ipaddress.ip_address(t)
            return t
        except Exception:
            continue

    m = RE_IP.search(raw)
    if m:
        candidate = m.group(0)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except Exception:
            return None
    return None


def _ip_version_of(ip: Optional[str]) -> Optional[str]:
    s = str(ip or "").strip()
    if not s:
        return None
    try:
        obj = ipaddress.ip_address(s)
        return "ipv4" if obj.version == 4 else "ipv6"
    except Exception:
        return None


def _classify_curl_failure(stderr_text: str, stdout_text: str) -> str:
    low = ((stderr_text or "") + "\n" + (stdout_text or "")).lower()

    if (
        "could not resolve host" in low
        or "name or service not known" in low
        or "temporary failure in name resolution" in low
        or "couldn't resolve host" in low
    ):
        return "dns_fail"

    if (
        "ssl" in low
        or "tls" in low
        or "certificate" in low
        or "handshake" in low
        or "wrong version number" in low
    ):
        return "tls_fail"

    if (
        "failed to connect" in low
        or "connection refused" in low
        or "connection timed out" in low
        or "network is unreachable" in low
        or "proxy connect aborted" in low
        or "connection reset by peer" in low
        or "operation timed out" in low
    ):
        return "tcp_fail"

    return "ip_echo_fail"


def _summarize_error(stderr_text: str, stdout_text: str, max_chars: int = 220) -> str:
    s = (stderr_text or "").strip() or (stdout_text or "").strip() or "no_detail"
    s = re.sub(r"\s+", " ", s)
    if len(s) <= max_chars:
        return s
    return s[: max_chars - 1] + "…"


async def _curl_ip_probe(curl_bin: str, socks_port: int, timeout_sec: int, endpoint: str) -> EndpointProbeResult:
    t0 = time.perf_counter()
    curl = await asyncio.create_subprocess_exec(
        curl_bin,
        "-sS",
        "--max-time",
        str(timeout_sec),
        "--socks5-hostname",
        f"127.0.0.1:{socks_port}",
        endpoint,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await curl.communicate()
    dt_ms = int((time.perf_counter() - t0) * 1000)
    out_s = out.decode("utf-8", errors="ignore")
    err_s = err.decode("utf-8", errors="ignore")

    if curl.returncode != 0:
        return EndpointProbeResult(
            endpoint=endpoint,
            ok=False,
            latency_ms=dt_ms,
            ip=None,
            ip_version=None,
            stage=_classify_curl_failure(err_s, out_s),
            detail=_summarize_error(err_s, out_s),
        )

    ip = _extract_ip_from_output(out_s)
    if not ip:
        return EndpointProbeResult(
            endpoint=endpoint,
            ok=False,
            latency_ms=dt_ms,
            ip=None,
            ip_version=None,
            stage="ip_echo_fail",
            detail="endpoint_response_without_ip",
        )

    return EndpointProbeResult(
        endpoint=endpoint,
        ok=True,
        latency_ms=dt_ms,
        ip=ip,
        ip_version=_ip_version_of(ip),
        stage="ok",
        detail=None,
    )


def _extract_outbound_meta(xray_config: Dict[str, Any]) -> Dict[str, Any]:
    ob = ((xray_config or {}).get("outbounds") or [{}])[0] or {}
    ss = ob.get("streamSettings") or {}
    settings = ob.get("settings") or {}
    proto = str(ob.get("protocol") or "").lower()
    network = str(ss.get("network") or "tcp").lower()
    security = str(ss.get("security") or "none").lower()

    host = None
    port = None
    if proto in ("vless", "vmess"):
        arr = settings.get("vnext") or []
        if arr:
            host = arr[0].get("address")
            port = arr[0].get("port")
    elif proto in ("trojan", "shadowsocks"):
        arr2 = settings.get("servers") or []
        if arr2:
            host = arr2[0].get("address")
            port = arr2[0].get("port")

    tls_s = ss.get("tlsSettings") or {}
    reality_s = ss.get("realitySettings") or {}
    ws_s = ss.get("wsSettings") or {}
    grpc_s = ss.get("grpcSettings") or {}

    sni = tls_s.get("serverName") or reality_s.get("serverName")
    alpn = tls_s.get("alpn") or reality_s.get("alpn")
    if isinstance(alpn, str):
        alpn = [x.strip() for x in alpn.split(",") if x.strip()]
    if not isinstance(alpn, list):
        alpn = None

    return {
        "protocol": proto,
        "network": network,
        "security": security,
        "host": str(host) if host else None,
        "port": int(port) if port is not None else None,
        "sni": str(sni) if sni else None,
        "alpn": alpn,
        "ws_path": str(ws_s.get("path") or "/"),
        "ws_host_header": (ws_s.get("headers") or {}).get("Host"),
        "grpc_service_name": str(grpc_s.get("serviceName") or "").strip().lstrip("/") or None,
    }


def _build_url(meta: Dict[str, Any], path: str = "/") -> Optional[str]:
    host = meta.get("host")
    port = meta.get("port")
    if not host or not port:
        return None
    scheme = "https" if str(meta.get("security") or "").lower() in ("tls", "reality") else "http"
    p = str(path or "/")
    if not p.startswith("/"):
        p = "/" + p
    return f"{scheme}://{host}:{int(port)}{p}"


def _parse_http_status_and_headers(text: str) -> Tuple[Optional[int], Dict[str, str], Optional[str]]:
    lines = (text or "").splitlines()
    if not lines:
        return None, {}, None

    idx = -1
    for i, ln in enumerate(lines):
        if re.match(r"^HTTP/\d(?:\.\d)?\s+\d{3}", ln.strip()):
            idx = i

    if idx < 0:
        return None, {}, None

    status_line = lines[idx].strip()
    code = None
    m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", status_line)
    if m:
        try:
            code = int(m.group(1))
        except Exception:
            code = None

    headers: Dict[str, str] = {}
    for ln in lines[idx + 1 :]:
        s = ln.strip()
        if not s:
            break
        if ":" not in s:
            continue
        k, v = s.split(":", 1)
        headers[k.strip().lower()] = v.strip()

    return code, headers, status_line


async def _curl_tls_telemetry(curl_bin: str, socks_port: int, timeout_sec: int, meta: Dict[str, Any]) -> Dict[str, Any]:
    security = str(meta.get("security") or "").lower()
    if security not in ("tls", "reality"):
        return {"attempted": False, "stage": "skip_no_tls", "detail": "security_not_tls"}

    url = _build_url(meta, "/")
    if not url:
        return {"attempted": False, "stage": "skip_no_target", "detail": "missing_host_or_port"}

    args = [
        curl_bin,
        "-v",
        "-I",
        "--max-time",
        str(timeout_sec),
        "--socks5-hostname",
        f"127.0.0.1:{socks_port}",
        url,
        "-o",
        os.devnull,
    ]
    if meta.get("sni"):
        # Helps when endpoint is IP-based and SNI is required.
        args.extend(["--header", f"Host: {meta['sni']}"])

    t0 = time.perf_counter()
    p = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await p.communicate()
    dt_ms = int((time.perf_counter() - t0) * 1000)
    out_s = out.decode("utf-8", errors="ignore")
    err_s = err.decode("utf-8", errors="ignore")

    if p.returncode != 0:
        return {
            "attempted": True,
            "ok": False,
            "latency_ms": dt_ms,
            "stage": _classify_curl_failure(err_s, out_s),
            "detail": _summarize_error(err_s, out_s),
        }

    tls_version = None
    cipher = None
    m = re.search(r"SSL connection using\s+([^\s/]+)(?:\s*/\s*([^\r\n]+))?", err_s, flags=re.IGNORECASE)
    if m:
        tls_version = (m.group(1) or "").strip() or None
        cipher = (m.group(2) or "").strip() or None

    alpn_selected = None
    m2 = re.search(r"ALPN.*?(?:accepted|use)\s+([^\r\n]+)", err_s, flags=re.IGNORECASE)
    if m2:
        alpn_selected = (m2.group(1) or "").strip() or None

    subject = None
    issuer = None
    sm = re.search(r"subject:\s*([^\r\n]+)", err_s, flags=re.IGNORECASE)
    im = re.search(r"issuer:\s*([^\r\n]+)", err_s, flags=re.IGNORECASE)
    if sm:
        subject = (sm.group(1) or "").strip() or None
    if im:
        issuer = (im.group(1) or "").strip() or None

    san = None
    sanm = re.search(r"subjectaltname:\s*([^\r\n]+)", err_s, flags=re.IGNORECASE)
    if sanm:
        san = (sanm.group(1) or "").strip() or None

    return {
        "attempted": True,
        "ok": True,
        "latency_ms": dt_ms,
        "stage": "ok",
        "tls_version": tls_version,
        "cipher": cipher,
        "alpn": alpn_selected,
        "cert_subject": subject,
        "cert_issuer": issuer,
        "cert_san": san,
    }


async def _curl_ws_probe(curl_bin: str, socks_port: int, timeout_sec: int, meta: Dict[str, Any]) -> Dict[str, Any]:
    if str(meta.get("network") or "").lower() != "ws":
        return {"attempted": False, "stage": "skip_not_ws", "detail": "network_not_ws"}

    url = _build_url(meta, meta.get("ws_path") or "/")
    if not url:
        return {"attempted": False, "stage": "skip_no_target", "detail": "missing_host_or_port"}

    args = [
        curl_bin,
        "-sS",
        "-i",
        "--http1.1",
        "--max-time",
        str(timeout_sec),
        "--socks5-hostname",
        f"127.0.0.1:{socks_port}",
        "-H",
        "Connection: Upgrade",
        "-H",
        "Upgrade: websocket",
        "-H",
        "Sec-WebSocket-Version: 13",
        "-H",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        url,
    ]
    host_header = meta.get("ws_host_header")
    if host_header:
        args.extend(["-H", f"Host: {host_header}"])

    t0 = time.perf_counter()
    p = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await p.communicate()
    dt_ms = int((time.perf_counter() - t0) * 1000)
    out_s = out.decode("utf-8", errors="ignore")
    err_s = err.decode("utf-8", errors="ignore")

    if p.returncode != 0:
        return {
            "attempted": True,
            "ok": False,
            "latency_ms": dt_ms,
            "stage": _classify_curl_failure(err_s, out_s),
            "detail": _summarize_error(err_s, out_s),
            "http_status": None,
        }

    code, headers, status_line = _parse_http_status_and_headers(out_s)
    ws_ok = int(code or 0) == 101
    return {
        "attempted": True,
        "ok": ws_ok,
        "latency_ms": dt_ms,
        "stage": "ok" if ws_ok else "ws_upgrade_fail",
        "detail": None if ws_ok else f"http_status={code}",
        "http_status": code,
        "status_line": status_line,
        "upgrade": headers.get("upgrade"),
        "connection": headers.get("connection"),
    }


async def _curl_grpc_probe(curl_bin: str, socks_port: int, timeout_sec: int, meta: Dict[str, Any]) -> Dict[str, Any]:
    if str(meta.get("network") or "").lower() != "grpc":
        return {"attempted": False, "stage": "skip_not_grpc", "detail": "network_not_grpc"}

    path = "/" + str(meta.get("grpc_service_name") or "").lstrip("/") if meta.get("grpc_service_name") else "/"
    url = _build_url(meta, path)
    if not url:
        return {"attempted": False, "stage": "skip_no_target", "detail": "missing_host_or_port"}

    args = [
        curl_bin,
        "-sS",
        "-i",
        "--http2",
        "--max-time",
        str(timeout_sec),
        "--socks5-hostname",
        f"127.0.0.1:{socks_port}",
        "-X",
        "POST",
        "-H",
        "Content-Type: application/grpc",
        "-H",
        "TE: trailers",
        "--data-binary",
        "",
        url,
    ]

    t0 = time.perf_counter()
    p = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await p.communicate()
    dt_ms = int((time.perf_counter() - t0) * 1000)
    out_s = out.decode("utf-8", errors="ignore")
    err_s = err.decode("utf-8", errors="ignore")

    if p.returncode != 0:
        return {
            "attempted": True,
            "ok": False,
            "latency_ms": dt_ms,
            "stage": _classify_curl_failure(err_s, out_s),
            "detail": _summarize_error(err_s, out_s),
            "http_status": None,
        }

    code, headers, status_line = _parse_http_status_and_headers(out_s)
    is_http2 = bool(status_line and "HTTP/2" in status_line.upper())
    ctype = (headers.get("content-type") or "").lower()
    grpc_like = "application/grpc" in ctype
    ok = bool(is_http2 and (code in (200, 204, 400, 404, 405, 415, 426, 429, 500, 502, 503)))

    return {
        "attempted": True,
        "ok": ok,
        "latency_ms": dt_ms,
        "stage": "ok" if ok else "grpc_fail",
        "detail": None if ok else f"http_status={code}, status_line={status_line}",
        "http_status": code,
        "status_line": status_line,
        "http2": is_http2,
        "content_type": headers.get("content-type"),
        "grpc_like_content_type": grpc_like,
        "service_name": meta.get("grpc_service_name"),
    }


async def run_xray_test(
    xray_bin: str,
    xray_config: dict,
    timeout_sec: int,
    curl_bin: str = "curl",
    tries: int = 3,
    delay_ms: int = 250,
    do_ip_check: bool = True,
    do_latency: bool = True,
    ip_echo_endpoints: Optional[List[str]] = None,
) -> TestResult:
    socks_port = xray_config["inbounds"][0]["port"]
    tries = max(1, int(tries))
    endpoints = _normalize_endpoints(ip_echo_endpoints)
    outbound_meta = _extract_outbound_meta(xray_config)

    with tempfile.TemporaryDirectory(prefix="mdma_xray_") as td:
        cfg_path = os.path.join(td, "config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(xray_config, f, ensure_ascii=False)

        proc = await asyncio.create_subprocess_exec(
            xray_bin,
            "run",
            "-c",
            cfg_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        try:
            await asyncio.sleep(0.35)
            if proc.returncode is not None:
                return TestResult(
                    ok=False,
                    latency_ms=None,
                    exit_ip=None,
                    ok_count=0,
                    tries=tries,
                    stage="xray_start_fail",
                    stage_detail=f"xray_exit_code={proc.returncode}",
                    ok_endpoint=None,
                    probe_results=[],
                    tls_telemetry=None,
                    ws_probe=None,
                    grpc_probe=None,
                )

            ok_count = 0
            best_latency: Optional[int] = None
            last_ip: Optional[str] = None
            ok_endpoint: Optional[str] = None
            last_fail_stage = "ip_echo_fail"
            last_fail_detail: Optional[str] = None
            probe_results: List[Dict[str, Any]] = []
            success_ips: List[str] = []
            ok_count_v4 = 0
            ok_count_v6 = 0

            for i in range(tries):
                if not do_ip_check:
                    if proc.returncode is None:
                        ok_count += 1
                    else:
                        last_fail_stage = "xray_dead"
                        last_fail_detail = f"xray_exit_code={proc.returncode}"
                    if i < tries - 1:
                        await asyncio.sleep(delay_ms / 1000)
                    continue

                if proc.returncode is not None:
                    last_fail_stage = "xray_dead"
                    last_fail_detail = f"xray_exit_code={proc.returncode}"
                    probe_results.append(
                        {
                            "try": int(i + 1),
                            "endpoint": "-",
                            "ok": False,
                            "latency_ms": None,
                            "ip": None,
                            "stage": "xray_dead",
                            "detail": last_fail_detail,
                        }
                    )
                    if i < tries - 1:
                        await asyncio.sleep(delay_ms / 1000)
                    continue

                hit: Optional[EndpointProbeResult] = None
                attempt_results: List[EndpointProbeResult] = []
                for ep in endpoints:
                    pr = await _curl_ip_probe(curl_bin, socks_port, timeout_sec, ep)
                    attempt_results.append(pr)
                    if pr.ok:
                        hit = pr
                        break

                probe_results.extend([x.as_dict(i + 1) for x in attempt_results])

                if hit and hit.ip:
                    ok_count += 1
                    last_ip = hit.ip
                    ok_endpoint = hit.endpoint
                    success_ips.append(hit.ip)
                    if hit.ip_version == "ipv4":
                        ok_count_v4 += 1
                    elif hit.ip_version == "ipv6":
                        ok_count_v6 += 1
                    if do_latency:
                        if best_latency is None or int(hit.latency_ms or 0) < best_latency:
                            best_latency = int(hit.latency_ms or 0)
                else:
                    priority = ["dns_fail", "tcp_fail", "tls_fail", "ip_echo_fail"]
                    stages = [x.stage for x in attempt_results if not x.ok]
                    picked = None
                    for p in priority:
                        if p in stages:
                            picked = p
                            break
                    last_fail_stage = picked or (stages[0] if stages else "ip_echo_fail")
                    last_fail_detail = None
                    for x in attempt_results:
                        if x.stage == last_fail_stage and x.detail:
                            last_fail_detail = x.detail
                            break

                if i < tries - 1:
                    await asyncio.sleep(delay_ms / 1000)

            tls_telemetry: Optional[Dict[str, Any]] = None
            ws_probe: Optional[Dict[str, Any]] = None
            grpc_probe: Optional[Dict[str, Any]] = None
            probe_timeout = max(2, min(int(timeout_sec), 10))
            try:
                tls_telemetry = await _curl_tls_telemetry(
                    curl_bin=curl_bin,
                    socks_port=socks_port,
                    timeout_sec=probe_timeout,
                    meta=outbound_meta,
                )
            except Exception as e:
                tls_telemetry = {
                    "attempted": True,
                    "ok": False,
                    "stage": "tls_probe_crash",
                    "detail": str(e),
                }

            try:
                ws_probe = await _curl_ws_probe(
                    curl_bin=curl_bin,
                    socks_port=socks_port,
                    timeout_sec=probe_timeout,
                    meta=outbound_meta,
                )
            except Exception as e:
                ws_probe = {
                    "attempted": True,
                    "ok": False,
                    "stage": "ws_probe_crash",
                    "detail": str(e),
                }

            try:
                grpc_probe = await _curl_grpc_probe(
                    curl_bin=curl_bin,
                    socks_port=socks_port,
                    timeout_sec=probe_timeout,
                    meta=outbound_meta,
                )
            except Exception as e:
                grpc_probe = {
                    "attempted": True,
                    "ok": False,
                    "stage": "grpc_probe_crash",
                    "detail": str(e),
                }

            required_probes: List[Tuple[str, Optional[Dict[str, Any]]]] = []
            if str(outbound_meta.get("security") or "").lower() in ("tls", "reality"):
                required_probes.append(("tls", tls_telemetry))
            if str(outbound_meta.get("network") or "").lower() == "ws":
                required_probes.append(("ws", ws_probe))
            if str(outbound_meta.get("network") or "").lower() == "grpc":
                required_probes.append(("grpc", grpc_probe))

            handshake_ok = True
            failed_parts: List[str] = []
            for nm, obj in required_probes:
                okv = bool((obj or {}).get("ok"))
                if not okv:
                    handshake_ok = False
                    failed_parts.append(nm)

            uniq_ips = sorted(set(success_ips))
            if not uniq_ips:
                ip_version: Optional[str] = None
                egress_consistent: Optional[bool] = None
            else:
                has_v4 = any(_ip_version_of(x) == "ipv4" for x in uniq_ips)
                has_v6 = any(_ip_version_of(x) == "ipv6" for x in uniq_ips)
                if has_v4 and has_v6:
                    ip_version = "mixed"
                elif has_v4:
                    ip_version = "ipv4"
                elif has_v6:
                    ip_version = "ipv6"
                else:
                    ip_version = None
                egress_consistent = len(uniq_ips) == 1

            handshake_detail = {
                "required": [x[0] for x in required_probes],
                "failed": failed_parts,
                "network": outbound_meta.get("network"),
                "security": outbound_meta.get("security"),
            }

            if ok_count <= 0:
                return TestResult(
                    ok=False,
                    latency_ms=best_latency,
                    exit_ip=last_ip,
                    ok_count=ok_count,
                    tries=tries,
                    stage=last_fail_stage,
                    stage_detail=last_fail_detail,
                    ok_endpoint=ok_endpoint,
                    probe_results=probe_results,
                    tls_telemetry=tls_telemetry,
                    ws_probe=ws_probe,
                    grpc_probe=grpc_probe,
                    ok_count_v4=ok_count_v4,
                    ok_count_v6=ok_count_v6,
                    ip_version=ip_version,
                    egress_consistent=egress_consistent,
                    handshake_ok=handshake_ok,
                    handshake_detail=handshake_detail,
                )

            latency_out = best_latency if (do_latency and best_latency is not None) else (best_latency or 0)
            return TestResult(
                ok=True,
                latency_ms=latency_out,
                exit_ip=last_ip,
                ok_count=ok_count,
                tries=tries,
                stage="ok",
                stage_detail=None,
                ok_endpoint=ok_endpoint,
                probe_results=probe_results,
                tls_telemetry=tls_telemetry,
                ws_probe=ws_probe,
                grpc_probe=grpc_probe,
                ok_count_v4=ok_count_v4,
                ok_count_v6=ok_count_v6,
                ip_version=ip_version,
                egress_consistent=egress_consistent,
                handshake_ok=handshake_ok,
                handshake_detail=handshake_detail,
            )

        finally:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    proc.kill()
