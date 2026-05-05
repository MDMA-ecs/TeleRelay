# main.py
from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import json
import logging
import os
import re
import socket
import shutil
import time
import urllib.parse
import urllib.request
import urllib.error
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, Callable

try:
    from telethon import TelegramClient, events, Button
except Exception:
    from telethon import TelegramClient, events
    from telethon.tl.custom import Button

from telethon.errors import FloodWaitError
from telethon.tl.types import MessageEntityTextUrl, MessageEntityUrl

from db import DB
from proxy_tester import RE_PROXY_LINK, TelegramProxy, parse_proxy_link, test_telegram_proxy
from runtime_config import RuntimeConfig
from tester import (
    apply_rename,
    flag_emoji_from_cc,
    geoip_ipapi_full,
    grade_from_latency,
    grade_label,
    normalize_config_for_fp,
    pick_socks_port,
    run_xray_test,
)

# Stop before common HTML delimiters too (so "<code>vless://..</code>" is safe)
RE_CONFIG_LINK = re.compile(
    r"((?:vless|vmess|trojan|ss)://[^\s<>'\"`]+)",
    re.IGNORECASE,
)

# Invisible / bidi controls that frequently appear in Telegram forwards
_INVISIBLES = [
    "\u200b", "\u200c", "\u200d", "\ufeff",  # zero width
    "\u2060",  # word joiner
    "\u00ad",  # soft hyphen
    "\u200e", "\u200f",  # LRM / RLM
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # bidi embedding/override
    "\u2066", "\u2067", "\u2068", "\u2069",  # bidi isolate
]

_LEADING_TRIM = " \t\r\n<([{«“\"'`"
_TRAILING_TRIM = " \t\r\n>)]}»”\"'`,.;:…!؟،؛"

TG_MAX = 3900  # keep below Telegram hard limit safely


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


def proto_of(link: str) -> str:
    link = (link or "").strip().lower()
    for p in ("vless", "vmess", "trojan", "ss"):
        if link.startswith(p + "://"):
            return p
    return "unknown"


def clean_text(s: str) -> str:
    """
    Normalize raw text for detection:
    - remove invisible chars
    - html-unescape (&amp; -> &)
    """
    if not s:
        return ""
    s = str(s)

    for ch in _INVISIBLES:
        s = s.replace(ch, "")

    try:
        s = html.unescape(s)
    except Exception:
        pass

    return s


def clean_link(link: str) -> str:
    """
    Aggressive-but-safe URL cleanup:
    - remove invisibles + html-unescape
    - strip wrappers/punctuation around the link
    - remove CR/LF inside (common in forwards)
    """
    s = clean_text(link or "")
    s = s.replace("\r", "").replace("\n", "").strip()

    while True:
        s2 = s.lstrip(_LEADING_TRIM).rstrip(_TRAILING_TRIM).strip()
        if s2 == s:
            break
        s = s2

    return s


def _msg_raw_text(msg: Any) -> str:
    t = getattr(msg, "raw_text", None)
    if t is None:
        t = getattr(msg, "message", None)
    return str(t or "")


def _scan_vmess_multiline(text: str) -> List[str]:
    out: List[str] = []
    low = (text or "").lower()
    i = 0
    while True:
        j = low.find("vmess://", i)
        if j < 0:
            break
        k = j + len("vmess://")
        buf: List[str] = []
        while k < len(text):
            ch = text[k]
            if ch.isalnum() or ch in "+/=_-":
                buf.append(ch)
            elif ch.isspace():
                pass
            else:
                break
            k += 1

        if len(buf) >= 16:
            out.append("vmess://" + "".join(buf))

        i = j + len("vmess://")
    return out


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        k = x.lower()
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def extract_urls_from_markup(msg: Any) -> List[str]:
    out: List[str] = []

    rm = getattr(msg, "reply_markup", None)
    rows = getattr(rm, "rows", None) if rm else None
    if rows:
        for row in rows:
            btns = getattr(row, "buttons", None) or []
            for b in btns:
                u = getattr(b, "url", None)
                if u:
                    out.append(clean_link(u))

    btns2 = getattr(msg, "buttons", None)
    if btns2:
        for row in btns2:
            for b in row:
                u = getattr(b, "url", None)
                if not u:
                    u = getattr(getattr(b, "button", None), "url", None)
                if u:
                    out.append(clean_link(u))

    media = getattr(msg, "media", None)
    webpage = getattr(media, "webpage", None) if media else None
    if webpage:
        u = getattr(webpage, "url", None)
        if u:
            out.append(clean_link(u))

    return _dedupe_keep_order([x for x in out if x])


def extract_links_by_regex(
    msg: Any,
    rx: re.Pattern,
    validator: Optional[Callable[[str], bool]] = None,
    also_scan_vmess_multiline: bool = False,
) -> List[str]:
    out: List[str] = []

    raw_orig = _msg_raw_text(msg)
    raw_norm = clean_text(raw_orig)

    ents = getattr(msg, "entities", None) or []
    for e in ents:
        try:
            if isinstance(e, MessageEntityTextUrl) and getattr(e, "url", None):
                u = clean_link(e.url)
                if u:
                    out.append(u)
            elif isinstance(e, MessageEntityUrl):
                piece = raw_orig[e.offset : e.offset + e.length]
                u = clean_link(piece)
                if u:
                    out.append(u)
        except Exception:
            continue

    try:
        out.extend(extract_urls_from_markup(msg))
    except Exception:
        pass

    for m in rx.finditer(raw_norm):
        try:
            u = clean_link(m.group(1))
            if u:
                out.append(u)
        except Exception:
            continue

    if also_scan_vmess_multiline:
        try:
            for u in _scan_vmess_multiline(raw_norm):
                u2 = clean_link(u)
                if u2:
                    out.append(u2)
        except Exception:
            pass

    final: List[str] = []
    for u in out:
        uu = clean_link(u)
        if not uu:
            continue
        if validator is not None:
            try:
                if not validator(uu):
                    continue
            except Exception:
                continue
        final.append(uu)

    return _dedupe_keep_order(final)


def _validate_config_link(u: str) -> bool:
    try:
        _ = build_outbound_from_link(u)
        return True
    except Exception:
        return False


def _validate_proxy_link(u: str) -> bool:
    try:
        _ = parse_proxy_link(u)
        return True
    except Exception:
        return False


def extract_config_links(msg: Any) -> List[str]:
    return extract_links_by_regex(msg, RE_CONFIG_LINK, validator=_validate_config_link, also_scan_vmess_multiline=True)


def extract_proxy_links(msg: Any) -> List[str]:
    return extract_links_by_regex(msg, RE_PROXY_LINK, validator=_validate_proxy_link, also_scan_vmess_multiline=False)


def detect_security_from_link(link: str) -> str:
    p = proto_of(link)
    if p in ("vless", "trojan"):
        base = link.split("#", 1)[0]
        u = urllib.parse.urlparse(base)
        qs = urllib.parse.parse_qs(u.query)
        sec = (qs.get("security", ["none"])[0] or "none").lower()
        if sec == "tls":
            return "TLS"
        if sec == "reality":
            return "REALITY"
        return "PLAIN"

    if p == "vmess":
        import base64

        b64 = link[len("vmess://") :].strip().replace("-", "+").replace("_", "/")
        try:
            pad = "=" * (-len(b64) % 4)
            raw = base64.b64decode(b64 + pad)
            j = json.loads(raw.decode("utf-8", errors="ignore"))
            tls = (j.get("tls") or "").lower()
            return "TLS" if tls else "PLAIN"
        except Exception:
            return "PLAIN"

    return "PLAIN"


def build_outbound_from_link(link: str) -> Dict[str, Any]:
    p = proto_of(link)

    if p in ("vless", "trojan"):
        base = link.split("#", 1)[0]
        u = urllib.parse.urlparse(base)

        userinfo, hostport = u.netloc.split("@", 1) if "@" in u.netloc else ("", u.netloc)
        if ":" not in hostport:
            raise ValueError("Missing host:port")
        host, port_s = hostport.rsplit(":", 1)
        port = int(port_s)

        qs = urllib.parse.parse_qs(u.query)
        security = (qs.get("security", ["none"])[0] or "none").lower()
        sni = qs.get("sni", [None])[0] or qs.get("host", [None])[0]
        fp = qs.get("fp", [None])[0]
        net = (qs.get("type", ["tcp"])[0] or "tcp").lower()
        path = qs.get("path", ["/"])[0]
        host_hdr = qs.get("host", [None])[0]
        alpn = qs.get("alpn", [None])[0]
        pbk = qs.get("pbk", [None])[0]
        sid = qs.get("sid", [None])[0]
        spx = qs.get("spx", [None])[0]
        flow = qs.get("flow", [None])[0]
        grpc_service = qs.get("serviceName", [None])[0] or qs.get("service", [None])[0]
        grpc_authority = qs.get("authority", [None])[0] or qs.get("host", [None])[0]

        sec = "tls" if security == "tls" else ("reality" if security == "reality" else "none")

        if p == "vless":
            user_obj: Dict[str, Any] = {"id": (userinfo or u.username or ""), "encryption": "none"}
            if flow:
                user_obj["flow"] = flow
            out: Dict[str, Any] = {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": host,
                            "port": port,
                            "users": [user_obj],
                        }
                    ]
                },
                "streamSettings": {"network": net, "security": sec},
            }
        else:
            out = {
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port, "password": (userinfo or u.username or "")}]},
                "streamSettings": {"network": net, "security": sec},
            }

        if sec in ("tls", "reality"):
            tls_settings: Dict[str, Any] = {}
            if sni:
                tls_settings["serverName"] = sni
            if alpn:
                tls_settings["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
            if fp:
                tls_settings["fingerprint"] = fp

            if sec == "tls":
                out["streamSettings"]["tlsSettings"] = tls_settings or {}
            else:
                reality = tls_settings or {}
                if pbk:
                    reality["publicKey"] = pbk
                if sid:
                    reality["shortId"] = sid
                if spx:
                    reality["spiderX"] = spx
                out["streamSettings"]["realitySettings"] = reality

        if net == "ws":
            ws: Dict[str, Any] = {"path": path}
            if host_hdr:
                ws["headers"] = {"Host": host_hdr}
            out["streamSettings"]["wsSettings"] = ws
        elif net == "grpc":
            gs: Dict[str, Any] = {"serviceName": (grpc_service or "").lstrip("/")}
            if grpc_authority:
                gs["authority"] = grpc_authority
            out["streamSettings"]["grpcSettings"] = gs

        return out

    if p == "vmess":
        import base64

        b64 = link[len("vmess://") :].strip().replace("-", "+").replace("_", "/")
        try:
            pad = "=" * (-len(b64) % 4)
            raw = base64.b64decode(b64 + pad)
            j = json.loads(raw.decode("utf-8", errors="ignore"))
        except Exception:
            raise ValueError("Invalid vmess base64/json")

        addr = j.get("add")
        port = int(j.get("port"))
        uuid = j.get("id")
        aid = int(j.get("aid", 0))
        net = (j.get("net") or "tcp").lower()
        tls = (j.get("tls") or "").lower()
        host_hdr = j.get("host") or None
        path = j.get("path") or "/"
        sni = j.get("sni") or j.get("host") or None
        grpc_service = j.get("serviceName") or (path if net == "grpc" else None)

        if not addr or not uuid:
            raise ValueError("Invalid vmess fields")

        out = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{"address": addr, "port": port, "users": [{"id": uuid, "alterId": aid, "security": "auto"}]}]
            },
            "streamSettings": {"network": net, "security": "tls" if tls else "none"},
        }

        if tls:
            out["streamSettings"]["tlsSettings"] = {"serverName": sni} if sni else {}

        if net == "ws":
            ws2: Dict[str, Any] = {"path": path}
            if host_hdr:
                ws2["headers"] = {"Host": host_hdr}
            out["streamSettings"]["wsSettings"] = ws2
        elif net == "grpc":
            out["streamSettings"]["grpcSettings"] = {"serviceName": str(grpc_service or "").lstrip("/")}

        return out

    if p == "ss":
        import base64

        base = link.split("#", 1)[0].strip()
        u = urllib.parse.urlparse(base)

        def b64decode_urlsafe(s: str) -> str:
            s = s.strip().replace("-", "+").replace("_", "/")
            pad = "=" * (-len(s) % 4)
            return base64.b64decode(s + pad).decode("utf-8", errors="ignore")

        host = port = method = password = None

        if u.netloc and "@" in u.netloc:
            left, hostport = u.netloc.split("@", 1)
            if ":" in left and ":" in hostport:
                try:
                    method, password = left.split(":", 1)
                    host, port_s = hostport.rsplit(":", 1)
                    port = int(port_s)
                except Exception:
                    pass

        if not (host and port and method and password) and u.netloc and "@" in u.netloc:
            left, hostport = u.netloc.split("@", 1)
            try:
                decoded = b64decode_urlsafe(left)
                if ":" in decoded and ":" in hostport:
                    method, password = decoded.split(":", 1)
                    host, port_s = hostport.rsplit(":", 1)
                    port = int(port_s)
            except Exception:
                pass

        if not (host and port and method and password):
            blob = (u.netloc or u.path or "").replace("ss://", "").strip("/")
            blob = blob.split("?", 1)[0]
            try:
                decoded = b64decode_urlsafe(blob)
                if "@" in decoded:
                    userinfo, hostport = decoded.split("@", 1)
                    if ":" in userinfo and ":" in hostport:
                        method, password = userinfo.split(":", 1)
                        host, port_s = hostport.rsplit(":", 1)
                        port = int(port_s)
            except Exception:
                pass

        if not (host and port and method and password):
            raise ValueError("Unsupported ss:// format")

        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
            "streamSettings": {"network": "tcp", "security": "none"},
        }

    raise ValueError(f"Unsupported or unknown protocol link: {p}")


def build_xray_test_config(outbound: Dict[str, Any], socks_port: int) -> Dict[str, Any]:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
        "routing": {"domainStrategy": "AsIs"},
    }


def extract_transport_fingerprint(raw_link: str, outbound: Dict[str, Any]) -> Dict[str, Any]:
    ss = (outbound or {}).get("streamSettings") or {}
    settings = (outbound or {}).get("settings") or {}
    proto = str((outbound or {}).get("protocol") or "").lower()

    # Normalize protocol label for reporting
    proto_label = proto
    if proto == "shadowsocks":
        proto_label = "ss"

    network = str(ss.get("network") or "tcp").lower()
    security = str(ss.get("security") or "none").lower()

    tls_s = ss.get("tlsSettings") or {}
    reality_s = ss.get("realitySettings") or {}
    ws_s = ss.get("wsSettings") or {}
    grpc_s = ss.get("grpcSettings") or {}
    http_s = ss.get("httpSettings") or {}

    sni = tls_s.get("serverName") or reality_s.get("serverName")
    alpn = tls_s.get("alpn") or reality_s.get("alpn")
    if isinstance(alpn, str):
        alpn = [x.strip() for x in alpn.split(",") if x.strip()]
    if not isinstance(alpn, list):
        alpn = None
    fp = tls_s.get("fingerprint") or reality_s.get("fingerprint")

    host = None
    port = None
    flow = None
    if proto in ("vless", "vmess"):
        arr = settings.get("vnext") or []
        if arr:
            host = arr[0].get("address")
            port = arr[0].get("port")
            users = arr[0].get("users") or []
            if users:
                flow = users[0].get("flow")
    elif proto in ("trojan", "shadowsocks"):
        arr2 = settings.get("servers") or []
        if arr2:
            host = arr2[0].get("address")
            port = arr2[0].get("port")

    ws_path = ws_s.get("path")
    ws_host_hdr = (ws_s.get("headers") or {}).get("Host")
    service_name = grpc_s.get("serviceName")

    http_path = http_s.get("path")
    if isinstance(http_path, list):
        http_path = http_path[0] if http_path else None
    http_host = http_s.get("host")
    if isinstance(http_host, list):
        http_host = http_host[0] if http_host else None

    return {
        "protocol": proto_label or proto_of(raw_link),
        "network": network,
        "security": security,
        "sni": sni,
        "alpn": alpn,
        "fp": fp,
        "flow": flow,
        "serviceName": service_name,
        "path": ws_path or http_path,
        "host_header": ws_host_hdr or http_host,
        "port": int(port) if port is not None else None,
        "target_host": host,
    }


def _is_cloudflare_asn_org(asn: Optional[str], org: Optional[str]) -> bool:
    a = str(asn or "").strip().lower()
    o = str(org or "").strip().lower()
    if not a and not o:
        return False

    if a.startswith("as13335"):
        return True
    if "cloudflare" in a:
        return True
    if "cloudflare" in o:
        return True
    return False


def _extract_outbound_target(outbound: Dict[str, Any]) -> Tuple[Optional[str], Optional[int]]:
    try:
        proto = str((outbound or {}).get("protocol") or "").lower()
        settings = (outbound or {}).get("settings") or {}

        if proto in ("vless", "vmess"):
            arr = settings.get("vnext") or []
            if arr:
                host = arr[0].get("address")
                port = arr[0].get("port")
                return (str(host) if host else None), (int(port) if port is not None else None)

        if proto in ("trojan", "shadowsocks"):
            arr2 = settings.get("servers") or []
            if arr2:
                host = arr2[0].get("address")
                port = arr2[0].get("port")
                return (str(host) if host else None), (int(port) if port is not None else None)
    except Exception:
        return None, None
    return None, None


async def _resolve_first_ip(host: str, timeout_sec: int = 4) -> Optional[str]:
    h = str(host or "").strip()
    if not h:
        return None

    try:
        ipaddress.ip_address(h)
        return h
    except Exception:
        pass

    def _resolve_sync() -> Optional[str]:
        infos = socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)
        for it in infos:
            try:
                ip = it[4][0]
                if ip:
                    return str(ip)
            except Exception:
                continue
        return None

    try:
        return await asyncio.wait_for(asyncio.to_thread(_resolve_sync), timeout=timeout_sec)
    except Exception:
        return None


async def detect_edge_info(outbound: Dict[str, Any], geoip_timeout: int = 6) -> Dict[str, Any]:
    host, port = _extract_outbound_target(outbound)
    out: Dict[str, Any] = {
        "edge_host": host,
        "edge_port": port,
        "edge_ip": None,
        "edge_asn": None,
        "edge_org": None,
        "edge_country_code": None,
        "edge_country": None,
        "edge_is_cloudflare": False,
    }
    if not host:
        return out

    edge_ip = await _resolve_first_ip(host, timeout_sec=4)
    out["edge_ip"] = edge_ip
    if not edge_ip:
        return out

    try:
        cc, country, asn, org = await geoip_ipapi_full(edge_ip, timeout_sec=geoip_timeout)
        out["edge_country_code"] = cc
        out["edge_country"] = country
        out["edge_asn"] = asn
        out["edge_org"] = org
        out["edge_is_cloudflare"] = _is_cloudflare_asn_org(asn, org)
    except Exception:
        pass
    return out


def _h(s: str) -> str:
    return html.escape(s or "", quote=False)


def _href(u: str) -> str:
    return html.escape(u or "", quote=True)


def _shorten_middle(s: str, max_chars: int) -> str:
    s = s or ""
    if max_chars <= 0:
        return ""
    if len(s) <= max_chars:
        return s
    if max_chars == 1:
        return "…"
    keep = max_chars - 1
    left = keep // 2
    right = keep - left
    return s[:left] + "…" + s[-right:]


class CircuitBreaker:
    def __init__(self, fail_threshold: int, cool_down_sec: int):
        self.fail_threshold = int(fail_threshold)
        self.cool_down_sec = int(cool_down_sec)
        self.fail_count = 0
        self.paused_until = 0.0

    def on_success(self) -> None:
        self.fail_count = 0

    def on_fail(self) -> None:
        self.fail_count += 1
        if self.fail_count >= self.fail_threshold:
            self.paused_until = time.time() + self.cool_down_sec
            self.fail_count = 0

    def is_paused(self) -> bool:
        return time.time() < self.paused_until

    def remaining(self) -> int:
        return max(0, int(self.paused_until - time.time()))

    def state(self) -> dict:
        return {
            "paused": self.is_paused(),
            "remaining_sec": self.remaining(),
            "fail_threshold": self.fail_threshold,
            "cool_down_sec": self.cool_down_sec,
        }


class AdaptiveProbeController:
    def __init__(
        self,
        enabled: bool = True,
        history_size: int = 120,
        min_timeout: int = 4,
        max_timeout: int = 24,
        min_tries: int = 1,
        max_tries: int = 5,
        fail_weight: float = 1.4,
        stage_weight: float = 1.0,
    ):
        self.enabled = bool(enabled)
        self.history = deque(maxlen=max(20, int(history_size)))
        self.min_timeout = max(1, int(min_timeout))
        self.max_timeout = max(self.min_timeout, int(max_timeout))
        self.min_tries = max(1, int(min_tries))
        self.max_tries = max(self.min_tries, int(max_tries))
        self.fail_weight = max(0.0, float(fail_weight))
        self.stage_weight = max(0.0, float(stage_weight))
        self.last_decision: Dict[str, Any] = {}

    def _rates(self) -> Tuple[float, float]:
        if not self.history:
            return 0.0, 0.0
        total = float(len(self.history))
        fail = 0.0
        harsh = 0.0
        harsh_set = {"dns_fail", "tcp_fail", "tls_fail", "xray_dead", "xray_start_fail", "ip_echo_fail"}
        for it in self.history:
            if not it.get("ok"):
                fail += 1.0
                if str(it.get("stage") or "").lower() in harsh_set:
                    harsh += 1.0
        return fail / total, harsh / total

    def decide(self, base_timeout: int, base_tries: int) -> Tuple[int, int, Dict[str, Any]]:
        bt = max(1, int(base_timeout))
        br = max(1, int(base_tries))
        if not self.enabled:
            meta = {
                "enabled": False,
                "base_timeout_sec": bt,
                "base_tries": br,
                "eff_timeout_sec": bt,
                "eff_tries": br,
                "fail_rate": 0.0,
                "harsh_fail_rate": 0.0,
            }
            self.last_decision = meta
            return bt, br, meta

        fail_rate, harsh_rate = self._rates()
        boost = 1.0 + (fail_rate * self.fail_weight) + (harsh_rate * self.stage_weight)
        eff_timeout = int(round(bt * boost))
        eff_timeout = max(self.min_timeout, min(self.max_timeout, eff_timeout))

        extra_tries = 0
        if fail_rate >= 0.35 or harsh_rate >= 0.25:
            extra_tries += 1
        if fail_rate >= 0.60 or harsh_rate >= 0.45:
            extra_tries += 1
        eff_tries = max(self.min_tries, min(self.max_tries, br + extra_tries))

        meta = {
            "enabled": True,
            "base_timeout_sec": bt,
            "base_tries": br,
            "eff_timeout_sec": eff_timeout,
            "eff_tries": eff_tries,
            "fail_rate": round(float(fail_rate), 4),
            "harsh_fail_rate": round(float(harsh_rate), 4),
            "boost_factor": round(float(boost), 3),
        }
        self.last_decision = meta
        return eff_timeout, eff_tries, meta

    def update(self, result: Any) -> None:
        try:
            self.history.append(
                {
                    "ok": bool(getattr(result, "ok", False)),
                    "stage": str(getattr(result, "stage", "") or "").lower(),
                    "ts": time.time(),
                }
            )
        except Exception:
            pass

    def state(self) -> Dict[str, Any]:
        fail_rate, harsh_rate = self._rates()
        return {
            "enabled": self.enabled,
            "history_size": len(self.history),
            "fail_rate": round(float(fail_rate), 4),
            "harsh_fail_rate": round(float(harsh_rate), 4),
            "last_decision": self.last_decision,
            "min_timeout_sec": self.min_timeout,
            "max_timeout_sec": self.max_timeout,
            "min_tries": self.min_tries,
            "max_tries": self.max_tries,
        }


def evaluate_quality_grade(
    latency_ms: int,
    good_ms: int,
    ok_ms: int,
    ok_count: int,
    tries: int,
    handshake_ok: Optional[bool],
    egress_consistent: Optional[bool],
    stage_fail_history: int,
) -> Dict[str, Any]:
    # 1) latency score
    lat = int(latency_ms or 999999)
    g = max(1, int(good_ms))
    o = max(g + 1, int(ok_ms))
    if lat <= g:
        latency_score = 100.0
    elif lat <= o:
        span = float(o - g)
        latency_score = 75.0 + (25.0 * (o - lat) / span)
    else:
        # soft floor at 20
        latency_score = max(20.0, 75.0 - (float(lat - o) / max(50.0, float(o)) * 40.0))

    # 2) stability
    tr = max(1, int(tries))
    stability_ratio = max(0.0, min(1.0, float(ok_count) / float(tr)))
    stability_score = stability_ratio * 100.0

    # 3) handshake quality
    if handshake_ok is True:
        handshake_score = 100.0
    elif handshake_ok is False:
        handshake_score = 35.0
    else:
        handshake_score = 70.0

    # 4) egress consistency
    if egress_consistent is True:
        egress_score = 100.0
    elif egress_consistent is False:
        egress_score = 45.0
    else:
        egress_score = 70.0

    # 5) stage fail history penalty
    sfh = max(0, int(stage_fail_history))
    history_score = max(20.0, 100.0 - (sfh * 12.0))

    # weighted score
    quality_score = (
        latency_score * 0.40
        + stability_score * 0.25
        + handshake_score * 0.15
        + egress_score * 0.10
        + history_score * 0.10
    )
    quality_score = max(0.0, min(100.0, quality_score))

    if quality_score >= 85.0:
        grade_code = "AA"
    elif quality_score >= 60.0:
        grade_code = "BB"
    else:
        grade_code = "CC"

    return {
        "quality_score": round(float(quality_score), 2),
        "grade_code": grade_code,
        "components": {
            "latency_score": round(float(latency_score), 2),
            "stability_score": round(float(stability_score), 2),
            "handshake_score": round(float(handshake_score), 2),
            "egress_score": round(float(egress_score), 2),
            "history_score": round(float(history_score), 2),
            "stability_ratio": round(float(stability_ratio), 4),
            "stage_fail_history": sfh,
        },
    }


def render_post_html(
    renamed_link: str,
    flag: str,
    country: str,
    proto: str,
    security_label: str,
    latency_ms: int,
    grade_code: str,
    ok_count: int,
    tries: int,
    asn: Optional[str],
    org: Optional[str],
    fixed_caption: str,
    add_tags: bool = True,
    gold_pick: bool = False,
) -> str:
    """
    IMPORTANT FIX:
    - Never truncate HTML by slicing msg[:...]
    - Keep <code> intact so config does NOT become plain URL.
    """
    grade_emo, grade_name = grade_label(grade_code)
    proto_u = (proto or "").upper()
    country_s = country or "Unknown"

    gold = "⭐️ <b>Gold pick</b>\n" if gold_pick else ""

    asn_line = ""
    if asn or org:
        if asn and org:
            asn_line = f"🏢 ASN: <code>{_h(org)}</code> (<code>{_h(asn)}</code>)\n"
        elif asn:
            asn_line = f"🏢 ASN: <code>{_h(asn)}</code>\n"
        else:
            asn_line = f"🏢 ASN: <code>{_h(org or '')}</code>\n"

    tags = f"\n#{proto.lower()} #{security_label.lower()} #{grade_code.lower()}" if add_tags else ""
    fixed = _h(fixed_caption or "")

    header = (
        f"{_h(flag)} {_h(country_s)} • {_h(proto_u)} • {_h(security_label)} • {_h(grade_emo)} "
        f"<b>{_h(grade_name)}</b>\n"
    )
    ping_line = f"⚡ Ping: <code>{int(latency_ms)}ms</code> • Stability: <code>{int(ok_count)}/{int(tries)}</code>\n"

    def make_link_line(link_value: str) -> str:
        return f"<code>{_h(link_value)}</code>\n\n"

    def assemble(link_value: str, use_gold: bool, use_ping: bool, use_asn: bool, use_tags: bool, use_fixed: bool) -> str:
        return (
            make_link_line(link_value)
            + header
            + (gold if use_gold else "")
            + (ping_line if use_ping else "")
            + (asn_line if use_asn else "")
            + (_h(tags) if use_tags else "")
            + (fixed if use_fixed else "")
        )

    # Try progressively removing least critical parts (but keeping code link intact)
    options = [
        (True, True, True, True, True),
        (True, True, True, False, True),
        (True, True, True, False, False),
        (False, True, True, False, False),
        (False, True, False, False, False),
        (False, False, False, False, False),
    ]

    for use_gold, use_ping, use_asn, use_tags, use_fixed in options:
        msg = assemble(renamed_link, use_gold, use_ping, use_asn, use_tags, use_fixed)
        if len(msg) <= TG_MAX:
            return msg

    # If still too long, the link itself is gigantic -> shorten it safely (still inside <code>)
    # We find a max link length by trial (accounting for HTML escaping expansion)
    base = header  # keep at least this
    min_msg = make_link_line("X") + base
    remaining = max(50, TG_MAX - len(min_msg) - 20)

    # start with rough guess and adjust down until it fits
    max_link = remaining
    link_disp = _shorten_middle(renamed_link, max_link)
    msg = make_link_line(link_disp) + base
    while len(msg) > TG_MAX and max_link > 50:
        max_link -= 50
        link_disp = _shorten_middle(renamed_link, max_link)
        msg = make_link_line(link_disp) + base

    # final fallback: just link line (still valid HTML)
    if len(msg) > TG_MAX:
        # shrink harder
        max_link = max(30, max_link // 2)
        link_disp = _shorten_middle(renamed_link, max_link)
        msg = make_link_line(link_disp)
        if len(msg) > TG_MAX:
            msg = make_link_line(_shorten_middle(renamed_link, 80))
    return msg


# -------------------------
# Proxy posting UX tweaks
# (ONLY affects proxy pipeline)
# -------------------------
def _mask_secret(s: Optional[str]) -> str:
    if not s:
        return ""
    s = str(s)
    if len(s) <= 14:
        return s
    return s[:6] + "…" + s[-4:]


def proxy_http_link(proxy: TelegramProxy) -> str:
    if proxy.kind == "socks":
        q = {"server": proxy.server, "port": str(proxy.port)}
        if getattr(proxy, "username", None):
            q["user"] = proxy.username
        if getattr(proxy, "password", None):
            q["pass"] = proxy.password
        return "https://t.me/socks?" + urllib.parse.urlencode(q, doseq=False)

    q2 = {"server": proxy.server, "port": str(proxy.port)}
    if getattr(proxy, "secret", None):
        q2["secret"] = proxy.secret
    return "https://t.me/proxy?" + urllib.parse.urlencode(q2, doseq=False)


def channel_to_tme_url(channel: str) -> Optional[str]:
    s = str(channel or "").strip()
    if not s:
        return None

    m = re.match(r"^(?:https?://)?t\.me/([A-Za-z0-9_]{4,})/?$", s, flags=re.IGNORECASE)
    if m:
        return f"https://t.me/{m.group(1)}"

    if s.startswith("@"):
        s = s[1:].strip()
    if re.fullmatch(r"[A-Za-z0-9_]{4,}", s):
        return f"https://t.me/{s}"

    return None


def render_proxy_post_html(
    proxy: TelegramProxy,
    latency_ms: int,
    grade_code: str,
    exit_ip: Optional[str],
    cc: Optional[str],
    country: Optional[str],
    asn: Optional[str],
    org: Optional[str],
    fixed_caption: str,
) -> str:
    grade_emo, grade_name = grade_label(grade_code)
    flag = flag_emoji_from_cc(cc or "")
    kind = "SOCKS5" if proxy.kind == "socks" else "MTPROTO"
    country_s = country or (cc or "Unknown")

    add_link = proxy_http_link(proxy)
    title = "➕ ADD Proxy " if proxy.kind != "socks" else "➕ افزودن SOCKS5"

    ip_line = f"🌐 Exit IP: <code>{_h(exit_ip)}</code>\n" if exit_ip else ""
    asn_line = ""
    if asn or org:
        if asn and org:
            asn_line = f"🏢 ASN: <code>{_h(org)}</code> (<code>{_h(asn)}</code>)\n"
        elif asn:
            asn_line = f"🏢 ASN: <code>{_h(asn)}</code>\n"
        else:
            asn_line = f"🏢 ASN: <code>{_h(org or '')}</code>\n"

    server_line = f"🧩 Server: <code>{_h(proxy.server)}:{int(proxy.port)}</code>\n"
    secret_line = ""
    if proxy.kind != "socks" and getattr(proxy, "secret", None):
        secret_line = f"🔑 Secret: <code>{_h(_mask_secret(proxy.secret))}</code>\n"

    tags = f"\n#tgproxy #{'socks' if proxy.kind == 'socks' else 'mtproto'} #{grade_code.lower()}"
    fixed = _h(fixed_caption or "")

    def assemble(use_ip: bool, use_asn: bool, use_fixed: bool, use_tags: bool) -> str:
        return (
            f"🔗 <a href=\"{_href(add_link)}\">{_h(title)}</a>\n"
            f"{_h(flag)} {_h(country_s)} • {_h(kind)} • {_h(grade_emo)} <b>{_h(grade_name)}</b>\n"
            f"⚡ Latency: <code>{int(latency_ms)}ms</code>\n"
            f"{server_line}"
            f"{secret_line}"
            f"{ip_line if use_ip else ''}"
            f"{asn_line if use_asn else ''}"
            f"{_h(tags) if use_tags else ''}"
            f"{fixed if use_fixed else ''}"
        )

    for use_ip, use_asn, use_fixed, use_tags in [
        (True, True, True, True),
        (True, True, True, False),
        (True, True, False, False),
        (False, True, False, False),
        (False, False, False, False),
    ]:
        msg = assemble(use_ip, use_asn, use_fixed, use_tags)
        if len(msg) <= TG_MAX:
            return msg

    # last resort: cut fixed caption safely (no HTML slicing that can break tags)
    msg = assemble(False, False, True, False)
    if len(msg) <= TG_MAX:
        return msg
    # trim only fixed caption
    head = assemble(False, False, False, False)
    remain = max(0, TG_MAX - len(head) - 5)
    return head + (_h(_shorten_middle(fixed_caption or "", remain)))


async def safe_send_html(client: TelegramClient, target: str, text_html: str, buttons=None) -> None:
    while True:
        try:
            await client.send_message(target, text_html, parse_mode="html", buttons=buttons)
            return
        except FloodWaitError as e:
            await asyncio.sleep(int(e.seconds) + 1)
        except Exception:
            # fallback: plain text (but try to keep something)
            try:
                await client.send_message(target, re.sub(r"<[^>]+>", "", text_html), parse_mode=None, buttons=buttons)
                return
            except FloodWaitError as e:
                await asyncio.sleep(int(e.seconds) + 1)


async def safe_send_html_proxy(
    client: TelegramClient,
    target: str,
    text_html: str,
    buttons=None,
) -> None:
    await safe_send_html(client, target, text_html, buttons=buttons)


async def safe_send_bot_api_html(
    bot_token: str,
    target: str,
    text_html: str,
    reply_markup: Optional[Dict[str, Any]] = None,
) -> bool:
    # Sends through Telegram Bot API so we can pass InlineKeyboardButton.style.
    # style="primary" makes supported Telegram clients show the button in blue.
    if not bot_token:
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    payload: Dict[str, Any] = {
        "chat_id": target,
        "text": text_html,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    if reply_markup:
        payload["reply_markup"] = reply_markup

    while True:
        try:
            def _post() -> Tuple[int, str]:
                data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return int(resp.status), resp.read().decode("utf-8", errors="ignore")

            status, body = await asyncio.to_thread(_post)

            try:
                j = json.loads(body or "{}")
            except Exception:
                j = {}

            if status == 200 and j.get("ok"):
                return True

            params = j.get("parameters") or {}
            retry_after = params.get("retry_after")
            if retry_after:
                await asyncio.sleep(int(retry_after) + 1)
                continue

            logging.getLogger("mdma-bot").warning("Bot API send failed: status=%s body=%s", status, body)
            return False

        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                pass

            try:
                j = json.loads(body or "{}")
            except Exception:
                j = {}

            params = j.get("parameters") or {}
            retry_after = params.get("retry_after")
            if retry_after:
                await asyncio.sleep(int(retry_after) + 1)
                continue

            logging.getLogger("mdma-bot").warning("Bot API HTTP error: %s body=%s", e, body)
            return False

        except Exception as e:
            logging.getLogger("mdma-bot").warning("Bot API send exception: %s", e)
            return False


def parse_source_list(items: List[Any]) -> Tuple[Set[str], Set[int], List[str]]:
    usernames: Set[str] = set()
    chat_ids: Set[int] = set()
    pretty: List[str] = []

    for it in items or []:
        s = str(it).strip()
        if not s:
            continue

        m = re.match(r"^https?://t\.me/([A-Za-z0-9_]{4,})/?$", s, flags=re.IGNORECASE)
        if m:
            s = "@" + m.group(1)

        if s.startswith("@"):
            u = s[1:].strip().lower()
            if u:
                usernames.add(u)
                pretty.append("@" + u)
            continue

        if re.fullmatch(r"-?\d+", s):
            try:
                cid = int(s)
                chat_ids.add(cid)
                pretty.append(str(cid))
                continue
            except Exception:
                pass

        u2 = s.lower()
        if u2:
            usernames.add(u2)
            pretty.append("@" + u2)

    seen = set()
    pretty2 = []
    for x in pretty:
        if x not in seen:
            seen.add(x)
            pretty2.append(x)
    return usernames, chat_ids, pretty2


@dataclass
class Job:
    kind: str  # "config" or "proxy"
    payload: str
    source: str
    msg_id: int


def resolve_executable(path_or_name: str) -> Optional[str]:
    p = (path_or_name or "").strip()
    if not p:
        return None
    if os.sep in p or p.startswith(".") or p.startswith("/"):
        return p if os.path.exists(p) else None
    return shutil.which(p)


def _session_candidates(base_session_name: str, user_session_name: Optional[str]) -> List[str]:
    items: List[str] = []
    if user_session_name:
        items.append(str(user_session_name).strip())
    if base_session_name:
        items.append(str(base_session_name).strip())
        items.append(str(base_session_name).strip() + "_user")

    out: List[str] = []
    seen: Set[str] = set()
    for x in items:
        s = (x or "").strip()
        if not s:
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


async def start_user_client(
    api_id: int,
    api_hash: str,
    base_session_name: str,
    user_session_name: Optional[str],
    log: logging.Logger,
) -> Tuple[TelegramClient, Any, str]:
    last_bot_id: Optional[int] = None
    tried: List[str] = []

    for sess in _session_candidates(base_session_name, user_session_name):
        tried.append(sess)
        c = TelegramClient(sess, api_id, api_hash)
        try:
            await c.start()
        except EOFError as e:
            await c.disconnect()
            raise RuntimeError(
                "User login is required for listener session but no interactive input was available. "
                f"Run 'python main.py' in an interactive terminal and login user session '{sess}'."
            ) from e
        me = await c.get_me()
        if me and not getattr(me, "bot", False):
            return c, me, sess

        last_bot_id = int(getattr(me, "id", 0) or 0) or None
        log.warning("Session '%s' is a bot account (id=%s). Trying next user session...", sess, last_bot_id)
        await c.disconnect()

    raise RuntimeError(
        "Could not start a USER session for listener client. "
        f"Tried sessions={tried}. Last bot id={last_bot_id}. "
        "Set telegram.user_session_name in config.json and login with a normal Telegram account."
    )


async def main() -> None:
    db = DB("bot.db")
    cfg_mgr = RuntimeConfig(db=db, file_path="config.json", poll_sec=2.0)
    cfg = cfg_mgr.snapshot()

    logging.basicConfig(level=getattr(logging, (cfg.get("logging", {}) or {}).get("level", "INFO")))
    log = logging.getLogger("mdma-bot")

    tg_cfg = (cfg.get("telegram", {}) or {})
    api_id = int((tg_cfg.get("api_id") or 0))
    api_hash = tg_cfg.get("api_hash") or ""
    session_name = tg_cfg.get("session_name") or "MDMA"
    user_session_name = tg_cfg.get("user_session_name")
    bot_session_name = tg_cfg.get("bot_session_name") or (str(session_name) + "_bot")
    bot_token = tg_cfg.get("bot_token") or cfg.get("bot_token") or ""

    # Listener must be a USER session (not bot).
    client, me, used_user_session = await start_user_client(
        api_id=api_id,
        api_hash=api_hash,
        base_session_name=session_name,
        user_session_name=user_session_name,
        log=log,
    )
    log.info("User listener session: %s", used_user_session)

    # Optional bot client: used for sending both config and proxy posts with inline buttons
    bot_client: Optional[TelegramClient] = None
    if bot_token:
        try:
            bot_client = TelegramClient(str(bot_session_name), api_id, api_hash)
            await bot_client.start(bot_token=bot_token)
            log.info("Bot client enabled for posting (config + proxy with buttons).")
        except Exception as e:
            bot_client = None
            log.warning("Failed to start bot client; fallback to user client (no inline buttons). err=%s", e)

    log.info("Logged in as: %s (id=%s)", getattr(me, "username", None), getattr(me, "id", None))

    enable_testing = True
    enable_geoip = True
    enable_send = True
    enable_ip_check = True
    enable_latency = True

    enabled_protocols: Set[str] = {"vless", "vmess", "trojan", "ss"}

    good_ms = 300
    ok_ms = 900
    test_timeout = 8
    dedupe_hours = 24

    stability_tries = 3
    stability_delay_ms = 250

    gold_ping_ms = 150
    gold_need_ok = 3

    post_interval_sec = 10
    rename_text = "MDMA"
    fixed_caption = "\n\n—\n⚠️MDMA"

    geoip_timeout = 6
    enable_cf_detection = True
    ip_echo_endpoints: List[str] = [
        "https://api.ipify.org?format=json",
        "https://api64.ipify.org?format=json",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://ipinfo.io/ip",
    ]

    xray_bin = (cfg.get("xray", {}) or {}).get("binary_path", "xray")
    curl_bin = (cfg.get("curl", {}) or {}).get("binary_path", "curl")

    max_queue = 1000
    worker_count = 1

    cb_fail_threshold = 30
    cb_cooldown_sec = 60
    breaker = CircuitBreaker(cb_fail_threshold, cb_cooldown_sec)
    adaptive_enabled = True
    adaptive_history_size = 120
    adaptive_min_timeout = 4
    adaptive_max_timeout = 24
    adaptive_min_tries = 1
    adaptive_max_tries = 5
    adaptive_fail_weight = 1.4
    adaptive_stage_weight = 1.0
    adaptive = AdaptiveProbeController(
        enabled=adaptive_enabled,
        history_size=adaptive_history_size,
        min_timeout=adaptive_min_timeout,
        max_timeout=adaptive_max_timeout,
        min_tries=adaptive_min_tries,
        max_tries=adaptive_max_tries,
        fail_weight=adaptive_fail_weight,
        stage_weight=adaptive_stage_weight,
    )

    target_channel = cfg.get("target_channel") or ""
    sources_usernames, sources_chat_ids, sources_pretty = parse_source_list(cfg.get("sources") or [])

    proxy_cfg = cfg.get("proxy_pipeline", {}) or {}
    proxy_enabled = bool(proxy_cfg.get("enabled", False))
    proxy_timeout = int(proxy_cfg.get("test_timeout_sec", 6))
    proxy_good_ms = int(proxy_cfg.get("good_ms", 250))
    proxy_ok_ms = int(proxy_cfg.get("ok_ms", 900))
    proxy_dedupe_hours = int(proxy_cfg.get("dedupe_window_hours", dedupe_hours))
    proxy_post_interval_sec = int(proxy_cfg.get("post_interval_sec", post_interval_sec))
    proxy_target_channel = proxy_cfg.get("target_channel") or target_channel
    proxy_sources_usernames, proxy_sources_chat_ids, proxy_sources_pretty = parse_source_list(proxy_cfg.get("sources") or [])
    channel_button_text = "Natrixo"
    channel_button_url: Optional[str] = None

    def apply_cfg(new_cfg: Dict[str, Any]) -> None:
        nonlocal enable_testing, enable_geoip, enable_send, enable_ip_check, enable_latency
        nonlocal enabled_protocols
        nonlocal good_ms, ok_ms, test_timeout, dedupe_hours
        nonlocal stability_tries, stability_delay_ms
        nonlocal gold_ping_ms, gold_need_ok
        nonlocal post_interval_sec, rename_text, fixed_caption
        nonlocal geoip_timeout, xray_bin, curl_bin
        nonlocal enable_cf_detection, ip_echo_endpoints
        nonlocal max_queue, worker_count
        nonlocal cb_fail_threshold, cb_cooldown_sec, breaker
        nonlocal adaptive_enabled, adaptive_history_size, adaptive_min_timeout, adaptive_max_timeout
        nonlocal adaptive_min_tries, adaptive_max_tries, adaptive_fail_weight, adaptive_stage_weight, adaptive
        nonlocal target_channel, sources_usernames, sources_chat_ids, sources_pretty
        nonlocal proxy_enabled, proxy_timeout, proxy_good_ms, proxy_ok_ms, proxy_dedupe_hours, proxy_post_interval_sec
        nonlocal proxy_target_channel, proxy_sources_usernames, proxy_sources_chat_ids, proxy_sources_pretty
        nonlocal channel_button_text, channel_button_url

        switches = new_cfg.get("switches", {}) or {}
        enable_testing = bool(switches.get("enable_testing", True))
        enable_geoip = bool(switches.get("enable_geoip", True))
        enable_send = bool(switches.get("enable_send", True))
        enable_ip_check = bool(switches.get("enable_ip_check", True))
        enable_latency = bool(switches.get("enable_latency", True))

        filters = new_cfg.get("filters", {}) or {}
        enabled_protocols = set([str(x).lower() for x in (filters.get("enabled_protocols") or ["vless", "vmess", "trojan", "ss"])])
        good_ms = int(filters.get("good_ms", 300))
        ok_ms = int(filters.get("ok_ms", 900))
        test_timeout = int(filters.get("test_timeout_sec", 8))
        dedupe_hours = int(filters.get("dedupe_window_hours", 24))

        stability_tries = int(filters.get("stability_tries", 3))
        stability_delay_ms = int(filters.get("stability_delay_ms", 250))

        gold_ping_ms = int(filters.get("gold_ping_ms", 150))
        gold_need_ok = int(filters.get("gold_need_ok", 3))

        worker_count = int(filters.get("worker_count", 1))
        max_queue = int(filters.get("max_queue", 1000))

        cb_fail_threshold = int(filters.get("cb_fail_threshold", 30))
        cb_cooldown_sec = int(filters.get("cb_cooldown_sec", 60))
        breaker = CircuitBreaker(cb_fail_threshold, cb_cooldown_sec)

        ad_cfg = new_cfg.get("adaptive_testing", {}) or {}
        adaptive_enabled = bool(ad_cfg.get("enabled", True))
        adaptive_history_size = int(ad_cfg.get("history_size", 120))
        adaptive_min_timeout = int(ad_cfg.get("min_timeout_sec", 4))
        adaptive_max_timeout = int(ad_cfg.get("max_timeout_sec", 24))
        adaptive_min_tries = int(ad_cfg.get("min_tries", 1))
        adaptive_max_tries = int(ad_cfg.get("max_tries", 5))
        adaptive_fail_weight = float(ad_cfg.get("fail_weight", 1.4))
        adaptive_stage_weight = float(ad_cfg.get("stage_weight", 1.0))
        adaptive = AdaptiveProbeController(
            enabled=adaptive_enabled,
            history_size=adaptive_history_size,
            min_timeout=adaptive_min_timeout,
            max_timeout=adaptive_max_timeout,
            min_tries=adaptive_min_tries,
            max_tries=adaptive_max_tries,
            fail_weight=adaptive_fail_weight,
            stage_weight=adaptive_stage_weight,
        )

        post_interval_sec = int(new_cfg.get("post_interval_sec", 10))
        rename_text = str(new_cfg.get("rename_text", "MDMA"))

        cap = new_cfg.get("caption", {}) or {}
        fixed_caption = str(cap.get("fixed", "\n\n—\n⚠️MDMA"))

        geoip_timeout = int((new_cfg.get("geoip", {}) or {}).get("timeout_sec", 6))
        cf_cfg = new_cfg.get("cloudflare", {}) or {}
        enable_cf_detection = bool(cf_cfg.get("enabled", True))

        ip_cfg = new_cfg.get("ip_check", {}) or {}
        raw_eps = ip_cfg.get("endpoints")
        if isinstance(raw_eps, list):
            eps_norm: List[str] = []
            eps_seen: Set[str] = set()
            for ep in raw_eps:
                s = str(ep or "").strip()
                if not s or s in eps_seen:
                    continue
                eps_seen.add(s)
                eps_norm.append(s)
            if eps_norm:
                ip_echo_endpoints = eps_norm

        xray_bin = str((new_cfg.get("xray", {}) or {}).get("binary_path", xray_bin))
        curl_bin = str((new_cfg.get("curl", {}) or {}).get("binary_path", curl_bin))

        target_channel = str(new_cfg.get("target_channel") or target_channel)
        sources_usernames, sources_chat_ids, sources_pretty = parse_source_list(new_cfg.get("sources") or [])

        pc = new_cfg.get("proxy_pipeline", {}) or {}
        proxy_enabled = bool(pc.get("enabled", proxy_enabled))
        proxy_timeout = int(pc.get("test_timeout_sec", proxy_timeout))
        proxy_good_ms = int(pc.get("good_ms", proxy_good_ms))
        proxy_ok_ms = int(pc.get("ok_ms", proxy_ok_ms))
        proxy_dedupe_hours = int(pc.get("dedupe_window_hours", proxy_dedupe_hours))
        proxy_post_interval_sec = int(pc.get("post_interval_sec", proxy_post_interval_sec))
        proxy_target_channel = str(pc.get("target_channel") or proxy_target_channel)
        proxy_sources_usernames, proxy_sources_chat_ids, proxy_sources_pretty = parse_source_list(pc.get("sources") or [])

        btn = new_cfg.get("buttons", {}) or {}
        channel_button_text = str(btn.get("channel_text", "Natrixo")).strip() or "Natrixo"
        channel_button_url = channel_to_tme_url(str(btn.get("channel_url", "")).strip())

    apply_cfg(cfg)

    q: asyncio.Queue[Job] = asyncio.Queue()
    sem = asyncio.Semaphore(max(1, worker_count))
    worker_tasks: List[asyncio.Task] = []

    async def ensure_workers() -> None:
        nonlocal sem
        sem = asyncio.Semaphore(max(1, worker_count))
        while len(worker_tasks) < max(1, worker_count):
            idx = len(worker_tasks) + 1
            worker_tasks.append(asyncio.create_task(worker_loop(idx)))

    async def heartbeat_loop() -> None:
        while True:
            try:
                meta = {
                    "queue": q.qsize(),
                    "max_queue": max_queue,
                    "workers": worker_count,
                    "breaker": breaker.state(),
                    "switches": {
                        "enable_testing": enable_testing,
                        "enable_geoip": enable_geoip,
                        "enable_send": enable_send,
                        "enable_ip_check": enable_ip_check,
                        "enable_latency": enable_latency,
                    },
                    "ip_check": {
                        "endpoint_count": len(ip_echo_endpoints),
                        "cloudflare_detection": enable_cf_detection,
                    },
                    "adaptive_testing": adaptive.state(),
                    "target": target_channel,
                    "sources": sources_pretty,
                    "proxy_pipeline": {
                        "enabled": proxy_enabled,
                        "target": proxy_target_channel,
                        "sources": proxy_sources_pretty,
                        "bot_buttons": bool(bot_client),
                    },
                    "config_runtime_updated_ts": cfg_mgr.last_runtime_ts,
                }
                db.set_health("bot", "ok", meta)
            except Exception:
                pass
            await asyncio.sleep(15)

    async def config_refresh_loop() -> None:
        async def on_change(new_cfg: Dict[str, Any]) -> None:
            apply_cfg(new_cfg)
            await ensure_workers()
            log.info("Runtime config updated (ts=%s). Applied live.", cfg_mgr.last_runtime_ts)

        await cfg_mgr.loop(on_change=on_change)

    def is_from_sources(chat_username: Optional[str], chat_id: Optional[int]) -> bool:
        u = (chat_username or "").lower().strip()
        if u and u in sources_usernames:
            return True
        if chat_id is not None and int(chat_id) in sources_chat_ids:
            return True
        return False

    def is_from_proxy_sources(chat_username: Optional[str], chat_id: Optional[int]) -> bool:
        u = (chat_username or "").lower().strip()
        if u and u in proxy_sources_usernames:
            return True
        if chat_id is not None and int(chat_id) in proxy_sources_chat_ids:
            return True
        return False

    async def enqueue_job(job: Job) -> None:
        if q.qsize() >= max_queue:
            log.warning("Queue full; dropping job kind=%s from %s msg=%s", job.kind, job.source, job.msg_id)
            db.add_event(kind="drop_queue_full", source=job.source, msg_id=job.msg_id, detail=f"kind={job.kind}")
            return
        await q.put(job)
        db.add_event(kind="enqueue", source=job.source, msg_id=job.msg_id, detail=f"kind={job.kind}")

    @client.on(events.NewMessage(incoming=True))
    async def handler(event: events.NewMessage.Event) -> None:
        try:
            chat = await event.get_chat()
        except Exception:
            return

        username = getattr(chat, "username", None)
        chat_id = getattr(event, "chat_id", None)
        src = ("@" + username.lower()) if username else (str(chat_id) if chat_id is not None else "unknown")

        if is_from_sources(username, chat_id):
            links = extract_config_links(event.message)
            if links:
                db.add_event(kind="rx", source=src, msg_id=event.message.id, detail=f"config_links={len(links)}")
                for raw_link in links:
                    await enqueue_job(Job(kind="config", payload=raw_link, source=src, msg_id=event.message.id))

        if proxy_enabled and is_from_proxy_sources(username, chat_id):
            plinks = extract_proxy_links(event.message)
            db.add_event(kind="proxy_rx", source=src, msg_id=event.message.id, detail=f"proxy_links={len(plinks)}")
            for raw_link in plinks:
                await enqueue_job(Job(kind="proxy", payload=raw_link, source=src, msg_id=event.message.id))

    async def process_config_job(job: Job) -> None:
        raw_link = clean_link(job.payload)
        p = proto_of(raw_link)
        if p not in enabled_protocols:
            db.add_event(kind="skip_proto", source=job.source, msg_id=job.msg_id, proto=p, detail="disabled_proto")
            return

        norm = normalize_config_for_fp(raw_link)
        fp = sha1(norm)
        db.touch_seen(fp)

        if db.recently_posted(fp, dedupe_hours):
            db.add_event(kind="dedupe_skip", source=job.source, msg_id=job.msg_id, fp=fp, proto=p, detail="recently_posted")
            return

        try:
            outbound = build_outbound_from_link(raw_link)
        except Exception as e:
            db.set_test_result(fp, "skip", None, None, None, None, None, None)
            db.add_event(kind="parse_fail", source=job.source, msg_id=job.msg_id, fp=fp, proto=p, status="skip", detail=str(e))
            return

        transport_fp = extract_transport_fingerprint(raw_link, outbound)
        edge_info: Dict[str, Any] = {}
        if enable_cf_detection:
            try:
                edge_info = await detect_edge_info(outbound, geoip_timeout=geoip_timeout)
            except Exception:
                edge_info = {}

        if breaker.is_paused():
            db.add_event(kind="cb_paused_skip", source=job.source, msg_id=job.msg_id, fp=fp, proto=p, detail=f"remaining={breaker.remaining()}")
            return

        if not enable_testing:
            db.set_test_result(fp, "ok", None, None, None, None, None, None)
            db.add_event(kind="test_bypassed", source=job.source, msg_id=job.msg_id, fp=fp, proto=p, status="ok", detail="enable_testing=false")
            return

        xray_resolved = resolve_executable(xray_bin)
        if not xray_resolved:
            raise FileNotFoundError(f"xray not found (path or PATH): {xray_bin}")
        if (os.sep in xray_resolved or xray_resolved.startswith((".", "/"))) and not os.access(xray_resolved, os.X_OK):
            raise PermissionError(f"xray not executable: {xray_resolved}")

        socks_port = pick_socks_port()
        xcfg = build_xray_test_config(outbound, socks_port)
        base_tries = max(1, int(stability_tries))
        eff_timeout, eff_tries, adaptive_meta = adaptive.decide(test_timeout, base_tries)

        try:
            res = await run_xray_test(
                xray_bin=xray_resolved,
                xray_config=xcfg,
                timeout_sec=eff_timeout,
                curl_bin=curl_bin,
                tries=eff_tries,
                delay_ms=stability_delay_ms,
                do_ip_check=enable_ip_check,
                do_latency=enable_latency,
                ip_echo_endpoints=ip_echo_endpoints,
            )
        except Exception as e:
            adaptive.update(type("R", (), {"ok": False, "stage": "xray_exec_fail"})())
            breaker.on_fail()
            db.set_test_result(fp, "fail", None, None, None, None, None, None)
            db.add_event(
                kind="test_crash",
                source=job.source,
                msg_id=job.msg_id,
                fp=fp,
                proto=p,
                status="fail",
                detail=json.dumps({"stage": "xray_exec_fail", "error": str(e), "adaptive": adaptive_meta}, ensure_ascii=False),
            )
            logging.getLogger("mdma-bot").exception("Test crashed: %s", e)
            return

        if not res.ok:
            adaptive.update(res)
            breaker.on_fail()
            db.set_test_result(fp, "fail", res.latency_ms, res.exit_ip, None, None, None, None)
            db.add_event(
                kind="test",
                source=job.source,
                msg_id=job.msg_id,
                fp=fp,
                proto=p,
                status="fail",
                latency_ms=res.latency_ms,
                exit_ip=res.exit_ip,
                detail=json.dumps(
                    {
                        "ok_count": res.ok_count,
                        "tries": res.tries,
                        "stage": res.stage,
                        "stage_detail": res.stage_detail,
                        "ok_endpoint": res.ok_endpoint,
                        "ip_version": res.ip_version,
                        "ok_count_v4": res.ok_count_v4,
                        "ok_count_v6": res.ok_count_v6,
                        "egress_consistent": res.egress_consistent,
                        "handshake_ok": res.handshake_ok,
                        "handshake_detail": res.handshake_detail or {},
                        "probe_results": res.probe_results or [],
                        "tls_telemetry": res.tls_telemetry or {},
                        "ws_probe": res.ws_probe or {},
                        "grpc_probe": res.grpc_probe or {},
                        "transport_fp": transport_fp,
                        "edge": edge_info,
                        "adaptive": adaptive_meta,
                    },
                    ensure_ascii=False,
                ),
            )
            return

        adaptive.update(res)
        breaker.on_success()

        cc = country = asn = org = None
        if enable_geoip and res.exit_ip:
            try:
                cc, country, asn, org = await geoip_ipapi_full(res.exit_ip, timeout_sec=geoip_timeout)
            except Exception:
                cc = country = asn = org = None

        flag = flag_emoji_from_cc(cc or "")
        security_label = detect_security_from_link(raw_link)
        exit_is_cloudflare = _is_cloudflare_asn_org(asn, org)
        edge_is_cloudflare = bool(edge_info.get("edge_is_cloudflare"))
        if edge_is_cloudflare and exit_is_cloudflare:
            cf_path = "cloudflare_edge_and_exit"
        elif edge_is_cloudflare and not exit_is_cloudflare:
            cf_path = "via_cloudflare_edge"
        elif (not edge_is_cloudflare) and exit_is_cloudflare:
            cf_path = "cloudflare_exit_only"
        else:
            cf_path = "non_cloudflare_or_unknown"

        latency_ms = int(res.latency_ms or 999999)
        latency_grade_code = grade_from_latency(latency_ms, good_ms, ok_ms)
        stage_fail_history = db.get_recent_stage_fail_count(fp=fp, stage=None, hours=24, limit=300)
        same_stage_fail_history = db.get_recent_stage_fail_count(
            fp=fp,
            stage=(res.stage or ""),
            hours=24,
            limit=300,
        )
        quality = evaluate_quality_grade(
            latency_ms=latency_ms,
            good_ms=good_ms,
            ok_ms=ok_ms,
            ok_count=int(res.ok_count),
            tries=int(res.tries),
            handshake_ok=res.handshake_ok,
            egress_consistent=res.egress_consistent,
            stage_fail_history=stage_fail_history,
        )
        grade_code = str(quality.get("grade_code") or latency_grade_code)

        gold_pick = (latency_ms <= gold_ping_ms) and (res.ok_count >= gold_need_ok) and (res.tries >= gold_need_ok)
        star = "⭐️ " if gold_pick else ""
        new_name = f"{star}{flag} {rename_text} {grade_code}".strip()
        renamed_link = apply_rename(raw_link, new_name)

        db.set_test_result(fp, "ok", latency_ms, res.exit_ip, cc, country, asn, org)
        db.add_event(
            kind="test",
            source=job.source,
            msg_id=job.msg_id,
            fp=fp,
            proto=p,
            status="ok",
            latency_ms=latency_ms,
            exit_ip=res.exit_ip,
            country_code=cc,
            country=country,
            asn=asn,
            org=org,
            detail=json.dumps(
                {
                    "ok_count": res.ok_count,
                    "tries": res.tries,
                    "grade": grade_code,
                    "latency_grade": latency_grade_code,
                    "quality": quality,
                    "security": security_label,
                    "stage": res.stage,
                    "stage_detail": res.stage_detail,
                    "ok_endpoint": res.ok_endpoint,
                    "ip_version": res.ip_version,
                    "ok_count_v4": res.ok_count_v4,
                    "ok_count_v6": res.ok_count_v6,
                    "egress_consistent": res.egress_consistent,
                    "handshake_ok": res.handshake_ok,
                    "handshake_detail": res.handshake_detail or {},
                    "stage_fail_history": stage_fail_history,
                    "same_stage_fail_history": same_stage_fail_history,
                    "probe_results": res.probe_results or [],
                    "tls_telemetry": res.tls_telemetry or {},
                    "ws_probe": res.ws_probe or {},
                    "grpc_probe": res.grpc_probe or {},
                    "transport_fp": transport_fp,
                    "edge": edge_info,
                    "exit_is_cloudflare": exit_is_cloudflare,
                    "cloudflare_path": cf_path,
                    "adaptive": adaptive_meta,
                },
                ensure_ascii=False,
            ),
        )

        if not enable_send:
            db.add_event(kind="send_bypassed", source=job.source, msg_id=job.msg_id, fp=fp, proto=p, status="ok", detail="enable_send=false")
            return

        msg = render_post_html(
            renamed_link=renamed_link,
            flag=flag,
            country=country or (cc or "Unknown"),
            proto=p,
            security_label=security_label,
            latency_ms=latency_ms,
            grade_code=grade_code,
            ok_count=res.ok_count,
            tries=res.tries,
            asn=asn,
            org=org,
            fixed_caption=fixed_caption,
            add_tags=True,
            gold_pick=gold_pick,
        )

        channel_url_cfg = channel_button_url or channel_to_tme_url(target_channel)

        sent_with_bot_api = False
        if bot_token and channel_url_cfg:
            cfg_reply_markup = {
                "inline_keyboard": [
                    [
                        {
                            "text": channel_button_text,
                            "url": channel_url_cfg,
                            "style": "primary",
                        }
                    ]
                ]
            }
            sent_with_bot_api = await safe_send_bot_api_html(
                bot_token=bot_token,
                target=target_channel,
                text_html=msg,
                reply_markup=cfg_reply_markup,
            )

        if not sent_with_bot_api:
            send_client = bot_client if bot_client else client
            cfg_buttons = None
            if bot_client and channel_url_cfg:
                cfg_buttons = [[Button.url(channel_button_text, channel_url_cfg)]]

            await safe_send_html(send_client, target_channel, msg, buttons=cfg_buttons)
        db.mark_posted(fp)
        db.add_event(kind="posted", source=job.source, msg_id=job.msg_id, fp=fp, proto=p, status="ok", latency_ms=latency_ms, exit_ip=res.exit_ip, country_code=cc, country=country, asn=asn, org=org, detail="posted")
        await asyncio.sleep(max(0, int(post_interval_sec)))

    async def process_proxy_job(job: Job) -> None:
        raw_link = clean_link(job.payload)
        try:
            proxy = parse_proxy_link(raw_link)
        except Exception as e:
            db.add_event(kind="proxy_parse_fail", source=job.source, msg_id=job.msg_id, status="skip", detail=str(e))
            return

        fp = sha1(proxy.normalized())
        db.touch_seen(fp)

        if db.recently_posted(fp, proxy_dedupe_hours):
            db.add_event(kind="proxy_dedupe_skip", source=job.source, msg_id=job.msg_id, fp=fp, proto=f"tg_{proxy.kind}", detail="recently_posted")
            return

        res = await test_telegram_proxy(proxy, timeout_sec=proxy_timeout)

        proto_tag = f"tg_{proxy.kind}"
        if not res.ok:
            db.set_test_result(fp, "fail", res.latency_ms, res.exit_ip, None, None, None, None)
            db.add_event(kind="proxy_test", source=job.source, msg_id=job.msg_id, fp=fp, proto=proto_tag, status="fail", latency_ms=res.latency_ms, exit_ip=res.exit_ip, detail=res.detail)
            return

        cc = country = asn = org = None
        if enable_geoip and res.exit_ip:
            try:
                cc, country, asn, org = await geoip_ipapi_full(res.exit_ip, timeout_sec=geoip_timeout)
            except Exception:
                cc = country = asn = org = None

        latency_ms = int(res.latency_ms or 999999)
        grade_code = grade_from_latency(latency_ms, proxy_good_ms, proxy_ok_ms)

        db.set_test_result(fp, "ok", latency_ms, res.exit_ip, cc, country, asn, org)
        db.add_event(kind="proxy_test", source=job.source, msg_id=job.msg_id, fp=fp, proto=proto_tag, status="ok", latency_ms=latency_ms, exit_ip=res.exit_ip, country_code=cc, country=country, asn=asn, org=org, detail=res.detail)

        if not enable_send:
            db.add_event(kind="proxy_send_bypassed", source=job.source, msg_id=job.msg_id, fp=fp, proto=proto_tag, status="ok", detail="enable_send=false")
            return

        msg = render_proxy_post_html(
            proxy=proxy,
            latency_ms=latency_ms,
            grade_code=grade_code,
            exit_ip=res.exit_ip,
            cc=cc,
            country=country,
            asn=asn,
            org=org,
            fixed_caption=fixed_caption,
        )

        add_link = proxy_http_link(proxy)
        btn_text = "➕ Add Proxy" if proxy.kind != "socks" else "➕ Add SOCKS5"

        channel_url_proxy = channel_button_url or channel_to_tme_url(proxy_target_channel) or channel_to_tme_url(target_channel)

        sent_with_bot_api = False
        if bot_token:
            row = [
                {
                    "text": btn_text,
                    "url": add_link,
                    "style": "primary",
                }
            ]

            if channel_url_proxy:
                row.append(
                    {
                        "text": channel_button_text,
                        "url": channel_url_proxy,
                        "style": "primary",
                    }
                )

            proxy_reply_markup = {
                "inline_keyboard": [row]
            }

            sent_with_bot_api = await safe_send_bot_api_html(
                bot_token=bot_token,
                target=proxy_target_channel,
                text_html=msg,
                reply_markup=proxy_reply_markup,
            )

        if not sent_with_bot_api:
            send_client = bot_client if bot_client else client
            buttons = None
            if bot_client:
                row2 = [Button.url(btn_text, add_link)]
                if channel_url_proxy:
                    row2.append(Button.url(channel_button_text, channel_url_proxy))
                buttons = [row2]

            await safe_send_html_proxy(send_client, proxy_target_channel, msg, buttons=buttons)
        db.mark_posted(fp)
        db.add_event(kind="proxy_posted", source=job.source, msg_id=job.msg_id, fp=fp, proto=proto_tag, status="ok", latency_ms=latency_ms, exit_ip=res.exit_ip, country_code=cc, country=country, asn=asn, org=org, detail="posted")
        await asyncio.sleep(max(0, int(proxy_post_interval_sec)))

    async def worker_loop(i: int) -> None:
        wlog = logging.getLogger("mdma-bot")
        wlog.info("Worker-%d started", i)
        while True:
            job = await q.get()
            try:
                async with sem:
                    if job.kind == "config":
                        await process_config_job(job)
                    else:
                        await process_proxy_job(job)
            except Exception as e:
                wlog.exception("Worker-%d error: %s", i, e)
                db.add_event(kind="worker_error", source=job.source, msg_id=job.msg_id, detail=str(e))
            finally:
                q.task_done()

    asyncio.create_task(heartbeat_loop())
    asyncio.create_task(config_refresh_loop())
    await ensure_workers()

    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
