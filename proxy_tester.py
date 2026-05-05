# proxy_tester.py
from __future__ import annotations

import asyncio
import html
import re
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional

RE_IP = re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3})|(?:[0-9a-fA-F:]{2,})")

_INVISIBLES = [
    "\u200b", "\u200c", "\u200d", "\ufeff",
    "\u2060", "\u00ad",
    "\u200e", "\u200f",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
]

_LEADING_TRIM = " \t\r\n<([{«“\"'`"
_TRAILING_TRIM = " \t\r\n>)]}»”\"'`,.;:…!؟،؛"


def _clean_link(s: str) -> str:
    s = str(s or "")
    for ch in _INVISIBLES:
        s = s.replace(ch, "")
    try:
        s = html.unescape(s)
    except Exception:
        pass
    s = s.replace("\r", "").replace("\n", "").strip()
    while True:
        s2 = s.lstrip(_LEADING_TRIM).rstrip(_TRAILING_TRIM).strip()
        if s2 == s:
            break
        s = s2
    return s


# tg://socks?... , tg://proxy?... ,
# https://t.me/socks?... , https://t.me/proxy?... ,
# telegram.me variants, and also bare "t.me/proxy?..."
RE_PROXY_LINK = re.compile(
    r"(?i)("
    r"tg://(?:socks|proxy)\?[^\s<>'\"`]+"
    r"|(?:https?://)?(?:t\.me|telegram\.me)/(?:socks|proxy)\?[^\s<>'\"`]+"
    r")"
)


@dataclass(frozen=True)
class TelegramProxy:
    kind: str  # "socks" | "mtproto"
    server: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    secret: Optional[str] = None  # mtproto secret (hex)

    def normalized(self) -> str:
        k = (self.kind or "").lower().strip()
        srv = (self.server or "").lower().strip()
        prt = int(self.port)

        if k == "socks":
            u = (self.username or "").strip()
            p = (self.password or "").strip()
            return f"socks|{srv}|{prt}|{u}|{p}"

        sec = (self.secret or "").strip().lower()
        return f"mtproto|{srv}|{prt}|{sec}"

    def share_link(self) -> str:
        if self.kind == "socks":
            q = {"server": self.server, "port": str(self.port)}
            if self.username:
                q["user"] = self.username
            if self.password:
                q["pass"] = self.password
            return "tg://socks?" + urllib.parse.urlencode(q, doseq=False)

        q2 = {"server": self.server, "port": str(self.port)}
        if self.secret:
            q2["secret"] = self.secret
        return "tg://proxy?" + urllib.parse.urlencode(q2, doseq=False)


def _clean_host(h: str) -> str:
    h = (h or "").strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h.strip()


def parse_proxy_link(link: str) -> TelegramProxy:
    """
    Supports:
      - tg://socks?server=HOST&port=PORT&user=U&pass=P
      - tg://proxy?server=HOST&port=PORT&secret=HEX
      - https://t.me/socks?...
      - https://t.me/proxy?...
      - https://telegram.me/(socks|proxy)?...
      - bare: t.me/proxy?...   telegram.me/socks?...
      - HTML-escaped: &amp; inside query
    """
    s = _clean_link(link)

    # accept bare domains without scheme
    if re.match(r"^(t\.me|telegram\.me)/", s, flags=re.IGNORECASE):
        s = "https://" + s

    # normalize https t.me/telegram.me to tg://
    if re.match(r"^https?://(?:t\.me|telegram\.me)/socks\?", s, flags=re.IGNORECASE):
        s = "tg://socks?" + s.split("?", 1)[1]
    elif re.match(r"^https?://(?:t\.me|telegram\.me)/proxy\?", s, flags=re.IGNORECASE):
        s = "tg://proxy?" + s.split("?", 1)[1]

    u = urllib.parse.urlparse(s)
    if (u.scheme or "").lower() != "tg":
        raise ValueError("Not a tg proxy link")

    host = (u.netloc or "").lower().strip()
    qs = urllib.parse.parse_qs(u.query or "", keep_blank_values=False)

    def qget(name: str) -> Optional[str]:
        v = qs.get(name)
        if not v:
            return None
        x = (v[0] or "").strip()
        return x if x else None

    server = _clean_host(qget("server") or "")
    port_s = (qget("port") or "").strip()

    if not server or not port_s or not re.fullmatch(r"\d+", port_s):
        raise ValueError("Invalid proxy params (need server, port)")

    port = int(port_s)
    if port <= 0 or port > 65535:
        raise ValueError("Invalid port")

    if host == "socks":
        user = qget("user")
        pwd = qget("pass")
        return TelegramProxy(kind="socks", server=server, port=port, username=user, password=pwd)

    if host == "proxy":
        secret = (qget("secret") or "").strip()
        if secret:
            # must be hex; do not be overly strict on length, but require even length commonly
            if not re.fullmatch(r"[0-9a-fA-F]+", secret):
                raise ValueError("Invalid mtproto secret (expected hex)")
        return TelegramProxy(kind="mtproto", server=server, port=port, secret=secret or None)

    raise ValueError("Unknown tg link kind (expected tg://socks or tg://proxy)")


@dataclass
class ProxyTestResult:
    ok: bool
    latency_ms: Optional[int] = None
    exit_ip: Optional[str] = None
    detail: Optional[str] = None


async def _read_exact(reader: asyncio.StreamReader, n: int, timeout: float) -> bytes:
    return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)


async def _socks5_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    username: Optional[str],
    password: Optional[str],
    timeout: float,
) -> None:
    if username or password:
        methods = bytes([0x00, 0x02])
    else:
        methods = bytes([0x00])

    writer.write(bytes([0x05, len(methods)]) + methods)
    await writer.drain()

    resp = await _read_exact(reader, 2, timeout)
    if resp[0] != 0x05 or resp[1] == 0xFF:
        raise RuntimeError("SOCKS5: no acceptable auth method")

    method = resp[1]
    if method == 0x02:
        u = (username or "").encode("utf-8")
        p = (password or "").encode("utf-8")
        if len(u) > 255 or len(p) > 255:
            raise RuntimeError("SOCKS5: username/password too long")

        writer.write(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
        await writer.drain()

        auth = await _read_exact(reader, 2, timeout)
        if auth[0] != 0x01 or auth[1] != 0x00:
            raise RuntimeError("SOCKS5: auth failed")


async def _socks5_connect_domain(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    domain: str,
    port: int,
    timeout: float,
) -> None:
    d = domain.encode("utf-8")
    if len(d) > 255:
        raise RuntimeError("SOCKS5: domain too long")

    req = bytes([0x05, 0x01, 0x00, 0x03, len(d)]) + d + bytes([(port >> 8) & 0xFF, port & 0xFF])
    writer.write(req)
    await writer.drain()

    head = await _read_exact(reader, 4, timeout)
    if head[0] != 0x05:
        raise RuntimeError("SOCKS5: invalid reply")
    rep = head[1]
    atyp = head[3]

    if atyp == 0x01:
        await _read_exact(reader, 4, timeout)
    elif atyp == 0x03:
        ln = await _read_exact(reader, 1, timeout)
        await _read_exact(reader, ln[0], timeout)
    elif atyp == 0x04:
        await _read_exact(reader, 16, timeout)
    else:
        raise RuntimeError("SOCKS5: unknown ATYP")

    await _read_exact(reader, 2, timeout)

    if rep != 0x00:
        raise RuntimeError(f"SOCKS5: connect failed (REP={rep})")


async def test_socks_proxy(proxy: TelegramProxy, timeout_sec: int = 6) -> ProxyTestResult:
    t0 = time.perf_counter()
    timeout = float(timeout_sec)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.server, int(proxy.port)),
            timeout=timeout,
        )
        try:
            await _socks5_handshake(reader, writer, proxy.username, proxy.password, timeout)
            await _socks5_connect_domain(reader, writer, "api.ipify.org", 80, timeout)

            req = (
                "GET /?format=text HTTP/1.1\r\n"
                "Host: api.ipify.org\r\n"
                "User-Agent: mdma-bot\r\n"
                "Connection: close\r\n\r\n"
            ).encode("utf-8")

            writer.write(req)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            text = data.decode("utf-8", errors="ignore")

            body = text.split("\r\n\r\n", 1)[-1].strip()
            m = RE_IP.search(body)
            ip = m.group(0) if m else None

            dt_ms = int((time.perf_counter() - t0) * 1000)
            if not ip:
                return ProxyTestResult(ok=True, latency_ms=dt_ms, exit_ip=None, detail="no_ip_parsed")
            return ProxyTestResult(ok=True, latency_ms=dt_ms, exit_ip=ip, detail="ok")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception as e:
        dt_ms = int((time.perf_counter() - t0) * 1000)
        return ProxyTestResult(ok=False, latency_ms=dt_ms, exit_ip=None, detail=str(e))


async def test_mtproto_tcp(proxy: TelegramProxy, timeout_sec: int = 4) -> ProxyTestResult:
    t0 = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.server, int(proxy.port)),
            timeout=float(timeout_sec),
        )
        dt_ms = int((time.perf_counter() - t0) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return ProxyTestResult(ok=True, latency_ms=dt_ms, exit_ip=None, detail="tcp_ok")
    except Exception as e:
        dt_ms = int((time.perf_counter() - t0) * 1000)
        return ProxyTestResult(ok=False, latency_ms=dt_ms, exit_ip=None, detail=str(e))


async def test_telegram_proxy(proxy: TelegramProxy, timeout_sec: int = 6) -> ProxyTestResult:
    if proxy.kind == "socks":
        return await test_socks_proxy(proxy, timeout_sec=timeout_sec)
    return await test_mtproto_tcp(proxy, timeout_sec=max(2, int(timeout_sec // 2)))
