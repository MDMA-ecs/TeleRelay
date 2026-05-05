# panel.py
import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

import pandas as pd
import streamlit as st

from db import DB

try:
    import altair as alt
except Exception:
    alt = None


# =========================================================
# UI / CSS (Glass + Gradient, safe)
# =========================================================
def _inject_css() -> None:
    st.markdown(
        """
<style>
:root{
  --glass-bg: rgba(255,255,255,0.075);
  --glass-bg2: rgba(255,255,255,0.11);
  --glass-border: rgba(255,255,255,0.16);
  --shadow: 0 22px 80px rgba(0,0,0,0.38);
  --shadow-soft: 0 14px 40px rgba(0,0,0,0.26);
  --text: rgba(255,255,255,0.92);
  --muted: rgba(255,255,255,0.72);
  --muted2: rgba(255,255,255,0.56);
  --good: #46f2a7;
  --warn: #ffd166;
  --bad: #ff5d6c;
  --info: #6aa8ff;
}

html, body, [class*="css"] {
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif;
}

.stApp{
  background:
    radial-gradient(1200px 600px at 18% 18%, rgba(98, 0, 255, 0.48), transparent 60%),
    radial-gradient(900px 500px at 80% 24%, rgba(0, 209, 255, 0.38), transparent 60%),
    radial-gradient(1200px 700px at 55% 85%, rgba(255, 0, 128, 0.28), transparent 62%),
    linear-gradient(145deg, #0b1020 0%, #070a14 50%, #060814 100%);
  color: var(--text);
  overflow-x: hidden;
}

div, p, span, label, h1, h2, h3, h4, h5, h6 { color: var(--text); }

section[data-testid="stSidebar"] > div{
  background: rgba(0,0,0,0.34);
  border-right: 1px solid rgba(255,255,255,0.10);
  backdrop-filter: blur(16px);
}

.stButton>button{
  border-radius: 16px !important;
  border: 1px solid rgba(255,255,255,0.16) !important;
  background: rgba(255,255,255,0.085) !important;
  color: var(--text) !important;
  box-shadow: var(--shadow-soft);
  transition: transform .09s ease-in-out, background .09s ease-in-out, box-shadow .09s ease-in-out;
}
.stButton>button:hover{
  transform: translateY(-1px);
  background: rgba(255,255,255,0.13) !important;
  box-shadow: 0 16px 48px rgba(0,0,0,0.32);
}

input, textarea { border-radius: 16px !important; }
div[data-baseweb="select"] > div { border-radius: 16px !important; }

button[role="tab"]{
  border-radius: 14px !important;
  border: 1px solid rgba(255,255,255,0.10) !important;
  background: rgba(255,255,255,0.06) !important;
}
button[role="tab"][aria-selected="true"]{
  border: 1px solid rgba(255,255,255,0.18) !important;
  background: rgba(255,255,255,0.10) !important;
}

.glass{
  background: var(--glass-bg);
  border: 1px solid var(--glass-border);
  border-radius: 24px;
  padding: 18px 18px;
  backdrop-filter: blur(18px);
  box-shadow: var(--shadow);
  position: relative;
  overflow: hidden;
}
.glass::before{
  content:"";
  position:absolute;
  inset:-2px;
  border-radius: 24px;
  background: linear-gradient(120deg, rgba(98,0,255,0.18), rgba(0,209,255,0.12), rgba(255,0,128,0.10));
  filter: blur(22px);
  opacity: 0.70;
  pointer-events:none;
}

.glass-lite{
  background: rgba(255,255,255,0.055);
  border: 1px solid rgba(255,255,255,0.13);
  border-radius: 22px;
  padding: 14px 14px;
  backdrop-filter: blur(16px);
  box-shadow: var(--shadow-soft);
}

.hero{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap: 14px;
  padding: 18px 18px;
  border-radius: 24px;
  background: linear-gradient(135deg, rgba(255,255,255,0.11), rgba(255,255,255,0.05));
  border: 1px solid rgba(255,255,255,0.18);
  backdrop-filter: blur(18px);
  box-shadow: var(--shadow);
  position: relative;
  overflow: hidden;
}
.hero-title{ font-size: 22px; font-weight: 900; letter-spacing: 0.2px; }
.hero-sub{ font-size: 13px; color: var(--muted); margin-top: 2px; }

.kpi-grid{
  display:grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
}
@media(max-width: 1100px){ .kpi-grid{ grid-template-columns: repeat(2, minmax(0, 1fr)); } }

.kpi{
  border-radius: 22px;
  padding: 14px 14px;
  background: var(--glass-bg2);
  border: 1px solid rgba(255,255,255,0.16);
  backdrop-filter: blur(18px);
  box-shadow: var(--shadow-soft);
  position: relative;
  overflow: hidden;
}
.kpi-top{ display:flex; align-items:center; justify-content:space-between; gap: 10px; }
.kpi-title{ font-size: 12px; color: var(--muted); font-weight: 700; }
.kpi-icon{
  width: 36px; height: 36px; border-radius: 16px;
  display:flex; align-items:center; justify-content:center;
  background: rgba(255,255,255,0.10);
  border: 1px solid rgba(255,255,255,0.14);
}
.kpi-value{ font-size: 22px; font-weight: 950; margin-top: 8px; letter-spacing: .2px; }
.kpi-hint{ font-size: 12px; color: var(--muted2); margin-top: 2px; }

.badge{
  display:inline-flex; align-items:center; gap: 6px;
  font-size: 12px; padding: 6px 10px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,0.16);
  background: rgba(255,255,255,0.06);
  backdrop-filter: blur(10px);
}
.badge.ok{ border-color: rgba(70,242,167,0.35); color: var(--good); }
.badge.warn{ border-color: rgba(255,209,102,0.35); color: var(--warn); }
.badge.bad{ border-color: rgba(255,93,108,0.35); color: var(--bad); }
.badge.info{ border-color: rgba(106,168,255,0.35); color: var(--info); }

[data-testid="stDataFrame"]{
  border-radius: 20px;
  overflow: hidden;
  border: 1px solid rgba(255,255,255,0.14);
  background: rgba(255,255,255,0.05);
  box-shadow: var(--shadow-soft);
}
hr{ border-color: rgba(255,255,255,0.14) !important; }
</style>
""",
        unsafe_allow_html=True,
    )


def html_escape(s: Any) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def badge(kind: str, text: str) -> str:
    cls = "info"
    if kind == "ok":
        cls = "ok"
    elif kind == "warn":
        cls = "warn"
    elif kind == "bad":
        cls = "bad"
    return f'<span class="badge {cls}">{html_escape(text)}</span>'


def hero(title: str, subtitle: str, right_badge: str = "info", right_text: str = "Live") -> None:
    st.markdown(
        f"""
<div class="hero">
  <div>
    <div class="hero-title">{html_escape(title)}</div>
    <div class="hero-sub">{html_escape(subtitle)}</div>
  </div>
  <div class="badge {html_escape(right_badge)}">{html_escape(right_text)}</div>
</div>
""",
        unsafe_allow_html=True,
    )
    st.write("")


def glass_open(kind: str = "glass") -> None:
    st.markdown(f'<div class="{kind}">', unsafe_allow_html=True)


def glass_close() -> None:
    st.markdown("</div>", unsafe_allow_html=True)


def kpi_card(title: str, value: Any, hint: str = "", icon: str = "⚡") -> None:
    st.markdown(
        f"""
<div class="kpi">
  <div class="kpi-top">
    <div class="kpi-title">{html_escape(title)}</div>
    <div class="kpi-icon">{html_escape(icon)}</div>
  </div>
  <div class="kpi-value">{html_escape(value)}</div>
  <div class="kpi-hint">{html_escape(hint)}</div>
</div>
""",
        unsafe_allow_html=True,
    )


# =========================================================
# Auth
# =========================================================
def must_login(username: str, password: str) -> None:
    st.session_state.setdefault("authed", False)
    if st.session_state["authed"]:
        return

    _inject_css()
    hero("MDMA Bot Panel", "ورود به پنل مدیریتی (Glass UI)", "info", "🔐 Auth")

    c1, c2, c3 = st.columns([1, 1.2, 1])
    with c2:
        glass_open("glass")
        st.markdown("### Login")
        u = st.text_input("Username", value="")
        p = st.text_input("Password", value="", type="password")

        b1, b2 = st.columns(2)
        with b1:
            ok = st.button("Login ✅", use_container_width=True)
        with b2:
            st.button("Clear", use_container_width=True, on_click=lambda: st.session_state.clear())

        if ok:
            if u == username and p == password:
                st.session_state["authed"] = True
                st.rerun()
            else:
                st.error("Wrong username/password")
        glass_close()

    st.stop()


# =========================================================
# Config + helpers
# =========================================================
def load_cfg() -> Dict[str, Any]:
    with open("config.json", "r", encoding="utf-8") as f:
        return json.load(f)


def ts_to_str(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def now_ts() -> int:
    return int(time.time())


def cutoff_ts(hours: int) -> int:
    return now_ts() - int(hours * 3600)


def in_window(df: pd.DataFrame, hours: int) -> pd.DataFrame:
    if df is None or df.empty or "ts" not in df.columns:
        return df
    c = cutoff_ts(hours)
    try:
        return df[df["ts"].astype(int) >= c].copy()
    except Exception:
        return df.copy()


def safe_series(df: pd.DataFrame, col: str) -> pd.Series:
    if df is None or df.empty or col not in df.columns:
        return pd.Series([], dtype="object")
    return df[col]


def normalize_sources(lines: List[str]) -> List[str]:
    out = []
    seen = set()
    for s in lines:
        s = (s or "").strip()
        if not s:
            continue
        if s in seen:
            continue
        out.append(s)
        seen.add(s)
    return out


def _safe_json_loads(s: Any) -> Dict[str, Any]:
    try:
        if not s:
            return {}
        if isinstance(s, dict):
            return s
        return json.loads(str(s))
    except Exception:
        return {}


def _extract_detail_fields(detail: Any) -> Dict[str, Any]:
    d = _safe_json_loads(detail)
    fp = d.get("transport_fp") or {}
    tls = d.get("tls_telemetry") or {}
    ws = d.get("ws_probe") or {}
    grpc = d.get("grpc_probe") or {}
    edge = d.get("edge") or {}

    return {
        "stage": d.get("stage"),
        "stage_detail": d.get("stage_detail"),
        "ok_endpoint": d.get("ok_endpoint"),
        "ip_version": d.get("ip_version"),
        "ok_count_v4": d.get("ok_count_v4"),
        "ok_count_v6": d.get("ok_count_v6"),
        "egress_consistent": d.get("egress_consistent"),
        "handshake_ok": d.get("handshake_ok"),
        "quality_score": (d.get("quality") or {}).get("quality_score") if isinstance(d.get("quality"), dict) else None,
        "quality_grade": (d.get("quality") or {}).get("grade_code") if isinstance(d.get("quality"), dict) else None,
        "cloudflare_path": d.get("cloudflare_path"),
        "exit_is_cloudflare": d.get("exit_is_cloudflare"),
        "fp_network": fp.get("network"),
        "fp_security": fp.get("security"),
        "fp_sni": fp.get("sni"),
        "fp_service_name": fp.get("serviceName"),
        "fp_path": fp.get("path"),
        "fp_host_header": fp.get("host_header"),
        "fp_target_host": fp.get("target_host"),
        "fp_port": fp.get("port"),
        "tls_ok": tls.get("ok"),
        "tls_stage": tls.get("stage"),
        "tls_version": tls.get("tls_version"),
        "tls_alpn": tls.get("alpn"),
        "tls_cert_issuer": tls.get("cert_issuer"),
        "ws_ok": ws.get("ok"),
        "ws_stage": ws.get("stage"),
        "ws_http_status": ws.get("http_status"),
        "grpc_ok": grpc.get("ok"),
        "grpc_stage": grpc.get("stage"),
        "grpc_http_status": grpc.get("http_status"),
        "edge_host": edge.get("edge_host"),
        "edge_ip": edge.get("edge_ip"),
        "edge_asn": edge.get("edge_asn"),
        "edge_org": edge.get("edge_org"),
        "edge_is_cloudflare": edge.get("edge_is_cloudflare"),
    }


def merge_settings(cfg_file: Dict[str, Any], runtime: Dict[str, Any]) -> Dict[str, Any]:
    defaults = {
        "switches": {
            "enable_testing": True,
            "enable_ip_check": True,
            "enable_latency": True,
            "enable_geoip": True,
            "enable_send": True,
        },
        "filters": {
            "enabled_protocols": (cfg_file.get("filters", {}) or {}).get("enabled_protocols", ["vless", "vmess", "trojan", "ss"]),
            "good_ms": (cfg_file.get("filters", {}) or {}).get("good_ms", 300),
            "ok_ms": (cfg_file.get("filters", {}) or {}).get("ok_ms", 900),
            "test_timeout_sec": (cfg_file.get("filters", {}) or {}).get("test_timeout_sec", 8),
            "dedupe_window_hours": (cfg_file.get("filters", {}) or {}).get("dedupe_window_hours", 24),
            "stability_tries": 3,
            "stability_delay_ms": 250,
            "worker_count": 1,
            "max_queue": 1000,
            "cb_fail_threshold": 30,
            "cb_cooldown_sec": 60,
            "gold_ping_ms": 150,
            "gold_need_ok": 3,
        },
        "rename_text": cfg_file.get("rename_text", "MDMA"),
        "post_interval_sec": cfg_file.get("post_interval_sec", 10),
        "caption": cfg_file.get("caption", {}),
        "geoip": cfg_file.get("geoip", {}),
        "xray": cfg_file.get("xray", {}),
        "curl": cfg_file.get("curl", {}),
        "sources": cfg_file.get("sources", []),
        "target_channel": cfg_file.get("target_channel", ""),
        "proxy_pipeline": cfg_file.get("proxy_pipeline", {"enabled": False, "sources": [], "target_channel": ""}),
        "ip_check": cfg_file.get("ip_check", {"endpoints": []}),
        "cloudflare": cfg_file.get("cloudflare", {"enabled": True}),
        "adaptive_testing": cfg_file.get(
            "adaptive_testing",
            {
                "enabled": True,
                "history_size": 120,
                "min_timeout_sec": 4,
                "max_timeout_sec": 24,
                "min_tries": 1,
                "max_tries": 5,
                "fail_weight": 1.4,
                "stage_weight": 1.0,
            },
        ),
    }

    merged = {}
    merged.update(defaults)
    merged.update(runtime or {})
    # normalize lists
    merged["sources"] = normalize_sources([str(x) for x in (merged.get("sources") or [])])
    pp = merged.get("proxy_pipeline") or {}
    pp["sources"] = normalize_sources([str(x) for x in (pp.get("sources") or [])])
    merged["proxy_pipeline"] = pp
    ip_ck = merged.get("ip_check") or {}
    ip_ck["endpoints"] = normalize_sources([str(x) for x in (ip_ck.get("endpoints") or [])])
    merged["ip_check"] = ip_ck
    return merged


# =========================================================
# Cache DB calls
# =========================================================
@st.cache_data(ttl=3)
def cached_kpis(db_path: str, hours: int) -> Dict[str, Any]:
    return DB(db_path).get_kpis(hours=hours)


@st.cache_data(ttl=3)
def cached_series(db_path: str, hours: int, kind: str) -> pd.DataFrame:
    rows = DB(db_path).get_timeseries(hours=hours, kind=kind)
    if not rows:
        return pd.DataFrame({"dt": pd.to_datetime([]), "count": []})
    df = pd.DataFrame(rows)
    df["dt"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
    df["count"] = pd.to_numeric(df["count"], errors="coerce").fillna(0).astype(int)
    return df[["dt", "count"]].sort_values("dt")


@st.cache_data(ttl=3)
def cached_events(db_path: str, limit: int) -> pd.DataFrame:
    rows = DB(db_path).get_events(limit=limit)
    df = pd.DataFrame(rows)
    if not df.empty and "ts" in df.columns:
        df["time"] = df["ts"].apply(ts_to_str)
        df["dt"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")
    if not df.empty and "detail" in df.columns:
        extra = df["detail"].apply(_extract_detail_fields).apply(pd.Series)
        if extra is not None and not extra.empty:
            for col in extra.columns:
                if col not in df.columns:
                    df[col] = extra[col]
    return df


@st.cache_data(ttl=3)
def cached_top_countries(db_path: str, hours: int) -> pd.DataFrame:
    rows = DB(db_path).get_top_countries(hours=hours, limit=12)
    return pd.DataFrame(rows)


@st.cache_data(ttl=3)
def cached_top_asn(db_path: str, hours: int) -> pd.DataFrame:
    rows = DB(db_path).get_top_asn(hours=hours, limit=12)
    return pd.DataFrame(rows)


# =========================================================
# Charts (Altair if exists else Streamlit fallback)
# =========================================================
def enable_altair_theme() -> None:
    if alt is None:
        return

    def mdma_theme():
        return {
            "config": {
                "background": "transparent",
                "view": {"stroke": "transparent"},
                "axis": {
                    "labelColor": "rgba(255,255,255,0.82)",
                    "titleColor": "rgba(255,255,255,0.82)",
                    "gridColor": "rgba(255,255,255,0.10)",
                    "domainColor": "rgba(255,255,255,0.12)",
                    "tickColor": "rgba(255,255,255,0.12)",
                },
                "legend": {
                    "labelColor": "rgba(255,255,255,0.80)",
                    "titleColor": "rgba(255,255,255,0.80)",
                },
                "title": {"color": "rgba(255,255,255,0.90)"},
            }
        }

    try:
        # اگر قبلاً register شده باشه خطا می‌داد؛ اینجا safe کردیم
        if "mdma_dark" not in alt.themes.names():
            alt.themes.register("mdma_dark", mdma_theme)
        alt.themes.enable("mdma_dark")
    except Exception:
        # اگر theme failed شد، پنل باید همچنان بالا بیاد
        pass


def chart_line(df: pd.DataFrame, title: str) -> None:
    if df is None or df.empty:
        st.info("No data yet.")
        return

    st.caption(title)
    if alt is None:
        try:
            st.line_chart(df.set_index("dt"))
        except Exception:
            st.dataframe(df)
        return

    ch = (
        alt.Chart(df)
        .mark_line()
        .encode(
            x=alt.X("dt:T", title="Time"),
            y=alt.Y("count:Q", title="Count"),
            tooltip=[alt.Tooltip("dt:T", title="Time"), alt.Tooltip("count:Q", title="Count")],
        )
        .interactive()
    )
    st.altair_chart(ch, use_container_width=True)


def chart_bar(df: pd.DataFrame, x: str, y: str, title: str, limit: int = 20) -> None:
    if df is None or df.empty:
        st.info("No data yet.")
        return
    st.caption(title)
    d = df.copy()
    if len(d) > limit:
        d = d.head(limit)

    if alt is None:
        try:
            d2 = d.set_index(x)[y]
            st.bar_chart(d2)
        except Exception:
            st.dataframe(d)
        return

    ch = (
        alt.Chart(d)
        .mark_bar()
        .encode(
            x=alt.X(f"{x}:N", sort="-y", title=x),
            y=alt.Y(f"{y}:Q", title=y),
            tooltip=[alt.Tooltip(f"{x}:N"), alt.Tooltip(f"{y}:Q")],
        )
    )
    st.altair_chart(ch, use_container_width=True)


def chart_stacked(df: pd.DataFrame, x: str, color: str, y: str, title: str, limit: int = 20) -> None:
    if df is None or df.empty:
        st.info("No data yet.")
        return
    st.caption(title)

    # محدودیت برای شلوغ نشدن
    topx = df.groupby(x)[y].sum().sort_values(ascending=False).head(limit).index.tolist()
    d = df[df[x].isin(topx)].copy()

    if alt is None:
        try:
            piv = d.pivot_table(index=x, columns=color, values=y, aggfunc="sum", fill_value=0)
            st.bar_chart(piv)
        except Exception:
            st.dataframe(d)
        return

    ch = (
        alt.Chart(d)
        .mark_bar()
        .encode(
            x=alt.X(f"{x}:N", sort="-y", title=x),
            y=alt.Y(f"sum({y}):Q", title=y),
            color=alt.Color(f"{color}:N", title=color),
            tooltip=[alt.Tooltip(f"{x}:N"), alt.Tooltip(f"{color}:N"), alt.Tooltip(f"{y}:Q")],
        )
    )
    st.altair_chart(ch, use_container_width=True)


# =========================================================
# Analytics builders (from events)
# =========================================================
def source_activity_table(df_events: pd.DataFrame, window_hours: int, sources_hint: List[str]) -> pd.DataFrame:
    if df_events is None or df_events.empty:
        return pd.DataFrame(columns=["source", "rows", "last_seen", "kinds", "ok", "fail"])

    dfw = in_window(df_events, window_hours)
    if dfw is None or dfw.empty or "source" not in dfw.columns:
        return pd.DataFrame(columns=["source", "rows", "last_seen", "kinds", "ok", "fail"])

    dfw["source"] = dfw["source"].astype(str)

    g = dfw.groupby("source", dropna=False)
    rows = g.size().rename("rows").reset_index()

    # last seen
    last_ts = g["ts"].max().rename("last_ts").reset_index()
    rows = rows.merge(last_ts, on="source", how="left")
    rows["last_seen"] = rows["last_ts"].apply(ts_to_str)

    # distinct kinds
    if "kind" in dfw.columns:
        kinds = g["kind"].nunique().rename("kinds").reset_index()
        rows = rows.merge(kinds, on="source", how="left")
    else:
        rows["kinds"] = 0

    # ok/fail counts if status exists
    if "status" in dfw.columns:
        ok = dfw[dfw["status"].astype(str).str.lower() == "ok"].groupby("source").size().rename("ok").reset_index()
        fail = dfw[dfw["status"].astype(str).str.lower() == "fail"].groupby("source").size().rename("fail").reset_index()
        rows = rows.merge(ok, on="source", how="left").merge(fail, on="source", how="left")
        rows["ok"] = rows["ok"].fillna(0).astype(int)
        rows["fail"] = rows["fail"].fillna(0).astype(int)
    else:
        rows["ok"] = 0
        rows["fail"] = 0

    rows = rows.drop(columns=["last_ts"], errors="ignore")
    rows = rows.sort_values("rows", ascending=False)

    # اگر source هایی تو تنظیمات هست ولی تو لاگ نیست، به جدول اضافه کن
    for s in sources_hint or []:
        if s and s not in set(rows["source"].tolist()):
            rows = pd.concat(
                [
                    rows,
                    pd.DataFrame([{"source": s, "rows": 0, "last_seen": "—", "kinds": 0, "ok": 0, "fail": 0}]),
                ],
                ignore_index=True,
            )

    # دوباره sort
    rows = rows.sort_values(["rows", "source"], ascending=[False, True]).reset_index(drop=True)
    return rows


def agg_counts(df_events: pd.DataFrame, window_hours: int, by: List[str]) -> pd.DataFrame:
    if df_events is None or df_events.empty:
        return pd.DataFrame()

    dfw = in_window(df_events, window_hours)
    if dfw is None or dfw.empty:
        return pd.DataFrame()

    for c in by:
        if c not in dfw.columns:
            dfw[c] = "—"

    out = dfw.groupby(by, dropna=False).size().reset_index(name="count")
    out = out.sort_values("count", ascending=False)
    return out


# =========================================================
# Pages
# =========================================================
def page_dashboard(db: DB, db_path: str, window_hours: int, cfg: Dict[str, Any], runtime: Dict[str, Any]) -> None:
    hero("Dashboard", f"نمای کلی بات — پنجره‌ی زمانی: {window_hours} ساعت", "info", "📡 Live")

    k = cached_kpis(db_path, window_hours)

    st.markdown('<div class="kpi-grid">', unsafe_allow_html=True)
    c = st.columns(5)
    with c[0]:
        kpi_card("RX (msgs)", k.get("rx", 0), "پیام‌های ورودی از منابع", "📥")
    with c[1]:
        kpi_card("Posted", k.get("posted", 0), "ارسال‌های موفق به کانال", "📤")
    with c[2]:
        kpi_card("Test OK", k.get("test_ok", 0), "تست‌های موفق", "✅")
    with c[3]:
        kpi_card("Test FAIL", k.get("test_fail", 0), "تست‌های ناموفق", "❌")
    avg_lat = k.get("avg_latency_ms", None)
    with c[4]:
        kpi_card("Avg Latency", f"{avg_lat} ms" if avg_lat is not None else "—", "میانگین latency", "⏱️")
    st.markdown("</div>", unsafe_allow_html=True)

    st.divider()

    tabs = st.tabs(["Timeline", "Channels Snapshot", "Health", "Latest Events"])

    with tabs[0]:
        left, right = st.columns([2, 1], gap="large")

        with left:
            glass_open("glass")
            st.markdown("#### Timeline")

            h = min(168, window_hours * 2)
            chart_line(cached_series(db_path, h, "posted"), "Posted (per hour)")
            chart_line(cached_series(db_path, h, "test"), "Tests (per hour)")

            # اگر DB این kind رو داشته باشه، نشون می‌ده؛ اگر نداشته باشه خالیه و ارور نمی‌ده
            df_proxy_posted = cached_series(db_path, h, "proxy_posted")
            if df_proxy_posted is not None and not df_proxy_posted.empty:
                chart_line(df_proxy_posted, "Proxy posted (per hour)")

            glass_close()

        with right:
            glass_open("glass")
            st.markdown("#### Rankings")

            st.caption("Top Countries (OK tests)")
            tc = cached_top_countries(db_path, window_hours)
            if tc is None or tc.empty:
                st.info("No data yet.")
            else:
                st.dataframe(tc, use_container_width=True, hide_index=True)

            st.caption("Top ASN / Org (OK tests)")
            ta = cached_top_asn(db_path, window_hours)
            if ta is None or ta.empty:
                st.info("No data yet.")
            else:
                st.dataframe(ta, use_container_width=True, hide_index=True)

            glass_close()

    with tabs[1]:
        glass_open("glass")
        st.markdown("#### Channels Snapshot (Sources)")

        merged = merge_settings(cfg, runtime or {})
        sources = merged.get("sources") or []

        df_ev = cached_events(db_path, limit=9000)
        table = source_activity_table(df_ev, window_hours, sources)

        # وضعیت فعال/غیرفعال (اگر last_seen واقعی داریم)
        if not table.empty and "last_seen" in table.columns:
            st.markdown(
                " ".join(
                    [
                        badge("info", f"sources: {len(sources)}"),
                        badge("info", f"active rows: {int(table['rows'].sum()) if 'rows' in table.columns else 0}"),
                    ]
                ),
                unsafe_allow_html=True,
            )

        st.dataframe(table, use_container_width=True, hide_index=True)

        # نمودار تعداد رویدادها بر اساس source
        if not table.empty and "source" in table.columns and "rows" in table.columns:
            chart_bar(table[["source", "rows"]], "source", "rows", "Events per source (top)")

        glass_close()

    with tabs[2]:
        glass_open("glass")
        st.markdown("#### Health")

        health = db.get_health_all() or []
        tg = cfg.get("telegram") or {}
        token_ok = bool(tg.get("bot_token") or cfg.get("bot_token"))
        pp = (merge_settings(cfg, runtime).get("proxy_pipeline") or {})
        st.markdown(
            " ".join(
                [
                    badge("ok" if token_ok else "warn", f"bot_token: {'set' if token_ok else 'missing'}"),
                    badge("info", f"proxy_pipeline: {'on' if pp.get('enabled') else 'off'}"),
                ]
            ),
            unsafe_allow_html=True,
        )

        if not health:
            st.info("No health records yet.")
        else:
            for h in health:
                comp = h.get("component", "unknown")
                status = str(h.get("status", "unknown")).lower()
                ts = h.get("updated_ts", 0)
                kind = "info"
                if status == "ok":
                    kind = "ok"
                elif status in ("warn", "warning", "degraded"):
                    kind = "warn"
                elif status in ("fail", "error", "down"):
                    kind = "bad"

                st.markdown(
                    f"""
<div class="glass-lite" style="margin-top:10px;">
  <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;">
    <div style="font-weight:900;">{html_escape(comp)}</div>
    <div>{badge(kind, status.upper())}</div>
  </div>
  <div style="margin-top:6px;color:rgba(255,255,255,0.72);font-size:12px;">
    last: {html_escape(ts_to_str(ts))}
  </div>
</div>
""",
                    unsafe_allow_html=True,
                )
                meta = h.get("meta") or {}
                if meta:
                    with st.expander(f"meta: {comp}", expanded=False):
                        st.json(meta, expanded=False)

        glass_close()

    with tabs[3]:
        glass_open("glass")
        st.markdown("#### Latest events")
        ev = cached_events(db_path, limit=350)
        if ev is None or ev.empty:
            st.info("No events yet.")
        else:
            cols = ["time", "kind", "status", "proto", "source", "msg_id", "latency_ms", "country_code", "country", "org", "detail"]
            cols = [c for c in cols if c in ev.columns]
            st.dataframe(ev[cols], use_container_width=True, hide_index=True)
        glass_close()


def page_sources_manager(db: DB, cfg: Dict[str, Any]) -> None:
    hero("Sources Manager", "مدیریت ورودی‌ها (sources) + چک کردن فعالیت هر ورودی", "warn", "🧩 Inputs")

    runtime = db.get_settings_dict() or {}
    merged = merge_settings(cfg, runtime)

    glass_open("glass")
    st.markdown("#### Edit sources (runtime)")

    # نمایش وضعیت فعلی
    st.markdown(
        " ".join(
            [
                badge("info", f"current sources: {len(merged.get('sources') or [])}"),
                badge("info", f"target: {merged.get('target_channel') or '—'}"),
            ]
        ),
        unsafe_allow_html=True,
    )

    # ادیت لیست
    current_text = "\n".join([str(x) for x in (merged.get("sources") or [])])
    new_text = st.text_area("Sources (one per line)", value=current_text, height=200)
    new_sources = normalize_sources(new_text.splitlines())

    target = st.text_input("Target channel", value=str(merged.get("target_channel") or ""))

    c1, c2, c3 = st.columns([1, 1, 2])
    with c1:
        save = st.button("Save ✅", use_container_width=True)
    with c2:
        reset = st.button("Load defaults ↩️", use_container_width=True)
    with c3:
        st.caption("این صفحه runtime settings رو تو DB ذخیره می‌کنه (بدون ریستارت).")

    if save:
        merged["sources"] = new_sources
        merged["target_channel"] = target
        db.set_settings_dict(merged)
        st.success("Saved. Bot applies settings live (بدون ریستارت).")
        st.rerun()

    if reset:
        defaults_only = merge_settings(cfg, {})
        db.set_settings_dict(defaults_only)
        st.success("Loaded defaults into runtime settings.")
        st.rerun()

    st.divider()
    st.markdown("#### Activity check")

    window_hours = st.slider("Check window (hours)", 1, 168, 24, key="src_check_window")
    db_path = cfg.get("db_path", "bot.db")
    df_ev = cached_events(db_path, limit=9000)
    table = source_activity_table(df_ev, window_hours, new_sources)

    st.dataframe(table, use_container_width=True, hide_index=True)

    if not table.empty and "source" in table.columns and "rows" in table.columns:
        chart_bar(table[["source", "rows"]], "source", "rows", "Events per source (top)")

    glass_close()


def page_analytics(db_path: str, window_hours: int) -> None:
    hero("Analytics", "آمار چنل‌ها/دیتکتورها/پروتکل‌ها برای دید بهتر", "info", "📊 Stats")

    df_ev = cached_events(db_path, limit=12000)
    if df_ev is None or df_ev.empty:
        glass_open("glass")
        st.info("No events yet.")
        glass_close()
        return

    dfw = in_window(df_ev, window_hours)
    if dfw is None or dfw.empty:
        glass_open("glass")
        st.info("No events in this window.")
        glass_close()
        return

    tabs = st.tabs(["By Source", "By Kind/Status", "By Protocol", "Geo/Org", "Detectors (custom view)"])

    with tabs[0]:
        glass_open("glass")
        st.markdown("#### Events per source / Success rate")

        t = agg_counts(dfw, window_hours=99999, by=["source"])  # dfw already windowed
        if t.empty:
            st.info("No source data.")
        else:
            chart_bar(t, "source", "count", "Events per source")

        if "status" in dfw.columns and "source" in dfw.columns:
            ok = dfw[dfw["status"].astype(str).str.lower() == "ok"].groupby("source").size().rename("ok")
            allc = dfw.groupby("source").size().rename("all")
            rate = pd.concat([ok, allc], axis=1).fillna(0)
            rate["ok_rate"] = (rate["ok"] / rate["all"].replace(0, 1)).round(3)
            rate = rate.reset_index().sort_values("all", ascending=False)

            st.caption("OK rate per source (top)")
            st.dataframe(rate.head(30), use_container_width=True, hide_index=True)

        glass_close()

    with tabs[1]:
        glass_open("glass")
        st.markdown("#### Kinds / Status distribution")

        by_kind = agg_counts(dfw, window_hours=99999, by=["kind"])
        if not by_kind.empty:
            chart_bar(by_kind, "kind", "count", "Events by kind")

        if "kind" in dfw.columns and "status" in dfw.columns:
            ks = agg_counts(dfw, window_hours=99999, by=["kind", "status"])
            if not ks.empty:
                chart_stacked(ks, x="kind", color="status", y="count", title="Kind × Status (stacked)")

        # Timeline per kind (select)
        st.divider()
        st.markdown("#### Timeline by kind")
        kinds = sorted(safe_series(dfw, "kind").dropna().astype(str).unique().tolist())
        kind_pick = st.multiselect("Select kinds", kinds, default=kinds[:2] if len(kinds) >= 2 else kinds)

        if "dt" in dfw.columns and "kind" in dfw.columns and kind_pick:
            d = dfw[dfw["kind"].astype(str).isin(kind_pick)].copy()
            d["hour"] = d["dt"].dt.floor("H")
            ts = d.groupby(["hour", "kind"]).size().reset_index(name="count")

            if alt is None:
                piv = ts.pivot_table(index="hour", columns="kind", values="count", fill_value=0)
                st.line_chart(piv)
            else:
                ch = (
                    alt.Chart(ts)
                    .mark_line()
                    .encode(
                        x=alt.X("hour:T", title="Time"),
                        y=alt.Y("count:Q", title="Count"),
                        color=alt.Color("kind:N", title="kind"),
                        tooltip=[alt.Tooltip("hour:T"), alt.Tooltip("kind:N"), alt.Tooltip("count:Q")],
                    )
                    .interactive()
                )
                st.altair_chart(ch, use_container_width=True)

        glass_close()

    with tabs[2]:
        glass_open("glass")
        st.markdown("#### Protocol analytics")

        if "proto" not in dfw.columns:
            st.info("No proto column in events.")
            glass_close()
        else:
            by_proto = agg_counts(dfw, window_hours=99999, by=["proto"])
            if not by_proto.empty:
                chart_bar(by_proto, "proto", "count", "Events by proto")

            if "status" in dfw.columns:
                ps = agg_counts(dfw, window_hours=99999, by=["proto", "status"])
                if not ps.empty:
                    chart_stacked(ps, x="proto", color="status", y="count", title="Proto × Status (stacked)")

            glass_close()

    with tabs[3]:
        glass_open("glass")
        st.markdown("#### Geo/Org overview")

        if "country_code" in dfw.columns:
            cc = dfw["country_code"].fillna("??").astype(str).value_counts().head(20).reset_index()
            cc.columns = ["country_code", "count"]
            chart_bar(cc, "country_code", "count", "Top country_code (events)")

        if "org" in dfw.columns:
            org = dfw["org"].fillna("Unknown").astype(str).value_counts().head(20).reset_index()
            org.columns = ["org", "count"]
            chart_bar(org, "org", "count", "Top org (events)", limit=20)

        glass_close()

    with tabs[4]:
        glass_open("glass")
        st.markdown("#### Detectors view (creative)")

        # اینجا "detector" رو برابر kind می‌گیریم. اگر در دیتابیس ستون detector/engine داشته باشی،
        # فقط اسم ستون رو اینجا جایگزین کن.
        detector_col = "kind"
        if detector_col not in dfw.columns:
            st.info("No detector column found.")
            glass_close()
        else:
            det = dfw[detector_col].fillna("—").astype(str).value_counts().reset_index()
            det.columns = ["detector", "count"]
            chart_bar(det, "detector", "count", "Detectors (by kind)")

            if "source" in dfw.columns:
                ds = dfw.groupby(["source", detector_col]).size().reset_index(name="count")
                chart_stacked(ds, x="source", color=detector_col, y="count", title="Source × Detector (stacked)", limit=15)

            glass_close()


def page_settings(cfg: Dict[str, Any], db: DB) -> None:
    hero("Settings", "تنظیمات Live — ذخیره در DB و اعمال بدون ریستارت", "warn", "🛠️ Runtime")

    current = db.get_settings_dict() or {}
    merged = merge_settings(cfg, current)
    last_ts = db.get_settings_updated_ts("runtime")

    glass_open("glass")

    if last_ts:
        st.caption(f"Last saved (runtime settings): `{ts_to_str(last_ts)}`")
    else:
        st.caption("Last saved (runtime settings): —")

    tabs = st.tabs(
        [
            "Switches",
            "Testing",
            "Workers/Safety",
            "Gold ⭐",
            "Posting",
            "Channels",
            "Binaries",
            "Caption",
            "Telegram Proxy Pipeline",
            "Adaptive/Net",
            "Raw JSON",
        ]
    )

    with st.form("settings_form"):
        with tabs[0]:
            sw = merged.get("switches", {}) or {}
            c1, c2 = st.columns(2)
            with c1:
                sw["enable_testing"] = st.toggle("Enable Testing", value=bool(sw.get("enable_testing", True)))
                sw["enable_ip_check"] = st.toggle("Enable IP Check (ipify)", value=bool(sw.get("enable_ip_check", True)))
                sw["enable_latency"] = st.toggle("Enable Latency", value=bool(sw.get("enable_latency", True)))
            with c2:
                sw["enable_geoip"] = st.toggle("Enable GeoIP + ASN", value=bool(sw.get("enable_geoip", True)))
                sw["enable_send"] = st.toggle("Enable Send to Target", value=bool(sw.get("enable_send", True)))
                st.caption("خاموش کردن Send یعنی تست انجام می‌شه ولی پست نمی‌ره.")
            merged["switches"] = sw

        with tabs[1]:
            f = merged.get("filters", {}) or {}
            f["good_ms"] = st.slider("Good <= (ms)", 50, 1000, int(f.get("good_ms", 300)))
            f["ok_ms"] = st.slider("OK <= (ms)", 100, 3000, int(f.get("ok_ms", 900)))
            f["test_timeout_sec"] = st.slider("Test timeout (sec)", 2, 30, int(f.get("test_timeout_sec", 8)))
            f["dedupe_window_hours"] = st.slider("Dedupe window (hours)", 0, 168, int(f.get("dedupe_window_hours", 24)))
            f["stability_tries"] = st.slider("Stability tries", 1, 5, int(f.get("stability_tries", 3)))
            f["stability_delay_ms"] = st.slider("Delay between tries (ms)", 0, 2000, int(f.get("stability_delay_ms", 250)))
            merged["filters"] = f

        with tabs[2]:
            f = merged.get("filters", {}) or {}
            f["worker_count"] = st.slider("Workers (parallel tests)", 1, 8, int(f.get("worker_count", 1)))
            f["max_queue"] = st.slider("Max Queue", 100, 20000, int(f.get("max_queue", 1000)))
            f["cb_fail_threshold"] = st.slider("Circuit Breaker fail threshold", 5, 200, int(f.get("cb_fail_threshold", 30)))
            f["cb_cooldown_sec"] = st.slider("Circuit Breaker cool down (sec)", 10, 900, int(f.get("cb_cooldown_sec", 60)))
            merged["filters"] = f
            st.caption("این‌ها Live اعمال می‌شن؛ worker_count فقط concurrency رو کنترل می‌کنه.")

        with tabs[3]:
            f = merged.get("filters", {}) or {}
            f["gold_ping_ms"] = st.slider("Gold ping <= (ms)", 50, 500, int(f.get("gold_ping_ms", 150)))
            f["gold_need_ok"] = st.slider("Gold need ok count", 1, 5, int(f.get("gold_need_ok", 3)))
            merged["filters"] = f

        with tabs[4]:
            merged["rename_text"] = st.text_input("Rename Text (middle)", value=str(merged.get("rename_text", "MDMA")))
            merged["post_interval_sec"] = st.number_input(
                "Post Interval (sec)", min_value=0, max_value=3600, value=int(merged.get("post_interval_sec", 10))
            )

        with tabs[5]:
            st.caption("sources می‌تونه @username یا chat_id عددی (گروه/سوپرگروه) باشه.")
            src_text = "\n".join([str(x) for x in (merged.get("sources") or [])])
            new_src_text = st.text_area("Sources (one per line)", value=src_text, height=120)
            merged["sources"] = normalize_sources([s.strip() for s in new_src_text.splitlines() if s.strip()])
            merged["target_channel"] = st.text_input("Target channel", value=str(merged.get("target_channel", "")))

        with tabs[6]:
            xray = merged.get("xray", {}) or {}
            curl = merged.get("curl", {}) or {}
            xray["binary_path"] = st.text_input("xray binary path", value=str(xray.get("binary_path", "xray")))
            curl["binary_path"] = st.text_input("curl binary path", value=str(curl.get("binary_path", "curl")))
            merged["xray"] = xray
            merged["curl"] = curl

        with tabs[7]:
            cap = merged.get("caption", {}) or {}
            cap["fixed"] = st.text_area("Fixed caption tail", value=str(cap.get("fixed", "\n\n—\n⚠️MDMA")), height=160)
            merged["caption"] = cap

        with tabs[8]:
            st.caption("Pipeline تست و ارسال Telegram Proxy")
            pc = merged.get("proxy_pipeline", {}) or {}
            pc["enabled"] = st.toggle("Enable Telegram Proxy Pipeline", value=bool(pc.get("enabled", False)))

            pc_src = "\n".join([str(x) for x in (pc.get("sources") or [])])
            pc_src2 = st.text_area("Proxy sources (one per line)", value=pc_src, height=120)
            pc["sources"] = normalize_sources([s.strip() for s in pc_src2.splitlines() if s.strip()])

            pc["target_channel"] = st.text_input("Proxy target channel", value=str(pc.get("target_channel", "")))
            pc["test_timeout_sec"] = st.slider("Proxy test timeout (sec)", 2, 20, int(pc.get("test_timeout_sec", 6)))
            pc["good_ms"] = st.slider("Proxy Good <= (ms)", 50, 1500, int(pc.get("good_ms", 250)))
            pc["ok_ms"] = st.slider("Proxy OK <= (ms)", 100, 5000, int(pc.get("ok_ms", 900)))
            pc["dedupe_window_hours"] = st.slider("Proxy dedupe window (hours)", 0, 168, int(pc.get("dedupe_window_hours", 24)))
            pc["post_interval_sec"] = st.number_input(
                "Proxy post interval (sec)",
                min_value=0,
                max_value=3600,
                value=int(pc.get("post_interval_sec", merged.get("post_interval_sec", 10))),
            )
            merged["proxy_pipeline"] = pc

        with tabs[9]:
            st.caption("Adaptive timeout/retry + multi-endpoint IP check + Cloudflare detection")

            ad = merged.get("adaptive_testing", {}) or {}
            ad["enabled"] = st.toggle("Enable adaptive testing", value=bool(ad.get("enabled", True)))
            ad["history_size"] = st.slider("Adaptive history size", 20, 500, int(ad.get("history_size", 120)))
            ad["min_timeout_sec"] = st.slider("Min timeout (sec)", 1, 30, int(ad.get("min_timeout_sec", 4)))
            ad["max_timeout_sec"] = st.slider("Max timeout (sec)", ad["min_timeout_sec"], 60, int(ad.get("max_timeout_sec", 24)))
            ad["min_tries"] = st.slider("Min tries", 1, 5, int(ad.get("min_tries", 1)))
            ad["max_tries"] = st.slider("Max tries", ad["min_tries"], 8, int(ad.get("max_tries", 5)))
            ad["fail_weight"] = float(st.slider("Fail weight", 0.0, 3.0, float(ad.get("fail_weight", 1.4)), 0.1))
            ad["stage_weight"] = float(st.slider("Stage weight", 0.0, 3.0, float(ad.get("stage_weight", 1.0)), 0.1))
            merged["adaptive_testing"] = ad

            ip_ck = merged.get("ip_check", {}) or {}
            ep_text = "\n".join([str(x) for x in (ip_ck.get("endpoints") or [])])
            ep_text2 = st.text_area("IP check endpoints (one per line)", value=ep_text, height=130)
            ip_ck["endpoints"] = normalize_sources([s.strip() for s in ep_text2.splitlines() if s.strip()])
            merged["ip_check"] = ip_ck

            cf = merged.get("cloudflare", {}) or {}
            cf["enabled"] = st.toggle("Enable Cloudflare detection", value=bool(cf.get("enabled", True)))
            merged["cloudflare"] = cf

        with tabs[10]:
            st.json(merged, expanded=False)

        c1, c2, c3 = st.columns([1, 1, 3])
        with c1:
            saved = st.form_submit_button("Save ✅", use_container_width=True)
        with c2:
            export = st.form_submit_button("Export JSON ⬇️", use_container_width=True)
        with c3:
            st.caption("Tip: پنل رو پشت Nginx + HTTPS + BasicAuth بذار برای امنیت بهتر.")

    if saved:
        db.set_settings_dict(merged)
        st.success("Saved. Bot applies settings live (بدون ریستارت).")
        st.rerun()

    if export:
        blob = json.dumps(merged, ensure_ascii=False, indent=2)
        st.download_button("Download settings_runtime.json", data=blob.encode("utf-8"), file_name="settings_runtime.json")

    glass_close()


def page_events(db_path: str, window_hours: int) -> None:
    hero("Events Explorer", "فیلتر/جستجو روی لاگ‌ها — برای دیباگ سریع", "info", "🧾 Logs")

    glass_open("glass")

    df = cached_events(db_path, limit=15000)
    if df is None or df.empty:
        st.info("No events yet.")
        glass_close()
        return

    dfw = in_window(df, window_hours)
    if dfw is None or dfw.empty:
        st.info("No events in this window.")
        glass_close()
        return

    # options
    kinds = sorted(safe_series(dfw, "kind").dropna().astype(str).unique().tolist())
    statuses = sorted(safe_series(dfw, "status").dropna().astype(str).unique().tolist())
    protos = sorted(safe_series(dfw, "proto").dropna().astype(str).unique().tolist())
    sources = sorted(safe_series(dfw, "source").dropna().astype(str).unique().tolist())

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        ksel = st.multiselect("Kind", kinds, default=[])
    with c2:
        ssel = st.multiselect("Status", statuses, default=[])
    with c3:
        psel = st.multiselect("Proto", protos, default=[])
    with c4:
        limit = st.slider("Rows", 50, 5000, 500)

    c5, c6 = st.columns([2, 1])
    with c5:
        q = st.text_input("Search (source/detail)", value="")
    with c6:
        src_pick = st.selectbox("Quick source", ["(all)"] + sources)

    dff = dfw.copy()
    if ksel and "kind" in dff.columns:
        dff = dff[dff["kind"].astype(str).isin(ksel)]
    if ssel and "status" in dff.columns:
        dff = dff[dff["status"].astype(str).isin(ssel)]
    if psel and "proto" in dff.columns:
        dff = dff[dff["proto"].astype(str).isin(psel)]
    if src_pick != "(all)" and "source" in dff.columns:
        dff = dff[dff["source"].astype(str) == src_pick]

    if q.strip():
        qq = q.strip().lower()
        src_s = dff["source"].astype(str) if "source" in dff.columns else ""
        det_s = dff["detail"].astype(str) if "detail" in dff.columns else ""
        combo = (src_s + " " + det_s).str.lower()
        dff = dff[combo.str.contains(qq, na=False)]

    st.markdown(
        " ".join(
            [
                badge("info", f"rows: {len(dff)}"),
                badge("info", f"window: {window_hours}h"),
                badge("info", f"kinds: {dff['kind'].nunique() if 'kind' in dff.columns else 0}"),
            ]
        ),
        unsafe_allow_html=True,
    )

    cols = [
        "time",
        "kind",
        "status",
        "proto",
        "source",
        "msg_id",
        "latency_ms",
        "exit_ip",
        "ip_version",
        "ok_count_v4",
        "ok_count_v6",
        "egress_consistent",
        "handshake_ok",
        "quality_score",
        "quality_grade",
        "country_code",
        "country",
        "org",
        "stage",
        "ok_endpoint",
        "cloudflare_path",
        "fp_network",
        "fp_security",
        "fp_sni",
        "tls_version",
        "ws_stage",
        "grpc_stage",
        "detail",
    ]
    cols = [c for c in cols if c in dff.columns]
    st.dataframe(dff.head(limit)[cols], use_container_width=True, hide_index=True)

    csv = dff[cols].to_csv(index=False).encode("utf-8")
    st.download_button("Download CSV ⬇️", data=csv, file_name="events.csv")

    glass_close()


# =========================================================
# Main
# =========================================================
def main() -> None:
    st.set_page_config(page_title="MDMA Panel", page_icon="🧪", layout="wide")
    _inject_css()
    enable_altair_theme()

    cfg = load_cfg()
    panel_cfg = cfg.get("panel", {}) or {}
    user = panel_cfg.get("username", "admin")
    pwd = panel_cfg.get("password", "admin")

    must_login(user, pwd)

    db_path = cfg.get("db_path", "bot.db")
    db = DB(db_path)
    db.set_health("panel", "ok", {"ts": now_ts()})

    runtime = db.get_settings_dict() or {}
    merged = merge_settings(cfg, runtime)

    # Sidebar
    st.sidebar.title("🧪 MDMA Panel")
    st.sidebar.caption("Glass UI • Live monitoring + Analytics")

    page = st.sidebar.radio("Navigate", ["Dashboard", "Sources Manager", "Analytics", "Settings", "Events"])
    window_hours = st.sidebar.slider("Window (hours)", 1, 168, 24)

    b1, b2 = st.sidebar.columns(2)
    with b1:
        if st.button("Rerun 🔄", use_container_width=True):
            st.rerun()
    with b2:
        if st.button("Logout 🚪", use_container_width=True):
            st.session_state["authed"] = False
            st.rerun()

    tg = cfg.get("telegram") or {}
    token_ok = bool(tg.get("bot_token") or cfg.get("bot_token"))
    st.sidebar.markdown(
        f"""
<div class="glass-lite" style="margin-top:12px;">
  <div style="font-weight:900;">Status</div>
  <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
    {badge("ok" if token_ok else "warn", "bot_token")}
    {badge("info", f"db: {html_escape(db_path)}")}
    {badge("info", f"sources: {len(merged.get('sources') or [])}")}
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    if page == "Dashboard":
        page_dashboard(db, db_path, window_hours, cfg, runtime)
    elif page == "Sources Manager":
        page_sources_manager(db, cfg)
    elif page == "Analytics":
        page_analytics(db_path, window_hours)
    elif page == "Settings":
        page_settings(cfg, db)
    else:
        page_events(db_path, window_hours)


if __name__ == "__main__":
    main()
