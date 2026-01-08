#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
import uuid
import queue
import sqlite3
import threading
import http.client
from urllib.parse import urlparse
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request, Response, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import uvicorn

# =========================
# 配置（环境变量覆盖）
# =========================
# 默认模式为 writer (单机模式选这个即可，既接收请求又写库)
MODE = os.getenv("ANALYTICS_MODE", "writer").strip().lower() 
# 如果是 ingest 模式，数据发往哪里（单机模式忽略）
WRITER_URL = os.getenv("ANALYTICS_WRITER_URL", "http://localhost:8000").strip()

# 数据库路径
DB_FILE = os.getenv("ANALYTICS_DB_FILE", "site_stats.db").strip()

# CORS：生产建议明确到你的静态网站域名
# 例：export ANALYTICS_ALLOWED_ORIGINS="https://www.example.com"
ALLOWED_ORIGINS = [s.strip() for s in os.getenv("ANALYTICS_ALLOWED_ORIGINS", "*").split(",") if s.strip()]

# 是否信任 X-Forwarded-For（如果你用 Nginx 反代，这里必须是 1）
TRUST_PROXY = os.getenv("ANALYTICS_TRUST_PROXY", "1").strip() == "1"

# 请求体限制（防滥用）
MAX_BODY_BYTES = int(os.getenv("ANALYTICS_MAX_BODY_BYTES", "32768"))

# 队列大小：满了就丢弃（保证不拖慢前台）
QUEUE_MAX = int(os.getenv("ANALYTICS_QUEUE_MAX", "20000"))

# writer 批量写（提升吞吐）
BATCH_SIZE = int(os.getenv("ANALYTICS_BATCH_SIZE", "100"))
BATCH_FLUSH_SEC = float(os.getenv("ANALYTICS_BATCH_FLUSH_SEC", "1.0"))

# /stats 面板访问密码 (不设置则为空，生产环境建议设置)
# 例: export ANALYTICS_ADMIN_TOKEN="mysecretpassword"
ADMIN_TOKEN = os.getenv("ANALYTICS_ADMIN_TOKEN", "").strip()

# uvicorn 配置
HOST = os.getenv("ANALYTICS_HOST", "0.0.0.0").strip()
PORT = int(os.getenv("ANALYTICS_PORT", "8000"))
WORKERS = int(os.getenv("ANALYTICS_WORKERS", "1"))  # writer 模式强制=1

# =========================
# App & CORS
# =========================
app = FastAPI(title="K8s-friendly Simple Analytics", version="1.0")

allow_all = (len(ALLOWED_ORIGINS) == 1 and ALLOWED_ORIGINS[0] == "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if allow_all else ALLOWED_ORIGINS,
    allow_credentials=False, 
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# =========================
# UA 轻量解析
# =========================
def parse_ua(ua: str) -> Tuple[str, str, str]:
    u = (ua or "").lower()

    # device
    if "ipad" in u or "tablet" in u:
        device = "tablet"
    elif "mobi" in u or "iphone" in u or "android" in u:
        device = "mobile"
    else:
        device = "desktop"

    # browser
    browser = "other"
    if "edg/" in u:
        browser = "edge"
    elif "chrome/" in u and "edg/" not in u:
        browser = "chrome"
    elif "firefox/" in u:
        browser = "firefox"
    elif "safari/" in u and "chrome/" not in u:
        browser = "safari"

    # os
    os_name = "other"
    if "windows nt" in u:
        os_name = "windows"
    elif "mac os x" in u and "iphone" not in u and "ipad" not in u:
        os_name = "macos"
    elif "android" in u:
        os_name = "android"
    elif "iphone" in u or "ipad" in u:
        os_name = "ios"
    elif "linux" in u:
        os_name = "linux"

    return browser, os_name, device

# =========================
# IP 获取
# =========================
def get_client_ip(request: Request) -> str:
    if TRUST_PROXY:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[0].strip()
    return (request.client.host if request.client else "") or ""

# =========================
# SQLite（writer 模式才用）
# =========================
def _connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    # WAL模式对并发写更友好
    conn.execute("PRAGMA journal_mode=WAL;") 
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    return conn

def init_db() -> None:
    os.makedirs(os.path.dirname(os.path.abspath(DB_FILE)), exist_ok=True)
    conn = _connect_db()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                user_id TEXT NOT NULL,
                site TEXT,
                event TEXT,
                ip_address TEXT,
                user_agent TEXT,
                browser TEXT,
                os TEXT,
                device TEXT,
                url TEXT,
                path TEXT,
                referrer TEXT,
                screen_res TEXT,
                language TEXT,
                tz TEXT,
                payload TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_visits_ts       ON visits(ts);
            CREATE INDEX IF NOT EXISTS idx_visits_user_id ON visits(user_id);
            CREATE INDEX IF NOT EXISTS idx_visits_site    ON visits(site);
            CREATE INDEX IF NOT EXISTS idx_visits_event   ON visits(event);
            """
        )
        conn.commit()
    finally:
        conn.close()

# =========================
# writer：队列 + 单写线程
# =========================
event_q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=QUEUE_MAX)
_writer_thread: Optional[threading.Thread] = None

def enqueue_event(evt: Dict[str, Any]) -> None:
    try:
        event_q.put_nowait(evt)
    except queue.Full:
        pass

def db_writer_loop() -> None:
    """后台单线程写入数据库"""
    conn = _connect_db()
    buffer = []
    last_flush = time.time()

    def flush():
        nonlocal buffer, last_flush
        if not buffer:
            return
        try:
            conn.executemany(
                """
                INSERT INTO visits(
                    ts, user_id, site, event,
                    ip_address, user_agent, browser, os, device,
                    url, path, referrer,
                    screen_res, language, tz,
                    payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                buffer,
            )
            conn.commit()
        except Exception as e:
            print(f"DB Write Error: {e}")
            try:
                conn.rollback()
            except Exception:
                pass
        buffer = []
        last_flush = time.time()

    try:
        while True:
            try:
                item = event_q.get(timeout=0.2)
            except queue.Empty:
                if buffer and (time.time() - last_flush) >= BATCH_FLUSH_SEC:
                    flush()
                continue

            if item is None: 
                break

            buffer.append(item["row"])
            if len(buffer) >= BATCH_SIZE:
                flush()

    finally:
        try:
            if buffer:
                flush()
        except Exception:
            pass
        conn.close()

@app.on_event("startup")
def on_startup():
    global _writer_thread
    if MODE == "writer":
        print(f"Starting in WRITER mode. DB: {DB_FILE}")
        init_db()
        _writer_thread = threading.Thread(target=db_writer_loop, daemon=True)
        _writer_thread.start()
    else:
        print(f"Starting in INGEST mode. Forwarding to: {WRITER_URL}")

# =========================
# ingest：转发到 writer（后台任务）
# =========================
def _forward_to_writer(raw_body: bytes, headers: Dict[str, str]) -> None:
    try:
        u = urlparse(WRITER_URL)
        scheme = (u.scheme or "http").lower()
        host = u.hostname or "localhost"
        port = u.port or (443 if scheme == "https" else 80)
        base_path = u.path.rstrip("/")
        path = base_path + "/api/track"

        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=1.5)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=1.5)

        conn.request("POST", path, body=raw_body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        conn.close()
    except Exception:
        return

# =========================
# 前端脚本：/analytics.js
# =========================
ANALYTICS_JS = r"""
(function () {
  try {
    var dnt = (navigator.doNotTrack === "1" || window.doNotTrack === "1" || navigator.msDoNotTrack === "1");
    var gpc = (typeof navigator.globalPrivacyControl === "boolean" && navigator.globalPrivacyControl === true);
    if (dnt || gpc) return;

    var scriptTag = document.currentScript;
    var site = (scriptTag && scriptTag.dataset && scriptTag.dataset.site) ? scriptTag.dataset.site : "";
    var apiUrl = null;

    if (scriptTag && scriptTag.src) {
      try {
        var o = new URL(scriptTag.src);
        apiUrl = o.origin + "/api/track";
      } catch (e) {}
    }
    if (!apiUrl) apiUrl = location.origin + "/api/track";

    var KEY = "site_uid_v1";

    function uuidv4() {
      if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
      return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0, v = (c === "x") ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
    }

    function getUid() {
      try {
        var v = localStorage.getItem(KEY);
        if (v) return v;
        v = uuidv4();
        localStorage.setItem(KEY, v);
        return v;
      } catch (e) {
        var m = document.cookie.match(new RegExp("(^| )" + KEY + "=([^;]+)"));
        if (m) return decodeURIComponent(m[2]);
        var nv = uuidv4();
        document.cookie = KEY + "=" + encodeURIComponent(nv) + "; path=/; max-age=31536000; samesite=lax";
        return nv;
      }
    }

    function buildPayload(ev) {
      return {
        user_id: getUid(),
        site: site,
        event: ev || "pageview",
        url: location.href,
        path: location.pathname + location.search,
        referrer: document.referrer || "",
        screen_width: (window.screen ? screen.width : null),
        screen_height: (window.screen ? screen.height : null),
        language: (navigator.language || ""),
        tz: (Intl && Intl.DateTimeFormat) ? (Intl.DateTimeFormat().resolvedOptions().timeZone || "") : "",
        ts: Math.floor(Date.now() / 1000)
      };
    }

    function send(ev) {
      var data = buildPayload(ev);
      var json = JSON.stringify(data);
      if (navigator.sendBeacon) {
        try {
          var blob = new Blob([json], { type: "application/json" });
          navigator.sendBeacon(apiUrl, blob);
          return;
        } catch (e) {}
      }
      try {
        fetch(apiUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: json,
          keepalive: true
        }).catch(function(){});
      } catch (e) {}
    }

    send("pageview");

    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "hidden") send("leave");
    });

    (function() {
      var _pushState = history.pushState;
      history.pushState = function() {
        _pushState.apply(this, arguments);
        window.dispatchEvent(new Event("locationchange"));
      };
      var _replaceState = history.replaceState;
      history.replaceState = function() {
        _replaceState.apply(this, arguments);
        window.dispatchEvent(new Event("locationchange"));
      };
      window.addEventListener("popstate", function() {
        window.dispatchEvent(new Event("locationchange"));
      });
    })();

    window.addEventListener("locationchange", function() {
      send("pageview");
    });

  } catch (e) {}
})();
""".strip()

@app.get("/analytics.js")
async def analytics_js():
    return Response(
        content=ANALYTICS_JS,
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "no-cache"},
    )

# =========================
# 采集接口：/api/track
# =========================
@app.post("/api/track")
async def track(request: Request, background_tasks: BackgroundTasks):
    cl = request.headers.get("content-length")
    if cl and int(cl) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")

    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")

    # 如果是 Ingest 模式，只负责转发给 Writer
    if MODE == "ingest":
        fwd_headers = {
            "Content-Type": request.headers.get("content-type", "application/json"),
            "User-Agent": request.headers.get("user-agent", ""),
            "Accept-Language": request.headers.get("accept-language", ""),
        }
        xff = request.headers.get("x-forwarded-for")
        if xff:
            fwd_headers["X-Forwarded-For"] = xff
        else:
            fwd_headers["X-Forwarded-For"] = (request.client.host if request.client else "")

        background_tasks.add_task(_forward_to_writer, raw, fwd_headers)
        return Response(status_code=204)

    # Writer 模式：处理数据并入队
    data: Dict[str, Any] = {}
    if raw:
        try:
            data = json.loads(raw.decode("utf-8", errors="ignore"))
            if not isinstance(data, dict): data = {}
        except Exception:
            data = {}

    user_id = str(data.get("user_id") or "").strip() or str(uuid.uuid4())
    site = str(data.get("site") or "").strip() or None
    event = str(data.get("event") or "pageview").strip()
    url = str(data.get("url") or "").strip() or None
    path = str(data.get("path") or "").strip() or None
    ref = str(data.get("referrer") or data.get("ref") or "").strip() or None
    lang = str(data.get("language") or "").strip() or (request.headers.get("accept-language") or "")
    tz = str(data.get("tz") or "").strip() or None
    ts = int(data.get("ts") or time.time())

    sw = data.get("screen_width")
    sh = data.get("screen_height")
    screen_res = f"{sw}x{sh}" if sw and sh else "Unknown"

    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "") or "Unknown"
    browser, os_name, device = parse_ua(ua)

    payload = dict(data)
    for k in ["user_id", "site", "event", "url", "path", "referrer", "ref", "language", "tz", "ts", "screen_width", "screen_height"]:
        payload.pop(k, None)
    payload_text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    row = (
        ts, user_id, site, event,
        ip, ua, browser, os_name, device,
        url, path, ref,
        screen_res, lang, tz,
        payload_text
    )
    enqueue_event({"row": row})

    return Response(status_code=204)

@app.get("/healthz")
async def healthz():
    return Response(content="ok", media_type="text/plain")

@app.get("/stats", response_class=HTMLResponse)
async def stats(token: str = "", limit: int = 50, days: int = 7):
    if MODE != "writer":
        raise HTTPException(status_code=404, detail="not found (ingest mode)")
    
    # 简单的 Token 验证
    if ADMIN_TOKEN and token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="unauthorized")

    days = max(1, min(days, 365))
    since = int(time.time()) - days * 86400
    limit = max(10, min(limit, 500))

    conn = _connect_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM visits WHERE ts >= ?", (since,))
        pv = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT user_id) FROM visits WHERE ts >= ? AND event='pageview'", (since,))
        uv = cur.fetchone()[0]
        cur.execute(
            """
            SELECT ts, user_id, ip_address, event, url, user_agent, screen_res
            FROM visits WHERE ts >= ?
            ORDER BY id DESC LIMIT ?
            """,
            (since, limit),
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    def fmt_ts(t: int) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))

    table_rows = ""
    for (ts, uid, ip, ev, url, ua, sr) in rows:
        ua_short = (ua[:60] + "...") if ua and len(ua) > 60 else (ua or "")
        url_short = (url[:60] + "...") if url and len(url) > 60 else (url or "")
        table_rows += f"""
        <tr style="border-bottom: 1px solid #eee;">
          <td>{fmt_ts(int(ts))}</td>
          <td><div style="font-family:monospace; color:#3b82f6;">{uid[:8]}...</div></td>
          <td><div style="font-family:monospace;">{ip or "-"}</div></td>
          <td><span style="background:#e0f2fe; color:#0369a1; padding:2px 6px; border-radius:4px; font-size:11px;">{ev}</span></td>
          <td title="{url or ""}"><div style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{url_short}</div></td>
          <td title="{ua or ""}"><div style="max-width:150px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#9ca3af;">{ua_short}</div></td>
          <td style="color:#6b7280;">{sr or "-"}</td>
        </tr>
        """

    html = f"""
    <!doctype html>
    <html lang="zh-CN">
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width,initial-scale=1"/>
      <title>站点访问统计</title>
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background:#f9fafb; margin:0; padding:20px; color: #1f2937; }}
        .card {{ max-width: 1000px; margin:0 auto; background:#fff; border-radius:12px; box-shadow:0 4px 6px -1px rgba(0,0,0,0.1); overflow:hidden; }}
        .header {{ padding:20px; border-bottom:1px solid #e5e7eb; display:flex; justify-content:space-between; align-items:center; background: #fff; }}
        .stats-grid {{ display:grid; grid-template-columns: 1fr 1fr; gap:20px; padding:20px; background: #f3f4f6; }}
        .stat-box {{ background:#fff; border:1px solid #e5e7eb; border-radius:8px; padding:15px; text-align:center; }}
        .stat-label {{ color:#6b7280; font-size:12px; text-transform:uppercase; letter-spacing:1px; margin-bottom: 5px; }}
        .stat-value {{ font-size:28px; font-weight:700; color: #111827; }}
        .table-container {{ overflow-x: auto; }}
        table {{ width:100%; border-collapse:collapse; font-size:13px; }}
        th {{ background:#f9fafb; padding:12px 16px; text-align:left; font-weight:600; color:#4b5563; border-bottom: 1px solid #e5e7eb; }}
        td {{ padding:12px 16px; color:#374151; }}
        tr:hover {{ background-color: #f9fafb; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <h2 style="margin:0; font-size:18px;">📊 访问统计 <span style="font-weight:400; color:#6b7280; font-size:14px;">(最近 {days} 天)</span></h2>
          <span style="background:#dbeafe; color:#1e40af; padding:4px 8px; border-radius:4px; font-size:12px; font-weight:600;">Writer Mode</span>
        </div>
        <div class="stats-grid">
          <div class="stat-box">
            <div class="stat-label">总浏览量 (PV)</div>
            <div class="stat-value" style="color:#2563eb;">{pv}</div>
          </div>
          <div class="stat-box">
            <div class="stat-label">独立访客 (UV)</div>
            <div class="stat-value" style="color:#059669;">{uv}</div>
          </div>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>时间</th><th>用户ID</th><th>IP</th><th>事件</th><th>URL</th><th>设备</th><th>分辨率</th>
              </tr>
            </thead>
            <tbody>{table_rows}</tbody>
          </table>
        </div>
        <div style="padding:15px; text-align:center; color:#9ca3af; font-size:12px; background:#fff; border-top:1px solid #e5e7eb;">
           生成时间: {fmt_ts(int(time.time()))}
        </div>
      </div>
    </body>
    </html>
    """
    return html

if __name__ == "__main__":
    # writer 模式下强制单进程，否则会产生多个写线程竞争锁
    workers = 1 if MODE == "writer" else max(1, WORKERS)
    uvicorn.run(app, host=HOST, port=PORT, workers=workers)
