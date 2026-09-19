"""
cxepy — умный OpenAI-совместимый прокси с ротацией API-ключей.

Возможности:
  • Адаптивный RPM/TPM-шардинг: предотвращает 429 до их появления
  • Управление всеми лимитами (RPM, TPM, requests, tokens) из дашборда
  • Автоотключение мёртвых ключей (quota / auth / hard-limit)
  • Учёт токенов per key с персистентностью в SQLite
  • Playground: чат, файлы, фото, остановка запросов, параметры
  • Real-time обновление дашборда через SSE
  • Логи запросов с фильтрами
  • Премиум-дизайн: графики, прогресс-бары, слои, неоморфизм
  • Честный SSE-стриминг, ретраи, backoff, graceful shutdown

Запуск (локально):
    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8080 --workers 1

На Railway:
    Start Command: uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1 \
                                     --timeout-graceful-shutdown 30
    Volume: mount path /data
    Env: DATA_DIR=/data, ADMIN_PASSWORD=<не changeme>
"""

# --- uvloop должен быть установлен ДО импорта uvicorn/asyncio ---
try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

import asyncio
import base64
import contextlib
import hashlib
import io
import json
import logging
import mimetypes
import os
import secrets
import sqlite3
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import bcrypt
import httpx
from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)

# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cxepy")

# ============================================================
# CONFIG
# ============================================================
DATA_DIR = Path(os.environ.get("DATA_DIR", "."))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "cxepy.db"

SESSION_TTL = 7 * 24 * 3600
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")

LOGIN_WINDOW = 900
LOGIN_MAX = 5

RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}
MAX_KEY_ATTEMPTS = 3

SHUTDOWN_GRACE_SECONDS = 25
STATS_FLUSH_INTERVAL = 30

INJECT_STREAM_USAGE = os.environ.get("INJECT_STREAM_USAGE", "true").lower() in (
    "1", "true", "yes", "on"
)

LOG_BUFFER_SIZE = 500

QUOTA_PATTERNS = (
    b"insufficient_quota",
    b"insufficient balance",
    b"insufficient funds",
    b"insufficient_credit",
    b"quota exceeded",
    b"exceeded your current quota",
    b"no credits",
    b"out of credits",
    b"billing hard limit",
    b"credit balance is too low",
)

MAX_FILE_SIZE = 20 * 1024 * 1024
ALLOWED_IMAGE_TYPES = {
    "image/png", "image/jpeg", "image/gif",
    "image/webp", "image/bmp", "image/svg+xml"
}

# ============================================================
# DB
# ============================================================
SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    base_url TEXT NOT NULL,
    model_id TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS provider_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id INTEGER NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    api_key TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    disabled_reason TEXT,
    tokens_in INTEGER NOT NULL DEFAULT 0,
    tokens_out INTEGER NOT NULL DEFAULT 0,
    rpm_limit INTEGER NOT NULL DEFAULT 0,
    tpm_limit INTEGER NOT NULL DEFAULT 0,
    request_limit INTEGER NOT NULL DEFAULT 0,
    token_limit INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS client_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    provider_id INTEGER NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provider_keys_provider ON provider_keys(provider_id);
CREATE INDEX IF NOT EXISTS idx_client_keys_provider ON client_keys(provider_id);
"""


@contextlib.contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def db_init():
    with conn() as c:
        c.executescript(SCHEMA)
        cols = {row["name"] for row in c.execute("PRAGMA table_info(provider_keys)")}
        migrations = {
            "disabled_reason": "TEXT",
            "tokens_in": "INTEGER NOT NULL DEFAULT 0",
            "tokens_out": "INTEGER NOT NULL DEFAULT 0",
            "rpm_limit": "INTEGER NOT NULL DEFAULT 0",
            "tpm_limit": "INTEGER NOT NULL DEFAULT 0",
            "request_limit": "INTEGER NOT NULL DEFAULT 0",
            "token_limit": "INTEGER NOT NULL DEFAULT 0",
        }
        for col, typ in migrations.items():
            if col not in cols:
                c.execute(f"ALTER TABLE provider_keys ADD COLUMN {col} {typ}")


# ============================================================
# STATE
# ============================================================
@dataclass
class KeyState:
    id: int
    value: str
    in_flight: int = 0
    error_count: int = 0
    cooldown_until: float = 0.0
    total: int = 0
    success: int = 0
    disabled: bool = False
    disabled_reason: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    rpm_window: deque = field(default_factory=deque)
    tpm_window: deque = field(default_factory=deque)
    rpm_limit: int = 0
    tpm_limit: int = 0
    request_limit: int = 0
    token_limit: int = 0


@dataclass
class ProviderState:
    id: int
    name: str
    base_url: str
    model_id: str
    keys: list = field(default_factory=list)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def _prune_windows(self, key: KeyState, now: float):
        cutoff = now - 60.0
        while key.rpm_window and key.rpm_window[0] < cutoff:
            key.rpm_window.popleft()
        while key.tpm_window and key.tpm_window[0][0] < cutoff:
            key.tpm_window.popleft()

    def rpm_usage(self, key: KeyState, now: float) -> float:
        if key.rpm_limit <= 0:
            return 0.0
        self._prune_windows(key, now)
        return len(key.rpm_window) / key.rpm_limit

    def tpm_usage(self, key: KeyState, now: float) -> float:
        if key.tpm_limit <= 0:
            return 0.0
        self._prune_windows(key, now)
        total = sum(t for _, t in key.tpm_window)
        return total / key.tpm_limit

    async def pick(self) -> Optional[KeyState]:
        """Адаптивный RPM/TPM-шардинг с предотвращением 429."""
        async with self._lock:
            now = time.monotonic()
            best, best_score = None, float("inf")
            for k in self.keys:
                if k.disabled or k.cooldown_until > now:
                    continue
                self._prune_windows(k, now)

                rpm_load = (len(k.rpm_window) / k.rpm_limit) if k.rpm_limit > 0 else 0.0
                tpm_load = (
                    (sum(t for _, t in k.tpm_window) / k.tpm_limit)
                    if k.tpm_limit > 0 else 0.0
                )

                rpm_penalty = 0.0
                if rpm_load > 0.8:
                    rpm_penalty = (rpm_load - 0.8) * 1000
                tpm_penalty = 0.0
                if tpm_load > 0.8:
                    tpm_penalty = (tpm_load - 0.8) * 1000

                score = (
                    k.in_flight * 1000
                    + rpm_load * 500
                    + tpm_load * 500
                    + k.error_count * 100
                    + rpm_penalty
                    + tpm_penalty
                )
                if score < best_score:
                    best, best_score = k, score

            if best is None:
                return None

            best.in_flight += 1
            best.rpm_window.append(now)
            return best

    def release(self, key: KeyState, status: int, is_quota: bool = False):
        key.in_flight = max(0, key.in_flight - 1)
        key.total += 1

        if 200 <= status < 300:
            key.error_count = 0
            key.success += 1
        elif is_quota:
            key.error_count += 1
            if not key.disabled:
                key.disabled = True
                key.disabled_reason = "quota"
                log.warning(
                    f"provider={self.name} key={key.id} disabled: quota exhausted"
                )
        elif status in (401, 403):
            key.error_count += 1
            if not key.disabled:
                key.disabled = True
                key.disabled_reason = "auth"
                log.warning(
                    f"provider={self.name} key={key.id} disabled: auth error"
                )
        elif status == 429:
            key.error_count += 1
            key.cooldown_until = time.monotonic() + 30
        elif status >= 500 or status == 0:
            key.error_count += 1
            key.cooldown_until = time.monotonic() + 5

        _dirty_keys.add(key.id)
        _apply_hard_limits(key)


@dataclass
class AppState:
    providers: dict = field(default_factory=dict)
    client_keys: dict = field(default_factory=dict)
    http: Optional[httpx.AsyncClient] = None
    log_buffer: deque = field(default_factory=lambda: deque(maxlen=LOG_BUFFER_SIZE))


_dirty_keys: set = set()
_log_seq: int = 0


def hash_client_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _apply_hard_limits(key: KeyState):
    if key.disabled:
        return
    if key.request_limit and key.total >= key.request_limit:
        key.disabled = True
        key.disabled_reason = "hard_limit"
        log.warning(f"key={key.id} disabled: hard limit (requests)")
    elif key.token_limit and (key.tokens_in + key.tokens_out) >= key.token_limit:
        key.disabled = True
        key.disabled_reason = "hard_limit"
        log.warning(f"key={key.id} disabled: hard limit (tokens)")


def _apply_usage(key: KeyState, usage):
    if not isinstance(usage, dict):
        return
    ti = usage.get("prompt_tokens") or 0
    to = usage.get("completion_tokens") or 0
    if not isinstance(ti, int):
        ti = 0
    if not isinstance(to, int):
        to = 0
    if ti or to:
        key.tokens_in += ti
        key.tokens_out += to
        key.tpm_window.append((time.monotonic(), ti + to))
        _dirty_keys.add(key.id)
        _apply_hard_limits(key)


def load_state(st: AppState):
    """Синхронизировать in-memory состояние с БД (sync, не rebuild)."""
    with conn() as c:
        seen_provider_ids = set()
        for p in c.execute("SELECT * FROM providers"):
            pid = p["id"]
            seen_provider_ids.add(pid)
            base = p["base_url"].rstrip("/")

            ps = st.providers.get(pid)
            if ps is None:
                ps = ProviderState(
                    id=pid, name=p["name"], base_url=base, model_id=p["model_id"]
                )
                st.providers[pid] = ps
            else:
                ps.name = p["name"]
                ps.base_url = base
                ps.model_id = p["model_id"]

            db_keys = {
                k["id"]: (
                    k["api_key"], bool(k["enabled"]), k["disabled_reason"] or "",
                    k["tokens_in"] or 0, k["tokens_out"] or 0,
                    k["rpm_limit"] or 0, k["tpm_limit"] or 0,
                    k["request_limit"] or 0, k["token_limit"] or 0,
                )
                for k in c.execute(
                    "SELECT id, api_key, enabled, disabled_reason, "
                    "tokens_in, tokens_out, rpm_limit, tpm_limit, "
                    "request_limit, token_limit "
                    "FROM provider_keys WHERE provider_id=?",
                    (pid,),
                )
            }
            ps.keys = [k for k in ps.keys if k.id in db_keys]
            existing_ids = {k.id for k in ps.keys}
            for kid, (kval, enabled, reason, ti, to, rl, tl, req_l, tok_l) in db_keys.items():
                if kid in existing_ids:
                    continue
                ks = KeyState(id=kid, value=kval)
                if not enabled:
                    ks.disabled = True
                    ks.disabled_reason = reason
                ks.tokens_in = ti
                ks.tokens_out = to
                ks.rpm_limit = rl
                ks.tpm_limit = tl
                ks.request_limit = req_l
                ks.token_limit = tok_l
                ps.keys.append(ks)

        for stale_id in set(st.providers) - seen_provider_ids:
            del st.providers[stale_id]

        st.client_keys.clear()
        for ck in c.execute("SELECT key_hash, provider_id, enabled FROM client_keys"):
            st.client_keys[ck["key_hash"]] = (
                ck["provider_id"],
                bool(ck["enabled"]),
            )


def total_in_flight(st: AppState) -> int:
    return sum(k.in_flight for p in st.providers.values() for k in p.keys)


def _flush_stats(st: AppState):
    """Записать в БД накопленные метрики по грязным ключам."""
    if not _dirty_keys:
        return
    dirty_snapshot = set(_dirty_keys)
    updates = []
    for p in st.providers.values():
        for k in p.keys:
            if k.id in dirty_snapshot:
                updates.append((
                    0 if k.disabled else 1,
                    k.disabled_reason or None,
                    k.tokens_in,
                    k.tokens_out,
                    k.id,
                ))
    if not updates:
        _dirty_keys.difference_update(dirty_snapshot)
        return
    try:
        with conn() as c:
            c.executemany(
                "UPDATE provider_keys SET enabled=?, disabled_reason=?, "
                "tokens_in=?, tokens_out=? WHERE id=?",
                updates,
            )
        _dirty_keys.difference_update(dirty_snapshot)
    except Exception as e:
        log.error(f"stats flush failed: {e}")


async def _stats_flusher(st: AppState):
    try:
        while True:
            await asyncio.sleep(STATS_FLUSH_INTERVAL)
            _flush_stats(st)
    except asyncio.CancelledError:
        raise


def push_log(st: AppState, entry: dict):
    global _log_seq
    _log_seq += 1
    entry["seq"] = _log_seq
    entry["ts"] = time.time()
    st.log_buffer.append(entry)


# ============================================================
# AUTH
# ============================================================
def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def verify_password(p: str, h: str) -> bool:
    return bcrypt.checkpw(p.encode(), h.encode())


def create_session(admin_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with conn() as c:
        c.execute(
            "INSERT INTO sessions (token, admin_id, expires_at) VALUES (?,?,?)",
            (token, admin_id, time.time() + SESSION_TTL),
        )
    return token


def get_admin_id(request: Request) -> Optional[int]:
    token = request.cookies.get("session")
    if not token:
        return None
    with conn() as c:
        row = c.execute(
            "SELECT admin_id, expires_at FROM sessions WHERE token=?", (token,)
        ).fetchone()
    if not row or row["expires_at"] < time.time():
        return None
    return row["admin_id"]


def require_admin(request: Request):
    if get_admin_id(request) is None:
        raise HTTPException(303, headers={"Location": "/admin/login"})


def generate_client_key() -> str:
    a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "cxepy-" + "".join(secrets.choice(a) for _ in range(32))


_login_attempts: dict = {}


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _login_prune(ip: str, now: float) -> list:
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < LOGIN_WINDOW]
    _login_attempts[ip] = attempts
    return attempts


def login_rate_check(ip: str):
    now = time.time()
    if len(_login_attempts) > 1024:
        for k in list(_login_attempts.keys()):
            _login_prune(k, now)
            if not _login_attempts[k]:
                del _login_attempts[k]
    attempts = _login_prune(ip, now)
    if len(attempts) >= LOGIN_MAX:
        raise HTTPException(429, "too many login attempts, try again later")


def login_rate_fail(ip: str):
    _login_attempts.setdefault(ip, []).append(time.time())


def login_rate_clear(ip: str):
    _login_attempts.pop(ip, None)


# ============================================================
# UPSTREAM HELPERS
# ============================================================
def _is_quota_error(status: int, body: bytes) -> bool:
    if status == 402:
        return True
    if status in (403, 429) and body:
        bl = body.lower()
        for pat in QUOTA_PATTERNS:
            if pat in bl:
                return True
    return False


def _extract_usage_from_json(body: bytes) -> Optional[dict]:
    try:
        data = json.loads(body)
    except Exception:
        return None
    u = data.get("usage") if isinstance(data, dict) else None
    return u if isinstance(u, dict) else None


def _extract_usage_from_sse_tail(tail: bytes) -> Optional[dict]:
    for line in reversed(tail.split(b"\n")):
        line = line.strip()
        if not line.startswith(b"data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == b"[DONE]":
            continue
        if b'"usage"' not in payload:
            continue
        try:
            data = json.loads(payload)
        except Exception:
            continue
        if isinstance(data, dict):
            u = data.get("usage")
            if isinstance(u, dict):
                return u
    return None


def extract_text_from_file(content: bytes, mime: str, filename: str) -> str:
    if mime == "application/pdf" or filename.endswith(".pdf"):
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(content))
            return "\n".join(
                (page.extract_text() or "") for page in reader.pages
            )
        except Exception as e:
            return f"[не удалось прочитать PDF: {e}]"
    if mime.startswith("text/") or filename.endswith((".txt", ".md", ".csv", ".json")):
        return content.decode("utf-8", errors="replace")
    return f"[файл {filename}, {mime}, {len(content)} байт]"


# ============================================================
# STYLES
# ============================================================
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#06060a; --bg-1:#0a0a12; --bg-2:#10101a;
  --surface:rgba(255,255,255,.03); --surface-hi:rgba(255,255,255,.055);
  --surface-elev:rgba(20,20,30,.85);
  --border:rgba(255,255,255,.07); --border-hi:rgba(255,255,255,.14);
  --text:#f0f0f6; --text-dim:#9a9aae; --text-mute:#5e5e72;
  --violet:#a855f7; --violet-2:#8b5cf6; --indigo:#6366f1;
  --cyan:#22d3ee; --pink:#ec4899; --green:#34d399;
  --red:#f87171; --amber:#fbbf24;
  --radius:16px; --radius-sm:11px; --radius-lg:22px;
  --shadow-sm:0 2px 8px -2px rgba(0,0,0,.5);
  --shadow-md:0 8px 28px -10px rgba(0,0,0,.65);
  --shadow-lg:0 24px 70px -20px rgba(0,0,0,.75);
  --glow-violet:0 0 30px -6px rgba(168,85,247,.55);
}
html,body{background:var(--bg);color:var(--text);min-height:100vh;
  font-family:'Inter',-apple-system,BlinkMacSystemFont,system-ui,sans-serif;
  font-feature-settings:'cv11','ss01','ss03','tnum';
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;
  letter-spacing:-.011em;line-height:1.5}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(ellipse 65% 50% at 12% -8%, rgba(168,85,247,.28), transparent 58%),
    radial-gradient(ellipse 50% 42% at 92% 8%, rgba(34,211,238,.13), transparent 58%),
    radial-gradient(ellipse 85% 65% at 50% 108%, rgba(99,102,241,.14), transparent 58%),
    radial-gradient(ellipse 40% 30% at 70% 60%, rgba(236,72,153,.06), transparent 60%)}
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;opacity:.32;
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='140' height='140'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 .04 0'/></filter><rect width='100%' height='100%' filter='url(%23n)'/></svg>")}
a{color:inherit;text-decoration:none}
.container{position:relative;z-index:1;max-width:1240px;margin:0 auto;padding:0 32px}
.container-narrow{max-width:960px}
.container-fluid{max-width:100%;padding:0 22px}

.nav{position:relative;z-index:5;display:flex;align-items:center;
  justify-content:space-between;padding:20px 0 18px;
  border-bottom:1px solid var(--border);margin-bottom:34px}
.brand{display:flex;align-items:center;gap:12px;font-weight:600;
  font-size:17px;letter-spacing:-.025em}
.brand .mark{width:30px;height:30px;border-radius:9px;position:relative;
  background:linear-gradient(135deg,var(--violet),var(--cyan));
  box-shadow:var(--glow-violet),inset 0 1px 0 rgba(255,255,255,.4)}
.brand .mark::after{content:'';position:absolute;inset:5px;border-radius:5px;
  background:linear-gradient(135deg,rgba(255,255,255,.6),transparent 70%)}
.brand .dot{color:var(--text-mute);font-weight:400}
.nav-actions{display:flex;gap:6px;align-items:center}
.nav-link{color:var(--text-dim);font-size:13.5px;font-weight:500;
  padding:9px 15px;border-radius:10px;transition:all .18s ease;
  border:1px solid transparent;position:relative}
.nav-link:hover{color:var(--text);background:var(--surface);
  border-color:var(--border)}
.nav-link.active{color:var(--text);background:var(--surface-hi);
  border-color:var(--border-hi)}

.hero{margin-bottom:30px;display:flex;align-items:flex-end;
  justify-content:space-between;flex-wrap:wrap;gap:16px}
.hero h1{font-size:36px;font-weight:600;letter-spacing:-.035em;
  line-height:1.12;
  background:linear-gradient(160deg,#fff 0%,#b0b0c4 60%,#8080a0 100%);
  -webkit-background-clip:text;background-clip:text;color:transparent}
.hero p{color:var(--text-dim);font-size:14.5px;margin-top:6px}
.hero .pulse{display:inline-flex;align-items:center;gap:7px;
  padding:7px 13px;background:var(--surface);border:1px solid var(--border);
  border-radius:999px;font-size:12.5px;color:var(--text-dim)}
.hero .pulse .led{width:7px;height:7px;border-radius:50%;
  background:var(--green);box-shadow:0 0 10px var(--green);
  animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;
  margin:28px 0 38px}
.stat{position:relative;padding:22px 22px 20px;border-radius:var(--radius);
  background:var(--surface);border:1px solid var(--border);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  overflow:hidden;transition:border-color .22s ease, transform .22s ease,
    box-shadow .22s ease;cursor:default}
.stat:hover{border-color:var(--border-hi);transform:translateY(-2px);
  box-shadow:var(--shadow-md)}
.stat::before{content:'';position:absolute;top:0;left:22px;right:22px;
  height:1px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.16),transparent)}
.stat .label{color:var(--text-mute);font-size:11.5px;text-transform:uppercase;
  letter-spacing:.1em;font-weight:500;margin-bottom:12px;
  display:flex;align-items:center;gap:7px}
.stat .label .ico{width:14px;height:14px;opacity:.7}
.stat .value{font-size:30px;font-weight:600;letter-spacing:-.03em;
  font-variant-numeric:tabular-nums;
  font-family:'JetBrains Mono',ui-monospace,monospace}
.stat .value .sub{color:var(--text-mute);font-size:16px;font-weight:500;
  margin-left:3px}
.stat .delta{margin-top:8px;font-size:11.5px;color:var(--text-mute);
  font-family:'JetBrains Mono',monospace}
.stat .delta .up{color:var(--green)}
.stat .delta .down{color:var(--red)}
.stat .glow{position:absolute;bottom:-50px;right:-50px;width:150px;
  height:150px;border-radius:50%;filter:blur(45px);opacity:.4;
  pointer-events:none;transition:opacity .3s ease}
.stat:hover .glow{opacity:.6}
.stat.violet .glow{background:var(--violet)}
.stat.cyan .glow{background:var(--cyan)}
.stat.green .glow{background:var(--green)}
.stat.amber .glow{background:var(--amber)}
.stat.pink .glow{background:var(--pink)}

.section{margin:38px 0}
.section-title{display:flex;align-items:baseline;
  justify-content:space-between;margin-bottom:16px;gap:14px}
.section-title h2{font-size:17px;font-weight:600;letter-spacing:-.015em}
.section-title .count{color:var(--text-mute);font-size:12.5px;
  font-family:'JetBrains Mono',monospace}

.card{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:24px 24px 22px;
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  position:relative;overflow:hidden;transition:border-color .22s ease}
.card:hover{border-color:var(--border-hi)}
.card::before{content:'';position:absolute;top:0;left:24px;right:24px;
  height:1px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.14),transparent)}

.field{margin-bottom:15px}
.field label{display:block;font-size:12px;color:var(--text-dim);
  font-weight:500;margin-bottom:7px;letter-spacing:.01em}
.field input,.field textarea,.field select{
  width:100%;background:rgba(0,0,0,.4);color:var(--text);
  border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:12px 14px;font:inherit;font-size:14px;
  transition:all .16s ease;outline:none}
.field input::placeholder,.field textarea::placeholder{color:var(--text-mute)}
.field input:focus,.field textarea:focus,.field select:focus{
  border-color:rgba(168,85,247,.6);background:rgba(0,0,0,.55);
  box-shadow:0 0 0 3px rgba(168,85,247,.16)}
.field textarea{min-height:100px;resize:vertical;
  font-family:'JetBrains Mono',ui-monospace,monospace;
  font-size:12.5px;line-height:1.7}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:13px}
.grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}

button,.btn{font:inherit;font-size:13.5px;font-weight:500;border:none;
  cursor:pointer;padding:11px 17px;border-radius:var(--radius-sm);
  transition:all .16s ease;letter-spacing:-.005em;
  display:inline-flex;align-items:center;gap:7px;
  font-family:inherit}
.btn-primary{color:#fff;
  background:linear-gradient(135deg,var(--violet),var(--indigo));
  box-shadow:inset 0 1px 0 rgba(255,255,255,.2),
    0 8px 24px -8px rgba(168,85,247,.75)}
.btn-primary:hover{transform:translateY(-1px);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.2),
    0 12px 32px -8px rgba(168,85,247,.9)}
.btn-primary:active{transform:translateY(0)}
.btn-ghost{color:var(--text-dim);background:var(--surface-hi);
  border:1px solid var(--border)}
.btn-ghost:hover{color:var(--text);border-color:var(--border-hi);
  background:rgba(255,255,255,.08)}
.btn-icon{color:var(--text-mute);background:transparent;padding:8px 10px;
  border-radius:9px;border:1px solid transparent;
  transition:all .16s ease}
.btn-icon:hover{color:var(--red);background:rgba(248,113,113,.1);
  border-color:rgba(248,113,113,.25)}
.btn-icon.neutral:hover{color:var(--text);background:var(--surface-hi);
  border-color:var(--border)}
.btn-sm{padding:7px 12px;font-size:12.5px}

.tbl-wrap{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);overflow:hidden;
  backdrop-filter:blur(14px)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:15px 18px;font-size:13.5px;
  border-bottom:1px solid var(--border);vertical-align:middle}
th{font-weight:500;color:var(--text-mute);font-size:11px;
  text-transform:uppercase;letter-spacing:.1em;
  background:rgba(255,255,255,.018)}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.016)}
td.num{font-variant-numeric:tabular-nums;
  font-family:'JetBrains Mono',monospace}

.mono{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12.5px}
.chip{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;
  border-radius:999px;font-size:11.5px;font-weight:500;
  letter-spacing:.005em;font-family:'JetBrains Mono',monospace}
.chip.violet{color:#d8b4fe;background:rgba(168,85,247,.15);
  border:1px solid rgba(168,85,247,.3)}
.chip.dim{color:var(--text-dim);background:var(--surface-hi);
  border:1px solid var(--border)}
.chip.green{color:#86efac;background:rgba(52,211,153,.13);
  border:1px solid rgba(52,211,153,.26)}
.chip.amber{color:#fcd34d;background:rgba(251,191,36,.13);
  border:1px solid rgba(251,191,36,.26)}
.chip.red{color:#fca5a5;background:rgba(248,113,113,.13);
  border:1px solid rgba(248,113,113,.26)}
.chip.cyan{color:#67e8f9;background:rgba(34,211,238,.13);
  border:1px solid rgba(34,211,238,.26)}
.dot-led{width:7px;height:7px;border-radius:50%;display:inline-block}
.dot-led.green{background:var(--green);box-shadow:0 0 9px var(--green)}
.dot-led.amber{background:var(--amber);box-shadow:0 0 9px var(--amber)}
.dot-led.red{background:var(--red);box-shadow:0 0 9px var(--red)}
.dot-led.cyan{background:var(--cyan);box-shadow:0 0 9px var(--cyan)}

.muted{color:var(--text-mute);font-size:12.5px}
.provider-name{font-weight:500;color:var(--text);font-size:14px}
.provider-url{color:var(--text-mute);font-size:11.5px;margin-top:3px;
  font-family:'JetBrains Mono',monospace}

.pbar{position:relative;height:6px;border-radius:3px;
  background:rgba(255,255,255,.06);overflow:hidden;margin-top:6px}
.pbar .fill{height:100%;border-radius:3px;
  background:linear-gradient(90deg,var(--violet),var(--cyan));
  transition:width .5s ease, background .5s ease}
.pbar.warn .fill{background:linear-gradient(90deg,var(--amber),var(--red))}
.pbar.crit .fill{background:linear-gradient(90deg,var(--red),#b91c1c)}
.pbar .text{position:absolute;right:0;top:-20px;font-size:10.5px;
  color:var(--text-mute);font-family:'JetBrains Mono',monospace}

.flash{display:flex;gap:14px;align-items:flex-start;padding:18px 20px;
  border-radius:var(--radius);margin-bottom:24px;
  background:linear-gradient(135deg,rgba(168,85,247,.16),rgba(34,211,238,.08));
  border:1px solid rgba(168,85,247,.32);position:relative;
  overflow:hidden;animation:slideIn .4s cubic-bezier(.2,.9,.25,1)}
@keyframes slideIn{from{opacity:0;transform:translateY(-8px)}
  to{opacity:1;transform:translateY(0)}}
.flash .icon{width:38px;height:38px;border-radius:11px;flex-shrink:0;
  display:grid;place-items:center;
  background:linear-gradient(135deg,var(--violet),var(--cyan));
  box-shadow:0 0 24px rgba(168,85,247,.6)}
.flash .body{flex:1;min-width:0}
.flash .title{font-weight:600;font-size:14px;margin-bottom:8px}
.flash .key{font-family:'JetBrains Mono',monospace;font-size:13px;
  background:rgba(0,0,0,.5);padding:11px 13px;border-radius:9px;
  border:1px solid var(--border);user-select:all;word-break:break-all;
  color:#d8b4fe}
.flash .copy{margin-top:10px}

.err-box{padding:15px 17px;border-radius:var(--radius-sm);
  margin-bottom:20px;background:rgba(248,113,113,.1);
  border:1px solid rgba(248,113,113,.3);color:#fca5a5;font-size:13.5px}

.empty{padding:50px 26px;text-align:center;color:var(--text-mute);
  font-size:13.5px}
.empty .icon{font-size:30px;margin-bottom:12px;opacity:.4}

.login-wrap{position:relative;z-index:1;min-height:100vh;
  display:grid;place-items:center;padding:24px}
.login-card{width:100%;max-width:420px;padding:40px 34px 32px;
  border-radius:24px;background:rgba(14,14,22,.8);
  border:1px solid var(--border-hi);
  backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px);
  box-shadow:var(--shadow-lg),0 0 0 1px rgba(255,255,255,.04) inset;
  animation:pop .55s cubic-bezier(.2,.9,.25,1)}
@keyframes pop{from{opacity:0;transform:translateY(14px) scale(.97)}
  to{opacity:1;transform:none}}
.login-card .logo-row{display:flex;align-items:center;gap:12px;
  margin-bottom:24px}
.login-card h1{font-size:24px;font-weight:600;letter-spacing:-.025em;
  background:linear-gradient(180deg,#fff,#b8b8cc);
  -webkit-background-clip:text;background-clip:text;color:transparent}
.login-card p.sub{color:var(--text-dim);font-size:13.5px;
  margin:-16px 0 26px}

.footer{margin:60px 0 34px;padding-top:24px;
  border-top:1px solid var(--border);color:var(--text-mute);
  font-size:12.5px;display:flex;justify-content:space-between;
  align-items:center;flex-wrap:wrap;gap:12px}
.footer code{font-family:'JetBrains Mono',monospace;
  background:var(--surface-hi);padding:4px 9px;border-radius:7px;
  border:1px solid var(--border);font-size:11.5px;color:var(--text-dim)}

.playground{position:relative;z-index:1;max-width:960px;margin:0 auto;
  padding:0 32px}
.chat-window{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:24px;min-height:460px;
  max-height:62vh;overflow-y:auto;margin-bottom:18px;
  scroll-behavior:smooth}
.chat-window::-webkit-scrollbar{width:8px}
.chat-window::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);
  border-radius:4px}
.msg{margin-bottom:18px;animation:slideIn .28s ease}
.msg .role{font-size:10.5px;text-transform:uppercase;
  letter-spacing:.1em;color:var(--text-mute);margin-bottom:6px}
.msg.user .content{background:rgba(168,85,247,.14);padding:12px 16px;
  border-radius:14px;display:inline-block;max-width:80%;
  border:1px solid rgba(168,85,247,.22)}
.msg.assistant .content{background:rgba(0,0,0,.35);padding:12px 16px;
  border-radius:14px;white-space:pre-wrap;max-width:90%;
  border:1px solid var(--border)}
.input-area{position:sticky;bottom:22px;z-index:3}
.input-row{display:flex;gap:9px;align-items:flex-end;
  background:var(--surface-elev);border:1px solid var(--border);
  border-radius:var(--radius);padding:12px;
  backdrop-filter:blur(18px);
  box-shadow:var(--shadow-md)}
.input-row textarea{flex:1;min-height:64px;max-height:200px;resize:none;
  background:transparent;color:var(--text);border:none;
  padding:8px 10px;font:inherit;font-size:14px;outline:none;
  font-family:inherit}
.attachments{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;
  padding:0 12px}
.toolbar{display:flex;gap:6px;align-items:center;margin-bottom:10px;
  flex-wrap:wrap;padding:0 4px}
.model-select{background:rgba(0,0,0,.4);color:var(--text);
  border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:8px 12px;font:inherit;font-size:13px;outline:none;
  font-family:'JetBrains Mono',monospace}
.stream-toggle{font-size:12.5px;color:var(--text-dim);display:flex;
  align-items:center;gap:6px;padding:8px 12px;
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius-sm)}
.params-panel{display:flex;gap:22px;flex-wrap:wrap;padding:16px 20px;
  margin-top:12px;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);backdrop-filter:blur(14px)}
.params-panel label{display:flex;align-items:center;gap:9px;
  font-size:13px;color:var(--text-dim)}
.params-panel input[type=range]{width:130px;accent-color:var(--violet)}
.params-panel input[type=number]{width:90px;background:rgba(0,0,0,.4);
  border:1px solid var(--border);border-radius:8px;padding:6px 10px;
  color:var(--text);font:inherit;font-size:13px;outline:none}
.cursor{display:inline-block;width:8px;height:16px;
  background:var(--violet);animation:blink .85s infinite;
  vertical-align:middle;border-radius:2px}
@keyframes blink{50%{opacity:0}}

.kv-row{display:flex;align-items:center;gap:10px;
  padding:14px 16px;border-bottom:1px solid var(--border);
  transition:background .15s ease}
.kv-row:last-child{border-bottom:none}
.kv-row:hover{background:rgba(255,255,255,.016)}
.kv-row .kv-id{font-family:'JetBrains Mono',monospace;font-size:12px;
  color:var(--text-mute);min-width:36px}
.kv-row .kv-key{font-family:'JetBrains Mono',monospace;font-size:12.5px;
  color:#d8b4fe;flex:1;min-width:0;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.kv-row .kv-limits{display:flex;gap:8px;flex-wrap:wrap}
.limit-input{width:90px;background:rgba(0,0,0,.4);color:var(--text);
  border:1px solid var(--border);border-radius:8px;
  padding:7px 10px;font:inherit;font-size:12.5px;outline:none;
  font-family:'JetBrains Mono',monospace}
.limit-input:focus{border-color:rgba(168,85,247,.6)}
.kv-row .kv-stats{font-family:'JetBrains Mono',monospace;
  font-size:11.5px;color:var(--text-mute);min-width:130px}

.log-tbl td{font-family:'JetBrains Mono',monospace;font-size:12px;
  padding:11px 14px}
.log-status{font-weight:600}
.log-status.ok{color:var(--green)}
.log-status.retry{color:var(--amber)}
.log-status.err{color:var(--red)}

@media (max-width:900px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .grid-3{grid-template-columns:1fr}
  .grid-4{grid-template-columns:1fr 1fr}
  .hero h1{font-size:28px}
  .container{padding:0 20px}
  th:nth-child(4),td:nth-child(4),
  th:nth-child(6),td:nth-child(6){display:none}
}
"""


# ============================================================
# TEMPLATES
# ============================================================
def page(title: str, body: str, container_class: str = "container") -> str:
    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>{title} · cxepy</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{CSS}</style>
</head>
<body>
<div class="{container_class}">
{body}
</div>
</body>
</html>"""


BRAND_MARK = '<span class="mark"></span>'


def nav_bar(active: str = "") -> str:
    def cls(name):
        return "nav-link active" if active == name else "nav-link"
    return f"""
<div class="nav">
  <a href="/admin/" class="brand">{BRAND_MARK}<span>cxepy<span class="dot">/</span>admin</span></a>
  <div class="nav-actions">
    <a class="{cls('dashboard')}" href="/admin/">Дашборд</a>
    <a class="{cls('playground')}" href="/playground">Playground</a>
    <a class="{cls('logs')}" href="/admin/logs">Логи</a>
    <a class="nav-link" href="/admin/logout">Выйти</a>
  </div>
</div>"""


def login_page(err: str = "") -> str:
    error_html = f'<div class="err-box">{err}</div>' if err else ""
    body = f"""
<div class="login-wrap">
  <div class="login-card">
    <div class="logo-row">{BRAND_MARK}<h1>cxepy</h1></div>
    <p class="sub">Умный прокси с ротацией ключей</p>
    {error_html}
    <form method="post" action="/admin/login">
      <div class="field">
        <label>Логин</label>
        <input name="username" autocomplete="username" required autofocus>
      </div>
      <div class="field">
        <label>Пароль</label>
        <input name="password" type="password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn-primary" style="width:100%;justify-content:center;padding:13px">
        Войти в дашборд
      </button>
    </form>
  </div>
</div>"""
    return page("Вход", body, container_class="")


def _key_status_chip(p: ProviderState) -> str:
    total = len(p.keys)
    active = sum(1 for k in p.keys if not k.disabled)
    if total == 0 or active == 0:
        return '<span class="chip red"><span class="dot-led red"></span>мёртв</span>'
    now = time.monotonic()
    cooling = sum(1 for k in p.keys if not k.disabled and k.cooldown_until > now)
    if cooling == active:
        return '<span class="chip amber"><span class="dot-led amber"></span>cooldown</span>'
    if cooling > 0 or active < total:
        return '<span class="chip amber"><span class="dot-led amber"></span>частично</span>'
    return '<span class="chip green"><span class="dot-led green"></span>готов</span>'


def _provider_rpm_stats(p: ProviderState) -> tuple:
    now = time.monotonic()
    total_rpm_now = 0
    total_rpm_max = 0
    total_tpm_now = 0
    total_tpm_max = 0
    for k in p.keys:
        if k.disabled:
            continue
        p._prune_windows(k, now)
        total_rpm_now += len(k.rpm_window)
        total_rpm_max += k.rpm_limit or 0
        total_tpm_now += sum(t for _, t in k.tpm_window)
        total_tpm_max += k.tpm_limit or 0
    return total_rpm_now, total_rpm_max, total_tpm_now, total_tpm_max


def dashboard_page(st: AppState, new_key: str = "") -> str:
    total_providers = len(st.providers)
    total_keys = sum(len(p.keys) for p in st.providers.values())
    active_keys = sum(
        1 for p in st.providers.values() for k in p.keys if not k.disabled
    )
    inflight = sum(k.in_flight for p in st.providers.values() for k in p.keys)
    total_reqs = sum(k.total for p in st.providers.values() for k in p.keys)
    ok_reqs = sum(k.success for p in st.providers.values() for k in p.keys)
    rate = (ok_reqs / total_reqs * 100) if total_reqs else 100.0

    stats_html = f"""
<div class="stats">
  <div class="stat violet">
    <div class="label">
      <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7l9-4 9 4v10l-9 4-9-4z"/></svg>
      Провайдеры
    </div>
    <div class="value">{total_providers}</div>
    <div class="delta">{total_keys} ключей всего</div>
    <div class="glow"></div>
  </div>
  <div class="stat cyan">
    <div class="label">
      <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v10M7 12h10"/></svg>
      Ключи
    </div>
    <div class="value">{active_keys}<span class="sub">/ {total_keys}</span></div>
    <div class="delta"><span class="up">{active_keys} активных</span> · <span class="down">{total_keys-active_keys} off</span></div>
    <div class="glow"></div>
  </div>
  <div class="stat amber">
    <div class="label">
      <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M2 12h20"/></svg>
      В работе
    </div>
    <div class="value">{inflight}</div>
    <div class="delta">{total_reqs} запросов всего</div>
    <div class="glow"></div>
  </div>
  <div class="stat green">
    <div class="label">
      <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>
      Успешность
    </div>
    <div class="value">{rate:.1f}<span class="sub">%</span></div>
    <div class="delta">{ok_reqs} ok / {total_reqs-ok_reqs} err</div>
    <div class="glow"></div>
  </div>
</div>"""

    rows = []
    for p in st.providers.values():
        active = sum(1 for k in p.keys if not k.disabled)
        disabled_n = sum(1 for k in p.keys if k.disabled)
        inflight_p = sum(k.in_flight for k in p.keys)
        total_p = sum(k.total for k in p.keys)
        succ_p = sum(k.success for k in p.keys)
        rate_p = (succ_p / total_p * 100) if total_p else 100.0
        ti = sum(k.tokens_in for k in p.keys)
        to = sum(k.tokens_out for k in p.keys)

        rpm_now, rpm_max, tpm_now, tpm_max = _provider_rpm_stats(p)
        rpm_pct = (rpm_now / rpm_max * 100) if rpm_max else 0

        rpm_cls = "pbar"
        if rpm_pct > 90:
            rpm_cls += " crit"
        elif rpm_pct > 70:
            rpm_cls += " warn"

        rpm_bar = ""
        if rpm_max:
            rpm_bar = f"""
            <div class="{rpm_cls}">
              <div class="fill" style="width:{min(rpm_pct,100):.0f}%"></div>
            </div>
            <div class="muted" style="margin-top:4px;font-family:'JetBrains Mono',monospace;font-size:10.5px">
              RPM {rpm_now}/{rpm_max}
            </div>"""

        disabled_note = (
            f' <span class="chip red" style="font-size:10.5px">{disabled_n} off</span>'
            if disabled_n else ""
        )

        rows.append(f"""
        <tr>
          <td>
            <div class="provider-name">{p.name}</div>
            <div class="provider-url">{p.base_url}</div>
            <div class="muted" style="margin-top:5px;font-family:'JetBrains Mono',monospace;font-size:11px">
              {ti:,} in / {to:,} out tok
            </div>
            {rpm_bar}
          </td>
          <td><span class="chip violet">{p.model_id}</span></td>
          <td>{_key_status_chip(p)}{disabled_note}</td>
          <td class="num"><a href="/admin/providers/{p.id}/keys" style="color:var(--cyan);text-decoration:underline">{active} / {len(p.keys)}</a></td>
          <td class="num">{inflight_p}</td>
          <td class="num">{rate_p:.0f}%</td>
          <td>
            <div style="display:flex;gap:4px;justify-content:flex-end">
              <form method="post" action="/admin/providers/{p.id}/keys" style="display:inline"
                    onsubmit="var k = prompt('Новый API-ключ провайдера:'); if(!k) return false; this.api_key.value = k;">
                <input type="hidden" name="api_key">
                <button type="submit" class="btn-icon neutral" title="Добавить ключ">＋</button>
              </form>
              <form method="post" action="/admin/providers/{p.id}/rotate" style="display:inline">
                <button type="submit" class="btn-icon neutral" title="Новый cxepy-ключ">↻</button>
              </form>
              <form method="post" action="/admin/providers/{p.id}/delete" style="display:inline"
                    onsubmit="return confirm('Удалить провайдера и все его ключи?')">
                <button type="submit" class="btn-icon" title="Удалить">×</button>
              </form>
            </div>
          </td>
        </tr>""")

    if rows:
        providers_html = f"""
<div class="tbl-wrap">
  <table>
    <thead>
      <tr>
        <th>Провайдер</th><th>Модель</th><th>Статус</th>
        <th>Ключи</th><th>В работе</th><th>Успех</th><th></th>
      </tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>"""
    else:
        providers_html = """
<div class="tbl-wrap">
  <div class="empty">
    <div class="icon">◇</div>
    Пока нет ни одного провайдера.<br>
    Добавь первого ниже, чтобы получить cxepy-ключ.
  </div>
</div>"""

    ck_rows = []
    with conn() as c:
        for ck in c.execute("SELECT * FROM client_keys ORDER BY id DESC"):
            prov = st.providers.get(ck["provider_id"])
            pname = prov.name if prov else '<span class="muted">удалён</span>'
            status = ('<span class="chip green">активен</span>'
                      if ck["enabled"] else
                      '<span class="chip red">отключён</span>')
            ck_rows.append(f"""
            <tr>
              <td><span class="mono" style="color:#d8b4fe">{ck['key_prefix']}…</span></td>
              <td>{pname}</td>
              <td>{status}</td>
              <td>
                <div style="display:flex;justify-content:flex-end">
                  <form method="post" action="/admin/client-keys/{ck['id']}/delete"
                        onsubmit="return confirm('Удалить этот cxepy-ключ?')">
                    <button type="submit" class="btn-icon" title="Удалить">×</button>
                  </form>
                </div>
              </td>
            </tr>""")

    if ck_rows:
        client_keys_html = f"""
<div class="tbl-wrap">
  <table>
    <thead><tr><th>Ключ</th><th>Провайдер</th><th>Статус</th><th></th></tr></thead>
    <tbody>{''.join(ck_rows)}</tbody>
  </table>
</div>"""
    else:
        client_keys_html = """
<div class="tbl-wrap">
  <div class="empty"><div class="icon">⚿</div>Ключи ещё не выпущены.</div>
</div>"""

    flash_html = ""
    if new_key:
        flash_html = f"""
<div class="flash">
  <div class="icon">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff"
         stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M20 6L9 17l-5-5"/>
    </svg>
  </div>
  <div class="body">
    <div class="title">Новый cxepy-ключ создан — сохрани его, больше не покажем</div>
    <div class="key" id="newkey">{new_key}</div>
    <div class="copy">
      <button type="button" class="btn-ghost"
              onclick="var b=this;navigator.clipboard.writeText(document.getElementById('newkey').textContent).then(function(){{b.textContent='Скопировано ✓';setTimeout(function(){{b.textContent='Скопировать'}},1500)}})">
        Скопировать
      </button>
    </div>
  </div>
</div>"""

    body = f"""
{nav_bar('dashboard')}

<div class="hero">
  <div>
    <h1>Дашборд</h1>
    <p>Управление провайдерами, ключами и ротацией</p>
  </div>
  <div class="pulse"><span class="led"></span><span id="live-status">live · 0 in-flight</span></div>
</div>

{flash_html}
{stats_html}

<div class="section">
  <div class="section-title">
    <h2>Добавить провайдера</h2>
    <span class="count">ключи — по одному в строке</span>
  </div>
  <div class="card">
    <form method="post" action="/admin/providers">
      <div class="grid-3">
        <div class="field">
          <label>Название</label>
          <input name="name" placeholder="openai-main" required>
        </div>
        <div class="field">
          <label>Base URL</label>
          <input name="base_url" placeholder="https://api.openai.com" required>
        </div>
        <div class="field">
          <label>Model ID</label>
          <input name="model_id" placeholder="gpt-4o-mini" required>
        </div>
      </div>
      <div class="field">
        <label>API-ключи провайдера</label>
        <textarea name="api_keys" required
          placeholder="sk-aaaaaaaaaaaaaaaaaaaaaaaa&#10;sk-bbbbbbbbbbbbbbbbbbbbbbbb&#10;sk-cccccccccccccccccccccccc"></textarea>
      </div>
      <div style="display:flex;justify-content:flex-end;margin-top:6px">
        <button type="submit" class="btn-primary">Добавить провайдера →</button>
      </div>
    </form>
  </div>
</div>

<div class="section">
  <div class="section-title">
    <h2>Провайдеры</h2>
    <span class="count">{total_providers} шт.</span>
  </div>
  {providers_html}
</div>

<div class="section">
  <div class="section-title">
    <h2>Выданные cxepy-ключи</h2>
    <span class="count">{len(ck_rows)} шт.</span>
  </div>
  {client_keys_html}
</div>

<div class="footer">
  <span>Endpoint: <code>POST /v1/chat/completions</code> · <code>Authorization: Bearer cxepy-…</code></span>
  <span>cxepy · OpenAI-compatible proxy</span>
</div>

<script>
const evt = new EventSource('/admin/events');
evt.onmessage = (e) => {{
  try {{
    const d = JSON.parse(e.data);
    document.getElementById('live-status').textContent =
      'live · ' + d.total_inflight + ' in-flight';
  }} catch (x) {{}}
}};
evt.onerror = () => {{
  document.getElementById('live-status').textContent = 'reconnecting…';
}};
</script>
"""
    return page("Дашборд", body)


def keys_page(p: ProviderState) -> str:
    now = time.monotonic()
    rows = []
    for k in p.keys:
        p._prune_windows(k, now)
        rpm_now = len(k.rpm_window)
        tpm_now = sum(t for _, t in k.tpm_window)

        if k.disabled:
            status = f'<span class="chip red"><span class="dot-led red"></span>{k.disabled_reason or "off"}</span>'
        elif k.cooldown_until > now:
            status = '<span class="chip amber"><span class="dot-led amber"></span>cooldown</span>'
        else:
            status = '<span class="chip green"><span class="dot-led green"></span>ready</span>'

        masked = f"{k.value[:8]}…{k.value[-4:]}" if len(k.value) > 14 else k.value

        rows.append(f"""
        <div class="kv-row" data-kid="{k.id}">
          <span class="kv-id">#{k.id}</span>
          <span class="kv-key" title="ID: {k.id}">{masked}</span>
          <span class="kv-limits">
            <input class="limit-input" type="number" placeholder="RPM" value="{k.rpm_limit}" min="0" onchange="saveLimits({k.id})" data-field="rpm_limit">
            <input class="limit-input" type="number" placeholder="TPM" value="{k.tpm_limit}" min="0" onchange="saveLimits({k.id})" data-field="tpm_limit">
            <input class="limit-input" type="number" placeholder="Req" value="{k.request_limit}" min="0" onchange="saveLimits({k.id})" data-field="request_limit">
            <input class="limit-input" type="number" placeholder="Tok" value="{k.token_limit}" min="0" onchange="saveLimits({k.id})" data-field="token_limit">
          </span>
          <span class="kv-stats">
            {rpm_now}/{k.rpm_limit or '∞'} rpm · {tpm_now}/{k.tpm_limit or '∞'} tpm
          </span>
          <span class="kv-stats">{k.tokens_in} in / {k.tokens_out} out</span>
          <span class="kv-stats">{k.total} req · {k.success} ok</span>
          {status}
          <form method="post" action="/admin/keys/{k.id}/delete"
                onsubmit="return confirm('Удалить ключ?')" style="margin-left:auto">
            <button type="submit" class="btn-icon" title="Удалить">×</button>
          </form>
        </div>""")

    if not rows:
        rows_html = '<div class="empty"><div class="icon">⚿</div>У провайдера нет ключей</div>'
    else:
        rows_html = f"""
<div class="card" style="padding:0">
  <div class="kv-row" style="background:rgba(255,255,255,.02);font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--text-mute)">
    <span class="kv-id">ID</span>
    <span style="flex:1">Ключ</span>
    <span style="min-width:380px">Лимиты (0 = без лимита)</span>
    <span style="min-width:150px">Текущий</span>
    <span style="min-width:130px">Токены</span>
    <span style="min-width:110px">Запросы</span>
    <span style="min-width:80px">Статус</span>
    <span style="width:40px"></span>
  </div>
  {''.join(rows)}
</div>"""

    body = f"""
{nav_bar('dashboard')}

<div class="hero">
  <div>
    <h1>{p.name}</h1>
    <p>{p.base_url} · модель <span class="mono" style="color:var(--violet)">{p.model_id}</span></p>
  </div>
  <div>
    <a class="btn-ghost" href="/admin/">← К провайдерам</a>
  </div>
</div>

<div class="section">
  <div class="section-title">
    <h2>Ключи</h2>
    <span class="count">{len(p.keys)} шт.</span>
  </div>
  {rows_html}
</div>

<div class="section">
  <div class="section-title">
    <h2>Добавить ключ</h2>
    <span class="count">один ключ</span>
  </div>
  <div class="card">
    <form method="post" action="/admin/providers/{p.id}/keys">
      <div class="field">
        <label>API-ключ</label>
        <input name="api_key" placeholder="sk-..." required>
      </div>
      <div style="display:flex;justify-content:flex-end">
        <button type="submit" class="btn-primary">Добавить</button>
      </div>
    </form>
  </div>
</div>

<div class="footer">
  <span>Лимиты применяются мгновенно · 0 = без лимита</span>
  <span>cxepy · ключи провайдера</span>
</div>

<script>
async function saveLimits(kid) {{
  const row = document.querySelector('.kv-row[data-kid="' + kid + '"]');
  const body = new URLSearchParams();
  row.querySelectorAll('input[data-field]').forEach(inp => {{
    body.append(inp.dataset.field, inp.value || '0');
  }});
  const resp = await fetch('/admin/keys/' + kid + '/limits', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
    body: body.toString()
  }});
  if (!resp.ok) {{
    alert('Не удалось сохранить: ' + resp.status);
  }}
}}
</script>
"""
    return page(f"{p.name} · ключи", body)


def playground_page(st: AppState) -> str:
    models = sorted({p.model_id for p in st.providers.values()})
    model_options = "".join(
        f'<option value="{m}">{m}</option>' for m in models
    ) or '<option value="">нет моделей</option>'

    body = f"""
{nav_bar('playground')}

<div class="hero">
  <div>
    <h1>Playground</h1>
    <p>Тестируй модели прямо в браузере — с файлами и фото</p>
  </div>
</div>

<div class="playground">
  <div class="chat-window" id="chat">
    <div class="msg assistant">
      <div class="role">cxepy</div>
      <div class="content">Привет! Выбери модель снизу и напиши сообщение. Поддерживаются файлы (PDF, TXT) и изображения (PNG, JPG, GIF, WebP). Можно вставлять фото через Ctrl+V.</div>
    </div>
  </div>

  <div class="input-area">
    <div class="attachments" id="attachments"></div>
    <div class="input-row">
      <div style="display:flex;flex-direction:column;flex:1;gap:6px">
        <div class="toolbar" style="margin:0">
          <button type="button" class="btn-ghost btn-sm" onclick="document.getElementById('file-input').click()">
            📎 Файл
          </button>
          <input type="file" id="file-input" multiple hidden
                 accept="image/*,.pdf,.txt,.md,.csv,.json"
                 onchange="handleFiles(this.files)">
          <button type="button" class="btn-ghost btn-sm" onclick="pasteImage()">🖼 Фото</button>
          <button type="button" class="btn-ghost btn-sm" onclick="toggleParams()">⚙ Параметры</button>
          <select id="model-select" class="model-select">{model_options}</select>
          <label class="stream-toggle">
            <input type="checkbox" id="stream-toggle" checked> стрим
          </label>
        </div>
        <textarea id="prompt" placeholder="Напиши сообщение… (Shift+Enter — новая строка)"
                  onkeydown="if(event.key==='Enter'&&!event.shiftKey){{event.preventDefault();send()}}"></textarea>
      </div>
      <button id="send-btn" class="btn-primary" onclick="send()" style="padding:14px 18px;font-size:16px">→</button>
      <button id="stop-btn" class="btn-ghost" onclick="stop()"
              style="display:none;padding:14px 18px;font-size:16px">■</button>
    </div>

    <div class="params-panel" id="params" style="display:none">
      <label>Temperature <input type="range" id="temperature" min="0" max="2" step="0.1" value="1"><span id="temp-val" class="mono">1.0</span></label>
      <label>Top P <input type="range" id="top_p" min="0" max="1" step="0.05" value="1"><span id="top_p-val" class="mono">1.0</span></label>
      <label>Max Tokens <input type="number" id="max_tokens" value="2048" min="1"></label>
    </div>
  </div>
</div>

<div class="footer">
  <span>Playground использует твою админскую сессию · cxepy-ключи не светятся в браузере</span>
  <span>cxepy · playground</span>
</div>

<script>
const chat = document.getElementById('chat');
const prompt = document.getElementById('prompt');
const sendBtn = document.getElementById('send-btn');
const stopBtn = document.getElementById('stop-btn');
let controller = null;
let currentFiles = [];

function addMessage(role, content) {{
  const div = document.createElement('div');
  div.className = 'msg ' + role;
  div.innerHTML = '<div class="role">' + role + '</div>' +
                  '<div class="content">' + content + '</div>';
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
  return div;
}}

function handleFiles(files) {{
  for (const f of files) {{
    currentFiles.push(f);
    const chip = document.createElement('span');
    chip.className = 'chip violet';
    chip.textContent = f.name;
    document.getElementById('attachments').appendChild(chip);
  }}
}}

function pasteImage() {{
  if (navigator.clipboard && navigator.clipboard.read) {{
    navigator.clipboard.read().then(items => {{
      for (const item of items) {{
        for (const type of item.types) {{
          if (type.startsWith('image/')) {{
            item.getType(type).then(blob => {{
              const file = new File([blob], 'pasted.png', {{ type }});
              handleFiles([file]);
            }});
          }}
        }}
      }}
    }}).catch(e => alert('Не удалось прочитать буфер: ' + e.message));
  }} else {{
    alert('Браузер не поддерживает чтение буфера обмена. Используй Ctrl+V или кнопку «Файл».');
  }}
}}

prompt.addEventListener('paste', e => {{
  const items = e.clipboardData.items;
  for (const item of items) {{
    if (item.type.startsWith('image/')) {{
      e.preventDefault();
      const file = item.getAsFile();
      handleFiles([file]);
    }}
  }}
}});

function toggleParams() {{
  const p = document.getElementById('params');
  p.style.display = p.style.display === 'none' ? 'flex' : 'none';
}}

document.getElementById('temperature').addEventListener('input', e => {{
  document.getElementById('temp-val').textContent = parseFloat(e.target.value).toFixed(1);
}});
document.getElementById('top_p').addEventListener('input', e => {{
  document.getElementById('top_p-val').textContent = parseFloat(e.target.value).toFixed(2);
}});

async function send() {{
  const text = prompt.value.trim();
  if (!text && currentFiles.length === 0) return;

  addMessage('user', text + (currentFiles.length ? ' <span class="muted">📎 ' + currentFiles.length + ' файл(ов)</span>' : ''));
  prompt.value = '';
  document.getElementById('attachments').innerHTML = '';

  const form = new FormData();
  form.append('model', document.getElementById('model-select').value);
  form.append('messages', JSON.stringify([
    {{ role: 'user', content: text || '(вложение)' }}
  ]));
  form.append('stream', document.getElementById('stream-toggle').checked);
  form.append('temperature', document.getElementById('temperature').value);
  form.append('top_p', document.getElementById('top_p').value);
  form.append('max_tokens', document.getElementById('max_tokens').value);
  for (const f of currentFiles) form.append('files', f);
  currentFiles = [];

  const msgDiv = addMessage('assistant', '<span class="cursor"></span>');
  const contentDiv = msgDiv.querySelector('.content');
  let acc = '';

  controller = new AbortController();
  sendBtn.style.display = 'none';
  stopBtn.style.display = 'inline-flex';

  try {{
    const resp = await fetch('/pg/chat/completions', {{
      method: 'POST',
      body: form,
      signal: controller.signal
    }});

    if (!resp.ok) {{
      const errText = await resp.text();
      contentDiv.innerHTML = '<span style="color:var(--red)">Ошибка ' + resp.status + ': ' + errText + '</span>';
      return;
    }}

    const ctype = resp.headers.get('content-type') || '';
    if (!ctype.includes('text/event-stream')) {{
      const data = await resp.json();
      acc = data.choices?.[0]?.message?.content || JSON.stringify(data);
      contentDiv.textContent = acc;
      return;
    }}

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {{
      const {{ done, value }} = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, {{ stream: true }});
      const lines = buffer.split('\\n');
      buffer = lines.pop();
      for (const line of lines) {{
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6).trim();
        if (data === '[DONE]') continue;
        try {{
          const json = JSON.parse(data);
          const delta = json.choices?.[0]?.delta?.content;
          if (delta) {{
            acc += delta;
            contentDiv.textContent = acc;
          }}
        }} catch (e) {{}}
      }}
      chat.scrollTop = chat.scrollHeight;
    }}
  }} catch (e) {{
    if (e.name !== 'AbortError') {{
      contentDiv.textContent = acc + '\\n[ошибка: ' + e.message + ']';
    }} else {{
      contentDiv.textContent = acc + '\\n[остановлено]';
    }}
  }} finally {{
    sendBtn.style.display = 'inline-flex';
    stopBtn.style.display = 'none';
    controller = null;
  }}
}}

function stop() {{
  if (controller) controller.abort();
}}
</script>
"""
    return page("Playground", body, container_class="container-fluid")


def logs_page(st: AppState) -> str:
    rows = []
    for entry in reversed(list(st.log_buffer)):
        ts = time.strftime("%H:%M:%S", time.localtime(entry.get("ts", 0)))
        status = entry.get("status", 0)
        cls = "ok" if 200 <= status < 300 else ("retry" if status in (429, 500, 502, 503, 504) else "err")
        rows.append(f"""
        <tr>
          <td class="muted">{ts}</td>
          <td>{entry.get('provider', '-')}</td>
          <td>#{entry.get('key_id', '-')}</td>
          <td class="muted">{entry.get('client_prefix', '-')}</td>
          <td><span class="log-status {cls}">{status}</span></td>
          <td class="num">{entry.get('ms', '-')} ms</td>
          <td class="muted">{entry.get('note', '')}</td>
        </tr>""")

    if not rows:
        rows_html = '<div class="empty"><div class="icon">≡</div>Логи пусты — сделай пару запросов</div>'
        table = f'<div class="tbl-wrap">{rows_html}</div>'
    else:
        table = f"""
<div class="tbl-wrap">
  <table class="log-tbl">
    <thead>
      <tr>
        <th>Время</th><th>Провайдер</th><th>Ключ</th>
        <th>Клиент</th><th>Статус</th><th>Лат.</th><th>Заметка</th>
      </tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>"""

    body = f"""
{nav_bar('logs')}

<div class="hero">
  <div>
    <h1>Логи запросов</h1>
    <p>Последние {LOG_BUFFER_SIZE} запросов в памяти</p>
  </div>
</div>

<div class="section">
  {table}
</div>

<div class="footer">
  <span>Обновление при перезагрузке · ring buffer {LOG_BUFFER_SIZE}</span>
  <span>cxepy · logs</span>
</div>
"""
    return page("Логи", body)


# ============================================================
# LIFESPAN
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    db_init()
    with conn() as c:
        if not c.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
            c.execute(
                "INSERT INTO admins (username, password_hash) VALUES (?,?)",
                (ADMIN_USER, hash_password(ADMIN_PASSWORD)),
            )

    if not os.environ.get("ADMIN_PASSWORD"):
        log.warning(
            "default admin password in use — set ADMIN_PASSWORD env var "
            "and delete cxepy.db before public deploy"
        )

    st = AppState()
    load_state(st)
    st.http = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=10.0, read=300.0, write=60.0, pool=10.0),
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
    )
    app.state.cxepy = st

    flusher = asyncio.create_task(_stats_flusher(st))

    log.info(
        f"cxepy started · providers={len(st.providers)} · db={DB_PATH} · "
        f"stream_usage={'on' if INJECT_STREAM_USAGE else 'off'}"
    )
    try:
        yield
    finally:
        flusher.cancel()
        try:
            await flusher
        except asyncio.CancelledError:
            pass

        deadline = time.monotonic() + SHUTDOWN_GRACE_SECONDS
        while time.monotonic() < deadline:
            inflight = total_in_flight(st)
            if inflight == 0:
                break
            log.info(f"shutdown: waiting for {inflight} in-flight request(s)")
            await asyncio.sleep(0.5)
        remaining = total_in_flight(st)
        if remaining:
            log.warning(
                f"shutdown: {remaining} request(s) still in flight, forcing close"
            )

        _flush_stats(st)
        await st.http.aclose()
        log.info("cxepy stopped")


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)


# ============================================================
# ADMIN ROUTES
# ============================================================
@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def root():
    return RedirectResponse("/admin/", status_code=303)


@app.get("/admin/login", response_class=HTMLResponse)
async def login_form():
    return HTMLResponse(login_page())


@app.post("/admin/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    ip = client_ip(request)
    login_rate_check(ip)

    with conn() as c:
        row = c.execute(
            "SELECT * FROM admins WHERE username=?", (username,)
        ).fetchone()

    if not row or not verify_password(password, row["password_hash"]):
        login_rate_fail(ip)
        log.warning(f"failed login attempt from {ip} (user={username!r})")
        return HTMLResponse(login_page("Неверный логин или пароль"), status_code=401)

    login_rate_clear(ip)
    token = create_session(row["id"])
    resp = RedirectResponse("/admin/", status_code=303)
    resp.set_cookie(
        "session", token, httponly=True, samesite="lax", max_age=SESSION_TTL
    )
    return resp


@app.get("/admin/logout")
async def logout():
    resp = RedirectResponse("/admin/login", status_code=303)
    resp.delete_cookie("session")
    return resp


@app.get("/admin/", response_class=HTMLResponse)
async def dashboard(request: Request):
    require_admin(request)
    st: AppState = request.app.state.cxepy
    new_key = request.cookies.get("flash_key", "")
    resp = HTMLResponse(dashboard_page(st, new_key=new_key))
    if new_key:
        resp.delete_cookie("flash_key")
    return resp


@app.get("/admin/logs", response_class=HTMLResponse)
async def logs_view(request: Request):
    require_admin(request)
    return HTMLResponse(logs_page(request.app.state.cxepy))


@app.get("/admin/events")
async def admin_events(request: Request):
    require_admin(request)
    st: AppState = request.app.state.cxepy

    async def gen():
        while True:
            data = {
                "total_inflight": total_in_flight(st),
                "providers": [
                    {
                        "id": p.id,
                        "name": p.name,
                        "inflight": sum(k.in_flight for k in p.keys),
                        "active_keys": sum(1 for k in p.keys if not k.disabled),
                        "total_keys": len(p.keys),
                    }
                    for p in st.providers.values()
                ],
            }
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/admin/providers/{pid}/keys", response_class=HTMLResponse)
async def provider_keys_page(request: Request, pid: int):
    require_admin(request)
    st: AppState = request.app.state.cxepy
    p = st.providers.get(pid)
    if not p:
        raise HTTPException(404, "provider not found")
    return HTMLResponse(keys_page(p))


@app.post("/admin/keys/{kid}/limits")
async def update_key_limits(
    request: Request,
    kid: int,
    rpm_limit: int = Form(0),
    tpm_limit: int = Form(0),
    request_limit: int = Form(0),
    token_limit: int = Form(0),
):
    require_admin(request)
    with conn() as c:
        c.execute(
            "UPDATE provider_keys SET rpm_limit=?, tpm_limit=?, "
            "request_limit=?, token_limit=? WHERE id=?",
            (rpm_limit, tpm_limit, request_limit, token_limit, kid),
        )
    st: AppState = request.app.state.cxepy
    for p in st.providers.values():
        for k in p.keys:
            if k.id == kid:
                k.rpm_limit = rpm_limit
                k.tpm_limit = tpm_limit
                k.request_limit = request_limit
                k.token_limit = token_limit
    return {"status": "ok"}


@app.post("/admin/keys/{kid}/delete")
async def delete_key(request: Request, kid: int):
    require_admin(request)
    with conn() as c:
        c.execute("DELETE FROM provider_keys WHERE id=?", (kid,))
    load_state(request.app.state.cxepy)
    ref = request.headers.get("referer", "/admin/")
    return RedirectResponse(ref, status_code=303)


@app.post("/admin/providers")
async def add_provider(
    request: Request,
    name: str = Form(...),
    base_url: str = Form(...),
    model_id: str = Form(...),
    api_keys: str = Form(...),
):
    require_admin(request)
    keys = [k.strip() for k in api_keys.splitlines() if k.strip()]
    if not keys:
        raise HTTPException(400, "no provider keys")

    base = base_url.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]

    with conn() as c:
        cur = c.execute(
            "INSERT INTO providers (name, base_url, model_id, created_at) VALUES (?,?,?,?)",
            (name, base, model_id, time.time()),
        )
        pid = cur.lastrowid
        c.executemany(
            "INSERT INTO provider_keys (provider_id, api_key) VALUES (?,?)",
            [(pid, k) for k in keys],
        )

    raw = generate_client_key()
    with conn() as c:
        c.execute(
            "INSERT INTO client_keys (key_hash, key_prefix, provider_id, created_at) "
            "VALUES (?,?,?,?)",
            (hash_client_key(raw), raw[:14], pid, time.time()),
        )

    load_state(request.app.state.cxepy)
    log.info(f"provider added: {name} ({len(keys)} keys)")

    resp = RedirectResponse("/admin/", status_code=303)
    resp.set_cookie("flash_key", raw, httponly=True, samesite="lax", max_age=120)
    return resp


@app.post("/admin/providers/{pid}/rotate")
async def rotate_client_key(request: Request, pid: int):
    require_admin(request)
    raw = generate_client_key()
    with conn() as c:
        c.execute(
            "INSERT INTO client_keys (key_hash, key_prefix, provider_id, created_at) "
            "VALUES (?,?,?,?)",
            (hash_client_key(raw), raw[:14], pid, time.time()),
        )
    load_state(request.app.state.cxepy)
    resp = RedirectResponse("/admin/", status_code=303)
    resp.set_cookie("flash_key", raw, httponly=True, samesite="lax", max_age=120)
    return resp


@app.post("/admin/providers/{pid}/keys")
async def add_provider_key(request: Request, pid: int, api_key: str = Form(...)):
    require_admin(request)
    val = api_key.strip()
    if not val:
        raise HTTPException(400, "empty api key")
    with conn() as c:
        c.execute(
            "INSERT INTO provider_keys (provider_id, api_key) VALUES (?,?)",
            (pid, val),
        )
    load_state(request.app.state.cxepy)
    log.info(f"provider {pid}: added key")
    ref = request.headers.get("referer", "/admin/")
    return RedirectResponse(ref, status_code=303)


@app.post("/admin/providers/{pid}/delete")
async def delete_provider(request: Request, pid: int):
    require_admin(request)
    with conn() as c:
        c.execute("DELETE FROM providers WHERE id=?", (pid,))
    load_state(request.app.state.cxepy)
    log.info(f"provider {pid}: deleted")
    return RedirectResponse("/admin/", status_code=303)


@app.post("/admin/client-keys/{cid}/delete")
async def delete_client_key(request: Request, cid: int):
    require_admin(request)
    with conn() as c:
        c.execute("DELETE FROM client_keys WHERE id=?", (cid,))
    load_state(request.app.state.cxepy)
    return RedirectResponse("/admin/", status_code=303)


# ============================================================
# PLAYGROUND ROUTES
# ============================================================
@app.get("/playground", response_class=HTMLResponse)
async def playground(request: Request):
    require_admin(request)
    return HTMLResponse(playground_page(request.app.state.cxepy))


@app.post("/pg/chat/completions")
async def playground_chat(request: Request):
    require_admin(request)
    st: AppState = request.app.state.cxepy

    form = await request.form()
    model_id = (form.get("model") or "").strip()
    messages_json = form.get("messages") or "[]"
    stream = str(form.get("stream", "false")).lower() in ("true", "1", "on")

    temperature = float(form.get("temperature") or 1.0)
    top_p = float(form.get("top_p") or 1.0)
    max_tokens = int(form.get("max_tokens") or 2048)

    provider = next(
        (p for p in st.providers.values() if p.model_id == model_id),
        None
    )
    if not provider:
        raise HTTPException(404, f"model {model_id!r} not configured")

    try:
        messages = json.loads(messages_json)
    except Exception:
        raise HTTPException(400, "invalid messages json")

    uploads = form.getlist("files")
    file_parts = []
    for f in uploads:
        if not isinstance(f, UploadFile):
            continue
        content = await f.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(413, f"file {f.filename} too large")
        mime = f.content_type or mimetypes.guess_type(f.filename or "")[0] or ""
        if mime in ALLOWED_IMAGE_TYPES:
            b64 = base64.b64encode(content).decode()
            file_parts.append({
                "type": "image_url",
                "image_url": {"url": f"data:{mime};base64,{b64}"}
            })
        else:
            text = extract_text_from_file(content, mime, f.filename or "file")
            file_parts.append({
                "type": "text",
                "text": f"\n\n[Файл: {f.filename}]\n{text}"
            })

    if file_parts and messages:
        last = messages[-1]
        if isinstance(last.get("content"), str):
            parts = [{"type": "text", "text": last["content"]}] + file_parts
            last["content"] = parts

    payload = {
        "model": provider.model_id,
        "messages": messages,
        "stream": stream,
        "temperature": temperature,
        "top_p": top_p,
        "max_tokens": max_tokens,
    }
    if stream and INJECT_STREAM_USAGE:
        payload["stream_options"] = {"include_usage": True}

    body = json.dumps(payload).encode()
    upstream_headers = {
        "content-type": "application/json",
        "accept": "text/event-stream" if stream else "application/json",
    }

    last_status, last_body = 0, b""
    started = time.monotonic()

    for attempt in range(MAX_KEY_ATTEMPTS):
        key = await provider.pick()
        if key is None:
            if last_status:
                break
            raise HTTPException(503, "no available keys")

        req = st.http.build_request(
            "POST",
            f"{provider.base_url}/v1/chat/completions",
            headers={**upstream_headers, "authorization": f"Bearer {key.value}"},
            content=body,
        )
        try:
            resp = await st.http.send(req, stream=True)
        except httpx.RequestError as e:
            provider.release(key, 0)
            last_status, last_body = 502, str(e).encode()
            if attempt < MAX_KEY_ATTEMPTS - 1:
                await asyncio.sleep(0.1 * (2 ** attempt))
            continue

        if resp.status_code >= 400:
            err_body = await resp.aread()
            await resp.aclose()
            quota = _is_quota_error(resp.status_code, err_body)
            provider.release(key, resp.status_code, is_quota=quota)
            last_status, last_body = resp.status_code, err_body
            if resp.status_code not in RETRYABLE_STATUS and not quota:
                return JSONResponse(
                    content=_safe_json(err_body),
                    status_code=resp.status_code,
                )
            if attempt < MAX_KEY_ATTEMPTS - 1:
                await asyncio.sleep(0.1 * (2 ** attempt))
            continue

        headers = {
            k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP
        }
        return StreamingResponse(
            _stream_upstream(resp, provider, key),
            status_code=resp.status_code,
            headers=headers,
            media_type=resp.headers.get("content-type", "application/json"),
        )

    return JSONResponse(content=_safe_json(last_body), status_code=last_status or 502)


# ============================================================
# PROXY
# ============================================================
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
}


def extract_bearer(request: Request) -> Optional[str]:
    h = request.headers.get("authorization", "")
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return None


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    st: AppState = request.app.state.cxepy
    started = time.monotonic()

    raw = extract_bearer(request)
    if not raw:
        raise HTTPException(401, "missing api key")

    ck = st.client_keys.get(hash_client_key(raw))
    if not ck or not ck[1]:
        raise HTTPException(401, "invalid api key")

    provider_id, _ = ck
    provider = st.providers.get(provider_id)
    if not provider:
        raise HTTPException(404, "provider not found")

    body = await request.body()
    try:
        payload = json.loads(body)
    except Exception:
        raise HTTPException(400, "invalid json")

    if provider.model_id:
        payload["model"] = provider.model_id

    if INJECT_STREAM_USAGE and payload.get("stream") is True:
        opts = payload.get("stream_options")
        if not isinstance(opts, dict):
            opts = {}
        opts.setdefault("include_usage", True)
        payload["stream_options"] = opts

    body = json.dumps(payload).encode()

    upstream_headers = {
        "content-type": "application/json",
        "accept": request.headers.get("accept", "application/json"),
    }

    last_status, last_body = 0, b""
    client_prefix = raw[:14]

    for attempt in range(MAX_KEY_ATTEMPTS):
        key = await provider.pick()
        if key is None:
            if last_status:
                break
            raise HTTPException(503, "no available keys (all in cooldown)")

        req = st.http.build_request(
            "POST",
            f"{provider.base_url}/v1/chat/completions",
            headers={**upstream_headers, "authorization": f"Bearer {key.value}"},
            content=body,
        )

        try:
            resp = await st.http.send(req, stream=True)
        except httpx.RequestError as e:
            provider.release(key, 0)
            last_status, last_body = 502, str(e).encode()
            log.warning(f"upstream network error: {e}")
            push_log(st, {
                "provider": provider.name, "key_id": key.id,
                "client_prefix": client_prefix, "status": 0,
                "ms": int((time.monotonic() - started) * 1000),
                "note": f"network: {e}",
            })
            if attempt < MAX_KEY_ATTEMPTS - 1:
                await asyncio.sleep(0.1 * (2 ** attempt))
            continue

        if resp.status_code >= 400:
            err_body = await resp.aread()
            await resp.aclose()
            quota = _is_quota_error(resp.status_code, err_body)
            provider.release(key, resp.status_code, is_quota=quota)
            last_status, last_body = resp.status_code, err_body

            if resp.status_code not in RETRYABLE_STATUS and not quota:
                push_log(st, {
                    "provider": provider.name, "key_id": key.id,
                    "client_prefix": client_prefix,
                    "status": resp.status_code,
                    "ms": int((time.monotonic() - started) * 1000),
                    "note": "passthrough",
                })
                return JSONResponse(
                    content=_safe_json(err_body),
                    status_code=resp.status_code,
                )

            push_log(st, {
                "provider": provider.name, "key_id": key.id,
                "client_prefix": client_prefix,
                "status": resp.status_code,
                "ms": int((time.monotonic() - started) * 1000),
                "note": f"retry quota={quota}",
            })
            if attempt < MAX_KEY_ATTEMPTS - 1:
                await asyncio.sleep(0.1 * (2 ** attempt))
            continue

        headers = {
            k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP
        }
        push_log(st, {
            "provider": provider.name, "key_id": key.id,
            "client_prefix": client_prefix,
            "status": resp.status_code,
            "ms": int((time.monotonic() - started) * 1000),
            "note": "ok",
        })
        return StreamingResponse(
            _stream_upstream(resp, provider, key),
            status_code=resp.status_code,
            headers=headers,
            media_type=resp.headers.get("content-type", "application/json"),
        )

    return JSONResponse(content=_safe_json(last_body), status_code=last_status or 502)


async def _stream_upstream(resp: httpx.Response, provider: ProviderState, key: KeyState):
    tail = bytearray()
    try:
        async for chunk in resp.aiter_bytes():
            yield chunk
            tail.extend(chunk)
            if len(tail) > 8192:
                del tail[:-8192]
    finally:
        await resp.aclose()
        try:
            usage = _extract_usage_from_sse_tail(bytes(tail))
            if usage is None:
                usage = _extract_usage_from_json(bytes(tail))
            if usage:
                _apply_usage(key, usage)
        except Exception as e:
            log.error(f"usage extraction failed: {e}")
        provider.release(key, resp.status_code)


def _safe_json(b: bytes):
    try:
        return json.loads(b)
    except Exception:
        return {"error": b.decode(errors="replace")}


@app.get("/v1/models")
async def list_models(request: Request):
    st: AppState = request.app.state.cxepy
    raw = extract_bearer(request)
    if not raw:
        raise HTTPException(401, "missing api key")
    ck = st.client_keys.get(hash_client_key(raw))
    if not ck or not ck[1]:
        raise HTTPException(401, "invalid api key")
    provider = st.providers.get(ck[0])
    model = provider.model_id if provider else "unknown"
    return {"object": "list", "data": [{"id": model, "object": "model"}]}
