"""
cxepy — умный OpenAI-совместимый прокси с ротацией API-ключей.

Возможности:
  • Умная ротация: минимальный in_flight + приоритет по ошибкам
  • Автоотключение мёртвых ключей (quota / auth)
  • Учёт токенов per key (in/out) с персистентностью в SQLite
  • Hard-limits per key через env (защита от слива баланса)
  • Точный учёт в стримах через stream_options.include_usage
  • Честный SSE-стриминг, ретраи на retryable-статусах, backoff
  • Красивый премиум-дашборд, rate-limit на логине, graceful shutdown

Запуск (локально):
    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8080 --workers 1

На Railway:
    Start Command: uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1 \
                                     --timeout-graceful-shutdown 30
    Volume: mount path /data
    Env: DATA_DIR=/data, ADMIN_PASSWORD=<не changeme>

Опциональные env:
    KEY_HARD_LIMIT_REQUESTS       — выключить ключ после N запросов
    KEY_HARD_LIMIT_TOKENS_IN      — выключить после N входных токенов
    KEY_HARD_LIMIT_TOKENS_OUT     — выключить после N выходных токенов
    INJECT_STREAM_USAGE=true|false (default true)
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import bcrypt
import httpx
from fastapi import FastAPI, Form, HTTPException, Request
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

KEY_HARD_LIMIT_REQUESTS = int(os.environ.get("KEY_HARD_LIMIT_REQUESTS", "0") or 0)
KEY_HARD_LIMIT_TOKENS_IN = int(os.environ.get("KEY_HARD_LIMIT_TOKENS_IN", "0") or 0)
KEY_HARD_LIMIT_TOKENS_OUT = int(os.environ.get("KEY_HARD_LIMIT_TOKENS_OUT", "0") or 0)

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
    tokens_out INTEGER NOT NULL DEFAULT 0
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
        # миграции для уже существующих БД
        cols = {row["name"] for row in c.execute("PRAGMA table_info(provider_keys)")}
        if "disabled_reason" not in cols:
            c.execute("ALTER TABLE provider_keys ADD COLUMN disabled_reason TEXT")
        if "tokens_in" not in cols:
            c.execute(
                "ALTER TABLE provider_keys ADD COLUMN tokens_in INTEGER NOT NULL DEFAULT 0"
            )
        if "tokens_out" not in cols:
            c.execute(
                "ALTER TABLE provider_keys ADD COLUMN tokens_out INTEGER NOT NULL DEFAULT 0"
            )


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


@dataclass
class ProviderState:
    id: int
    name: str
    base_url: str
    model_id: str
    keys: list = field(default_factory=list)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def pick(self) -> Optional[KeyState]:
        """Выбрать наименее загруженный ключ вне cooldown."""
        async with self._lock:
            now = time.monotonic()
            best, best_score = None, float("inf")
            for k in self.keys:
                if k.disabled or k.cooldown_until > now:
                    continue
                score = k.in_flight * 1000 + k.error_count * 100
                if score < best_score:
                    best, best_score = k, score
            if best is None:
                return None
            best.in_flight += 1
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


# ключи, у которых менялись метрики и которые надо записать в БД
_dirty_keys: set = set()


def hash_client_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _apply_hard_limits(key: KeyState):
    if key.disabled:
        return
    if KEY_HARD_LIMIT_REQUESTS and key.total >= KEY_HARD_LIMIT_REQUESTS:
        key.disabled = True
        key.disabled_reason = "hard_limit"
        log.warning(f"key={key.id} disabled: hard limit (requests)")
    elif KEY_HARD_LIMIT_TOKENS_IN and key.tokens_in >= KEY_HARD_LIMIT_TOKENS_IN:
        key.disabled = True
        key.disabled_reason = "hard_limit"
        log.warning(f"key={key.id} disabled: hard limit (tokens_in)")
    elif KEY_HARD_LIMIT_TOKENS_OUT and key.tokens_out >= KEY_HARD_LIMIT_TOKENS_OUT:
        key.disabled = True
        key.disabled_reason = "hard_limit"
        log.warning(f"key={key.id} disabled: hard limit (tokens_out)")


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
        _dirty_keys.add(key.id)
        _apply_hard_limits(key)


def load_state(st: AppState):
    """
    Синхронизировать in-memory состояние с БД.

    Не пересоздаём ProviderState / KeyState для уже существующих сущностей —
    иначе сбросятся in_flight, cooldown и накопленная статистика у ключей,
    которые прямо сейчас обслуживают запросы.
    """
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
                    k["api_key"],
                    bool(k["enabled"]),
                    k["disabled_reason"] or "",
                    k["tokens_in"] or 0,
                    k["tokens_out"] or 0,
                )
                for k in c.execute(
                    "SELECT id, api_key, enabled, disabled_reason, "
                    "tokens_in, tokens_out "
                    "FROM provider_keys WHERE provider_id=?",
                    (pid,),
                )
            }
            ps.keys = [k for k in ps.keys if k.id in db_keys]
            existing_ids = {k.id for k in ps.keys}
            for kid, (kval, enabled, reason, ti, to) in db_keys.items():
                if kid in existing_ids:
                    continue
                ks = KeyState(id=kid, value=kval)
                if not enabled:
                    ks.disabled = True
                    ks.disabled_reason = reason
                ks.tokens_in = ti
                ks.tokens_out = to
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
# UPSTREAM ERROR / USAGE HELPERS
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
    """Найти последний SSE-чанк с usage в хвосте стрима (best effort)."""
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


# ============================================================
# STYLES + TEMPLATES
# ============================================================
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#07070c; --bg-1:#0c0c14; --surface:rgba(255,255,255,.028);
  --surface-hi:rgba(255,255,255,.05); --border:rgba(255,255,255,.07);
  --border-hi:rgba(255,255,255,.14);
  --text:#ececf3; --text-dim:#9898a8; --text-mute:#5a5a6a;
  --violet:#8b5cf6; --indigo:#6366f1; --cyan:#22d3ee;
  --green:#34d399; --red:#f87171; --amber:#fbbf24;
  --radius:14px; --radius-sm:10px;
}
html,body{background:var(--bg);color:var(--text);min-height:100vh;
  font-family:'Inter',-apple-system,BlinkMacSystemFont,system-ui,sans-serif;
  font-feature-settings:'cv11','ss01','ss03';-webkit-font-smoothing:antialiased;
  -moz-osx-font-smoothing:grayscale;letter-spacing:-.011em;line-height:1.5}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(ellipse 70% 55% at 15% -5%, rgba(139,92,246,.22), transparent 55%),
    radial-gradient(ellipse 55% 45% at 90% 10%, rgba(34,211,238,.10), transparent 55%),
    radial-gradient(ellipse 90% 70% at 50% 105%, rgba(99,102,241,.10), transparent 55%)}
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;opacity:.35;
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='120' height='120'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 .035 0'/></filter><rect width='100%' height='100%' filter='url(%23n)'/></svg>")}
a{color:inherit;text-decoration:none}
.container{position:relative;z-index:1;max-width:1120px;margin:0 auto;padding:0 28px}

.nav{position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;
  padding:22px 0 20px;border-bottom:1px solid var(--border);margin-bottom:36px}
.brand{display:flex;align-items:center;gap:11px;font-weight:600;font-size:17px;letter-spacing:-.02em}
.brand .mark{width:28px;height:28px;border-radius:8px;position:relative;
  background:linear-gradient(135deg,var(--violet),var(--cyan));
  box-shadow:0 0 24px rgba(139,92,246,.45),inset 0 1px 0 rgba(255,255,255,.35)}
.brand .mark::after{content:'';position:absolute;inset:5px;border-radius:4px;
  background:linear-gradient(135deg,rgba(255,255,255,.55),transparent)}
.brand .dot{color:var(--text-mute);font-weight:400}
.nav-actions{display:flex;gap:8px;align-items:center}
.nav-link{color:var(--text-dim);font-size:13.5px;font-weight:500;padding:8px 14px;
  border-radius:9px;transition:all .15s ease;border:1px solid transparent}
.nav-link:hover{color:var(--text);background:var(--surface);border-color:var(--border)}

.hero{margin-bottom:28px}
.hero h1{font-size:34px;font-weight:600;letter-spacing:-.03em;line-height:1.15;
  background:linear-gradient(180deg,#fff 0%,#a8a8bc 100%);
  -webkit-background-clip:text;background-clip:text;color:transparent}
.hero p{color:var(--text-dim);font-size:14.5px;margin-top:6px}

.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:26px 0 34px}
.stat{position:relative;padding:20px 20px 18px;border-radius:var(--radius);
  background:var(--surface);border:1px solid var(--border);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  overflow:hidden;transition:border-color .2s ease, transform .2s ease}
.stat:hover{border-color:var(--border-hi);transform:translateY(-1px)}
.stat::before{content:'';position:absolute;top:0;left:20px;right:20px;height:1px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.14),transparent)}
.stat .label{color:var(--text-mute);font-size:11.5px;text-transform:uppercase;
  letter-spacing:.08em;font-weight:500;margin-bottom:10px}
.stat .value{font-size:26px;font-weight:600;letter-spacing:-.02em;
  font-variant-numeric:tabular-nums}
.stat .value .sub{color:var(--text-mute);font-size:15px;font-weight:500;margin-left:2px}
.stat .glow{position:absolute;bottom:-40px;right:-40px;width:120px;height:120px;
  border-radius:50%;filter:blur(40px);opacity:.35;pointer-events:none}
.stat.violet .glow{background:var(--violet)}
.stat.cyan .glow{background:var(--cyan)}
.stat.green .glow{background:var(--green)}
.stat.amber .glow{background:var(--amber)}

.section{margin:34px 0}
.section-title{display:flex;align-items:baseline;justify-content:space-between;
  margin-bottom:14px}
.section-title h2{font-size:16px;font-weight:600;letter-spacing:-.01em}
.section-title .count{color:var(--text-mute);font-size:12.5px}

.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:22px 22px 20px;backdrop-filter:blur(12px);
  -webkit-backdrop-filter:blur(12px);position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:22px;right:22px;height:1px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.12),transparent)}

.field{margin-bottom:14px}
.field label{display:block;font-size:12px;color:var(--text-dim);font-weight:500;
  margin-bottom:6px;letter-spacing:.01em}
.field input,.field textarea{width:100%;background:rgba(0,0,0,.35);color:var(--text);
  border:1px solid var(--border);border-radius:var(--radius-sm);padding:11px 13px;
  font:inherit;font-size:14px;transition:all .15s ease;outline:none}
.field input::placeholder,.field textarea::placeholder{color:var(--text-mute)}
.field input:focus,.field textarea:focus{border-color:rgba(139,92,246,.55);
  background:rgba(0,0,0,.5);box-shadow:0 0 0 3px rgba(139,92,246,.14)}
.field textarea{min-height:96px;resize:vertical;font-family:'JetBrains Mono',ui-monospace,
  monospace;font-size:12.5px;line-height:1.65}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}

button,.btn{font:inherit;font-size:13.5px;font-weight:500;border:none;cursor:pointer;
  padding:10px 16px;border-radius:var(--radius-sm);transition:all .15s ease;
  letter-spacing:-.005em;display:inline-flex;align-items:center;gap:7px}
.btn-primary{color:#fff;background:linear-gradient(135deg,var(--violet),var(--indigo));
  box-shadow:0 1px 0 rgba(255,255,255,.15) inset, 0 6px 20px -8px rgba(139,92,246,.65)}
.btn-primary:hover{transform:translateY(-1px);
  box-shadow:0 1px 0 rgba(255,255,255,.15) inset, 0 10px 26px -8px rgba(139,92,246,.8)}
.btn-primary:active{transform:translateY(0)}
.btn-ghost{color:var(--text-dim);background:var(--surface-hi);border:1px solid var(--border)}
.btn-ghost:hover{color:var(--text);border-color:var(--border-hi);background:rgba(255,255,255,.07)}
.btn-icon{color:var(--text-mute);background:transparent;padding:7px 9px;border-radius:8px;
  border:1px solid transparent}
.btn-icon:hover{color:var(--red);background:rgba(248,113,113,.09);border-color:rgba(248,113,113,.22)}
.btn-icon.neutral:hover{color:var(--text);background:var(--surface-hi);border-color:var(--border)}

.tbl-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  overflow:hidden;backdrop-filter:blur(12px)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:14px 18px;font-size:13.5px;border-bottom:1px solid var(--border);
  vertical-align:middle}
th{font-weight:500;color:var(--text-mute);font-size:11px;text-transform:uppercase;
  letter-spacing:.08em;background:rgba(255,255,255,.015)}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.014)}
td.num{font-variant-numeric:tabular-nums}

.mono{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12.5px}
.chip{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:999px;
  font-size:11.5px;font-weight:500;letter-spacing:.005em;font-family:'JetBrains Mono',monospace}
.chip.violet{color:#c4b5fd;background:rgba(139,92,246,.14);border:1px solid rgba(139,92,246,.28)}
.chip.dim{color:var(--text-dim);background:var(--surface-hi);border:1px solid var(--border)}
.chip.green{color:#86efac;background:rgba(52,211,153,.12);border:1px solid rgba(52,211,153,.25)}
.chip.amber{color:#fcd34d;background:rgba(251,191,36,.12);border:1px solid rgba(251,191,36,.25)}
.chip.red{color:#fca5a5;background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.25)}
.dot-led{width:7px;height:7px;border-radius:50%;display:inline-block}
.dot-led.green{background:var(--green);box-shadow:0 0 8px var(--green)}
.dot-led.amber{background:var(--amber);box-shadow:0 0 8px var(--amber)}
.dot-led.red{background:var(--red);box-shadow:0 0 8px var(--red)}

.muted{color:var(--text-mute);font-size:12.5px}
.provider-name{font-weight:500;color:var(--text)}
.provider-url{color:var(--text-mute);font-size:12px;margin-top:2px;
  font-family:'JetBrains Mono',monospace}

.flash{display:flex;gap:12px;align-items:flex-start;padding:16px 18px;border-radius:var(--radius);
  margin-bottom:22px;background:linear-gradient(135deg,rgba(139,92,246,.14),rgba(34,211,238,.07));
  border:1px solid rgba(139,92,246,.3);position:relative;overflow:hidden;
  animation:slideIn .35s cubic-bezier(.2,.9,.25,1)}
@keyframes slideIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.flash .icon{width:34px;height:34px;border-radius:9px;flex-shrink:0;display:grid;
  place-items:center;background:linear-gradient(135deg,var(--violet),var(--cyan));
  box-shadow:0 0 20px rgba(139,92,246,.5)}
.flash .body{flex:1;min-width:0}
.flash .title{font-weight:600;font-size:13.5px;margin-bottom:6px}
.flash .key{font-family:'JetBrains Mono',monospace;font-size:13px;background:rgba(0,0,0,.45);
  padding:10px 12px;border-radius:8px;border:1px solid var(--border);
  user-select:all;word-break:break-all;color:#c4b5fd}
.flash .copy{margin-top:8px}
.err-box{padding:14px 16px;border-radius:var(--radius-sm);margin-bottom:18px;
  background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.28);
  color:#fca5a5;font-size:13.5px}

.empty{padding:44px 24px;text-align:center;color:var(--text-mute);font-size:13.5px}
.empty .icon{font-size:28px;margin-bottom:10px;opacity:.4}

.login-wrap{position:relative;z-index:1;min-height:100vh;display:grid;place-items:center;
  padding:24px}
.login-card{width:100%;max-width:400px;padding:36px 32px 30px;border-radius:20px;
  background:rgba(15,15,22,.75);border:1px solid var(--border-hi);
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  box-shadow:0 24px 80px -20px rgba(0,0,0,.7),
    0 0 0 1px rgba(255,255,255,.03) inset;
  animation:pop .5s cubic-bezier(.2,.9,.25,1)}
@keyframes pop{from{opacity:0;transform:translateY(12px) scale(.98)}to{opacity:1;transform:none}}
.login-card .logo-row{display:flex;align-items:center;gap:11px;margin-bottom:22px}
.login-card h1{font-size:22px;font-weight:600;letter-spacing:-.02em;
  background:linear-gradient(180deg,#fff,#b8b8c8);
  -webkit-background-clip:text;background-clip:text;color:transparent}
.login-card p.sub{color:var(--text-dim);font-size:13.5px;margin:-14px 0 24px}

.footer{margin:56px 0 32px;padding-top:22px;border-top:1px solid var(--border);
  color:var(--text-mute);font-size:12.5px;display:flex;justify-content:space-between;
  align-items:center;flex-wrap:wrap;gap:10px}
.footer code{font-family:'JetBrains Mono',monospace;background:var(--surface-hi);
  padding:3px 8px;border-radius:6px;border:1px solid var(--border);font-size:11.5px;
  color:var(--text-dim)}

@media (max-width:820px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .grid-3{grid-template-columns:1fr}
  .hero h1{font-size:26px}
  th:nth-child(4),td:nth-child(4),
  th:nth-child(6),td:nth-child(6){display:none}
}
"""


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


def nav_bar() -> str:
    return f"""
<div class="nav">
  <a href="/admin/" class="brand">{BRAND_MARK}<span>cxepy<span class="dot">/</span>admin</span></a>
  <div class="nav-actions">
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
      <button type="submit" class="btn-primary" style="width:100%;justify-content:center;padding:12px">
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
    <div class="label">Провайдеры</div>
    <div class="value">{total_providers}</div>
    <div class="glow"></div>
  </div>
  <div class="stat cyan">
    <div class="label">Ключи провайдеров</div>
    <div class="value">{active_keys}<span class="sub">/ {total_keys}</span></div>
    <div class="glow"></div>
  </div>
  <div class="stat amber">
    <div class="label">В работе</div>
    <div class="value">{inflight}</div>
    <div class="glow"></div>
  </div>
  <div class="stat green">
    <div class="label">Успешность</div>
    <div class="value">{rate:.1f}<span class="sub">%</span></div>
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
        tokens_note = f"{ti:,} in / {to:,} out".replace(",", " ")
        disabled_note = (
            f' <span class="chip red" style="font-size:10.5px">{disabled_n} off</span>'
            if disabled_n else ""
        )
        rows.append(f"""
        <tr>
          <td>
            <div class="provider-name">{p.name}</div>
            <div class="provider-url">{p.base_url}</div>
            <div class="muted" style="margin-top:4px;font-family:'JetBrains Mono',monospace;
                 font-size:11px">{tokens_note} tok</div>
          </td>
          <td><span class="chip violet">{p.model_id}</span></td>
          <td>{_key_status_chip(p)}{disabled_note}</td>
          <td class="num">{active} / {len(p.keys)}</td>
          <td class="num">{inflight_p}</td>
          <td class="num">{rate_p:.0f}% <span class="muted">({succ_p}/{total_p})</span></td>
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
              <td><span class="mono" style="color:#c4b5fd">{ck['key_prefix']}…</span></td>
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
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff"
         stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M20 6L9 17l-5-5"/>
    </svg>
  </div>
  <div class="body">
    <div class="title">Новый cxepy-ключ создан — сохрани его, больше не покажем</div>
    <div class="key" id="newkey">{new_key}</div>
    <div class="copy">
      <button type="button" class="btn-ghost"
              onclick="navigator.clipboard.writeText(document.getElementById('newkey').textContent).then(()=>{this.textContent='Скопировано ✓';setTimeout(()=>this.textContent='Скопировать',1500)})">
        Скопировать
      </button>
    </div>
  </div>
</div>"""

    body = f"""
{nav_bar()}

<div class="hero">
  <h1>Дашборд</h1>
  <p>Управление провайдерами, ключами и ротацией</p>
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
      <div style="display:flex;justify-content:flex-end;margin-top:4px">
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
"""
    return page("Дашборд", body)


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

        _flush_stats(st)  # финальный сброс статистики
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
    return RedirectResponse("/admin/", status_code=303)


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

    # инъекция include_usage — чтобы провайдер вернул usage в стриме
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
                # 400/403/404 (не-квота) — вина клиента, отдаём как есть
                log.info(
                    f"proxy 4xx passthrough · prov={provider.name} key={key.id} "
                    f"status={resp.status_code} "
                    f"ms={int((time.monotonic()-started)*1000)}"
                )
                return JSONResponse(
                    content=_safe_json(err_body),
                    status_code=resp.status_code,
                )

            log.info(
                f"proxy retry · prov={provider.name} key={key.id} "
                f"status={resp.status_code} quota={quota} attempt={attempt+1}"
            )
            if attempt < MAX_KEY_ATTEMPTS - 1:
                await asyncio.sleep(0.1 * (2 ** attempt))
            continue

        # 2xx — отдаём клиенту (со стримингом)
        headers = {
            k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP
        }
        log.info(
            f"proxy ok · prov={provider.name} key={key.id} "
            f"status={resp.status_code} ms={int((time.monotonic()-started)*1000)}"
        )
        return StreamingResponse(
            _stream_upstream(resp, provider, key),
            status_code=resp.status_code,
            headers=headers,
            media_type=resp.headers.get("content-type", "application/json"),
        )

    return JSONResponse(content=_safe_json(last_body), status_code=last_status or 502)


async def _stream_upstream(resp: httpx.Response, provider: ProviderState, key: KeyState):
    """
    Прокидываем чанки в клиент без буферизации.
    Параллельно держим хвост последних 8KB, чтобы вытащить usage из SSE
    (приходит в финальном чанке при stream_options.include_usage=true).
    """
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
                # на случай не-стримингового ответа через тот же путь
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
