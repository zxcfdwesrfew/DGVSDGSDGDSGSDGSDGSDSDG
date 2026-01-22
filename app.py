import os
import time
import secrets
import json
import sqlite3
import secrets
from datetime import datetime, timedelta

import pytz
import pyotp
import requests
import re
from flask import Flask, render_template, request, redirect, session, url_for, abort, jsonify, send_from_directory, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Security headers configuration
BASE_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://ajax.googleapis.com; "
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
    "img-src 'self' data: blob:; "
    "connect-src 'self' ws: wss:; "
    "media-src 'self' data:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "darkbin-secret")
# Cookie / session hardening
app.config.update(
    SESSION_COOKIE_SECURE=True,      # send only over HTTPS (relaxed for local dev below)
    SESSION_COOKIE_HTTPONLY=True,    # block JS access to session
    SESSION_COOKIE_SAMESITE="Lax",   # mitigate CSRF on top-level navigation
    PREFERRED_URL_SCHEME="https",
)

# Cloudflare Turnstile keys (move to env in production)
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "0x4AAAAAACON9xBUzAStBHdq")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "0x4AAAAAACON9xeSiosPN9Yra-0F76PAFRc")

BASE_DIR = os.path.abspath(os.getcwd())
DATA = os.path.join(BASE_DIR, "data")
ADMIN_PASTES = os.path.join(DATA, "admin")
ANON_PASTES = os.path.join(DATA, "other")
UPLOAD_ROOT = os.path.join(BASE_DIR, "static", "uploads")
EDIT_STORE = os.path.join(DATA, "edits")
os.makedirs(EDIT_STORE, exist_ok=True)

NAME_EFFECTS = {
    "gold": "/assets/gold.gif",
    "sparkle-blue": "/assets/sparkle_blue.gif",
    "sparkle-green": "/assets/sparkle_green.gif",
    "sparkle-red": "/assets/sparkle_red.gif",
    "sparkle-black": "/assets/sparkle_black.gif",
    "sparkle-pink": "/assets/sparkle_pink.gif",
        "sparkle-white": "/assets/sparkle_white.gif",
        "sparkle-yellow": "/assets/sparkle_yellow.gif",
        "sparkle-purple": "/assets/purple.gif",
}


@app.after_request
def set_security_headers(resp: Response):
    # Core hardening headers
    resp.headers.setdefault("Content-Security-Policy", BASE_CSP)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    # Enforce TLS for compliant clients (no-op on plain HTTP dev servers)
    resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    return resp

ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_GIF_BYTES = 2 * 1024 * 1024       # legacy cap for gif
MAX_AVATAR_BYTES = 1 * 1024 * 1024    # 1 MB avatars
MAX_BANNER_BYTES = 524 * 1024         # ~0.5 MB banners
MAX_BACKGROUND_BYTES = 524 * 1024     # ~0.5 MB backgrounds
MAX_MUSIC_BYTES = 5 * 1024 * 1024     # 5 MB music
ALLOWED_MUSIC_EXT = {"mp3"}

TEMP_BLACKLIST_MINUTES = 50
ADMIN_PROBE_LIMIT = 3
SENSITIVE_PROBE_LIMIT = 5
PROBE_WINDOW_SECONDS = 900  # 15 minutes window for probe counts
REQUEST_RATE_LIMIT = None
REQUEST_RATE_WINDOW = None

ROLE_LEVELS = {
    "founder": 100,
    "admin": 90,
    "manager": 80,
    "mod": 70,
    "council": 60,
    "helper": 55,
    "clique": 50,
    "rich": 40,
    "vip": 30,
    "criminal": 20,
    "companion": 20,
    "fbi": 20,
    "user": 10,
}
SENSITIVE_PROBE_PATHS = ("/database.db", "/data", "/helpers", "/static/uploads", "/__pycache__", "/app.py", "/main.py")
SUSPICIOUS_VPN_MARKERS = ["vpn", "proxy", "tor", "okhttp", "python-requests", "curl", "httpclient"]
PROXY_CACHE = {}  # ip -> (timestamp, is_proxy)
PROXY_CACHE_TTL = 15 * 60  # 15 minutes
RF_IP = {}  # ip -> (start_ts, count, stage)

FLAG_REASONS = [
    "Personal information of individuals under 15",
    "Links to explicit material involving minors",
    "Dox requests / harassment",
    "Spam / malicious content",
    "Direct threats",
    "Reposting identical content",
]


# --- DB helpers ---
def get_db():
    conn = sqlite3.connect(os.path.join(BASE_DIR, "database.db"), timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def is_proxy_ip(ip: str) -> bool:
    """Lightweight VPN/Proxy detection via proxycheck.io with caching."""
    if not ip or ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        return False
    now = time.time()
    cached = PROXY_CACHE.get(ip)
    if cached and now - cached[0] < PROXY_CACHE_TTL:
        return cached[1]
    try:
        resp = requests.get(
            f"https://proxycheck.io/v3/{ip}",
            params={"risk": 1, "vpn": 1, "asn": 1, "node": 1, "port": 1, "seen": 1, "ver": 2},
            timeout=2,
        )
        data = resp.json().get(ip, {})
        is_bad = data.get("proxy") == "yes" or data.get("type", "").lower() in ("vpn", "proxy", "tor")
    except Exception:
        is_bad = False
    PROXY_CACHE[ip] = (now, is_bad)
    return is_bad


def run_migrations():
    conn = get_db()
    cur = conn.cursor()

    def add_column(table, definition):
        try:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")
        except sqlite3.OperationalError:
            pass  # already exists

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT DEFAULT 'user',
            datejoin TEXT NOT NULL,
            email TEXT
        )
    """
    )
    add_column("users", "email TEXT")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pasts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            pastname TEXT NOT NULL,
            date TEXT NOT NULL,
            hour TEXT NOT NULL,
            view TEXT NOT NULL,
            pin TEXT NOT NULL,
            ip TEXT NOT NULL,
            email TEXT,
            comments TEXT,
            status TEXT DEFAULT 'active',
            flag_status TEXT DEFAULT 'none',
            edit_status TEXT DEFAULT 'none',
            deleted_by TEXT,
            deleted_reason TEXT
        )
    """
    )
    # Ensure new columns exist on legacy DB
    add_column("pasts", "status TEXT DEFAULT 'active'")
    add_column("pasts", "flag_status TEXT DEFAULT 'none'")
    add_column("pasts", "edit_status TEXT DEFAULT 'none'")
    add_column("pasts", "deleted_by TEXT")
    add_column("pasts", "deleted_reason TEXT")
    add_column("gift_codes", "expires_at TEXT")

    # Gift codes table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS gift_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            reward TEXT,
            max_uses INTEGER DEFAULT 1,
            used_by INTEGER,
            used_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(used_by) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            granted_by INTEGER,
            reason TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS badges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            color TEXT DEFAULT '#202225',
            icon TEXT,
            tooltip TEXT,
            system INTEGER DEFAULT 0,
            granted_by INTEGER,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, name),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(granted_by) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            avatar_path TEXT,
            banner_path TEXT,
            background_path TEXT,
            background_scope TEXT DEFAULT 'none',
            bio TEXT,
            bio_animation_type TEXT,
            username_color TEXT,
            allow_profile_comments INTEGER DEFAULT 1,
            name_effect TEXT,
            glow_enabled INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS profile_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_user_id INTEGER NOT NULL,
            author_user_id INTEGER,
            comment TEXT NOT NULL,
            created_at TEXT NOT NULL,
            ip TEXT,
            status_snapshot TEXT,
            FOREIGN KEY(profile_user_id) REFERENCES users(id),
            FOREIGN KEY(author_user_id) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS paste_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            paste_id INTEGER NOT NULL,
            author_user_id INTEGER,
            comment TEXT NOT NULL,
            created_at TEXT NOT NULL,
            ip TEXT,
            status_snapshot TEXT,
            FOREIGN KEY(paste_id) REFERENCES pasts(id),
            FOREIGN KEY(author_user_id) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            paste_id INTEGER NOT NULL,
            raised_by INTEGER NOT NULL,
            role_snapshot TEXT,
            reason TEXT NOT NULL,
            status TEXT NOT NULL,
            decided_by INTEGER,
            created_at TEXT NOT NULL,
            decided_at TEXT,
            FOREIGN KEY(paste_id) REFERENCES pasts(id),
            FOREIGN KEY(raised_by) REFERENCES users(id),
            FOREIGN KEY(decided_by) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS edit_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            paste_id INTEGER NOT NULL,
            requested_by INTEGER NOT NULL,
            reason TEXT,
            new_body_path TEXT NOT NULL,
            status TEXT NOT NULL,
            decided_by INTEGER,
            created_at TEXT NOT NULL,
            decided_at TEXT,
            FOREIGN KEY(paste_id) REFERENCES pasts(id),
            FOREIGN KEY(requested_by) REFERENCES users(id),
            FOREIGN KEY(decided_by) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            payload TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            detail TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(actor_id) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            ip TEXT,
            is_deleted INTEGER DEFAULT 0,
            deleted_by INTEGER,
            deleted_reason TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(deleted_by) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_mutes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            muted_until TEXT NOT NULL,
            reason TEXT DEFAULT 'link spam',
            muted_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(muted_by) REFERENCES users(id)
        )
    """
    )
    
    # Add missing columns to chat_mutes if they don't exist
    add_column("chat_mutes", "muted_until TEXT")
    add_column("chat_mutes", "reason TEXT DEFAULT 'link spam'")
    add_column("chat_mutes", "muted_by INTEGER")
    add_column("chat_mutes", "created_at TEXT DEFAULT CURRENT_TIMESTAMP")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            body TEXT,
            link TEXT,
            color TEXT DEFAULT '#25ABEE',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            ua TEXT,
            ip TEXT,
            last_seen TEXT NOT NULL,
            is_locked INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS username_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            old_username TEXT NOT NULL,
            new_username TEXT NOT NULL,
            changed_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS order_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item TEXT,
            amount REAL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS twofa (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            enabled INTEGER DEFAULT 0,
            forced INTEGER DEFAULT 0,
            authed INTEGER DEFAULT 0,
            secret TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ip TEXT,
            reason TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """
    )
    add_column("blacklist", "expires_at TEXT")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_mutes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            muted_by INTEGER NOT NULL,
            reason TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(muted_by) REFERENCES users(id)
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS followers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            follower_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(follower_id, target_id)
        )
    """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_follow_target ON followers(target_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_follow_follower ON followers(follower_id)")

    conn.commit()
    conn.close()


def ensure_upload_dirs(user_id: int):
    for folder in ("avatar", "banner", "background"):
        os.makedirs(os.path.join(UPLOAD_ROOT, str(user_id), folder), exist_ok=True)


def get_current_user():
    username = session.get("username")
    if not username:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    return user


def get_follow_counts(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM followers WHERE target_id = ?", (user_id,))
    followers = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM followers WHERE follower_id = ?", (user_id,))
    following = cur.fetchone()[0]
    conn.close()
    return followers, following


def is_following(follower_id: int, target_id: int) -> bool:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM followers WHERE follower_id = ? AND target_id = ?",
        (follower_id, target_id),
    )
    row = cur.fetchone()
    conn.close()
    return bool(row)


def get_user_by_id(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()
    return user


def highest_role_for_user(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT role FROM roles WHERE user_id = ?", (user_id,))
    roles = [r["role"] for r in cur.fetchall()]
    if not roles:
        cur.execute("SELECT status FROM users WHERE id = ?", (user_id,))
        status_row = cur.fetchone()
        if status_row and status_row["status"]:
            status_val = status_row["status"]
            if status_val == "root":
                status_val = "admin"
            roles = [status_val]
    conn.close()
    if not roles:
        return "user"
    return max(roles, key=lambda r: ROLE_LEVELS.get(r, 0))


def has_role(user_id: int, min_role: str) -> bool:
    if not user_id:
        return False
    top = highest_role_for_user(user_id)
    return ROLE_LEVELS.get(top, 0) >= ROLE_LEVELS.get(min_role, 0)


# Common bot / scraper user-agent fragments we want to block from sensitive areas
SUSPICIOUS_UA = [
    "curl",
    "wget",
    "python-requests",
    "aiohttp",
    "httpclient",
    "okhttp",
    "libwww-perl",
    "java/",
    "go-http-client",
    "bot",
    "spider",
    "crawler",
    "scrapy",
    "postmanruntime",
]


def issue_captcha_token():
    token = secrets.token_hex(16)
    session["captcha_token"] = token
    session["captcha_issued_at"] = time.time()
    return token


def verify_captcha_token(form_value: str) -> bool:
    saved = session.get("captcha_token")
    issued_at = session.get("captcha_issued_at", 0)
    if not saved or not form_value or saved != form_value:
        return False
    # expire after 5 minutes
    if time.time() - issued_at > 300:
        return False
    # one-time use
    session.pop("captcha_token", None)
    session.pop("captcha_issued_at", None)
    return True


def rate_limit(action: str, seconds: int):
    key = f"rl_{action}"
    now = time.time()
    last = session.get(key, 0)
    if now - last < seconds:
        return False, seconds - (now - last)
    session[key] = now
    return True, 0


# --- CSRF helpers ---
def issue_csrf_token():
    token = secrets.token_hex(20)
    session["csrf_token"] = token
    session["csrf_issued_at"] = time.time()
    return token


def get_csrf_token():
    token = session.get("csrf_token")
    issued = session.get("csrf_issued_at", 0)
    if not token or time.time() - issued > 3600:
        token = issue_csrf_token()
    return token


def verify_csrf_token(form_value: str) -> bool:
    saved = session.get("csrf_token")
    ts = session.get("csrf_issued_at", 0)
    if not saved or not form_value or saved != form_value:
        return False
    if time.time() - ts > 3600:  # 1 hour validity
        return False
    return True


@app.context_processor
def inject_csrf():
    return {"csrf_token": get_csrf_token()}

# CSRF helper for JSON / AJAX requests (uses X-CSRF-Token header)
def verify_json_csrf() -> bool:
    return verify_csrf_token(request.headers.get("X-CSRF-Token", ""))


@app.context_processor
def inject_nav_counters():
    admin_flags = 0
    admin_edits = 0
    total_pending = 0
    user = get_current_user()
    if user and has_role(user["id"], "admin"):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM flags WHERE status = 'pending'")
        admin_flags = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM edit_requests WHERE status = 'pending'")
        admin_edits = cur.fetchone()["c"]
        conn.close()
        total_pending = admin_flags + admin_edits
    return {
        "nav_admin_flags": admin_flags,
        "nav_admin_edits": admin_edits,
        "nav_admin_total": total_pending,
    }


def can_flag(user_id: int) -> bool:
    # Council and above can file flags
    return (
        has_role(user_id, "council")
        or has_role(user_id, "mod")
        or has_role(user_id, "manager")
        or has_role(user_id, "admin")
        or has_role(user_id, "founder")
    )


def can_decide_flag(user_id: int) -> bool:
    return has_role(user_id, "mod") or has_role(user_id, "manager") or has_role(user_id, "admin") or has_role(user_id, "founder")


def can_decide_edit(user_id: int) -> bool:
    return has_role(user_id, "mod") or has_role(user_id, "manager") or has_role(user_id, "admin") or has_role(user_id, "founder")


def is_blacklisted(user_id: int, ip: str) -> bool:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, expires_at FROM blacklist WHERE user_id = ? OR ip = ?", (user_id, ip))
    row = cur.fetchone()
    if not row:
        conn.close()
        return False
    expires = row["expires_at"]
    if expires:
        try:
            exp_dt = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
            exp_dt = pytz.timezone("Europe/Moscow").localize(exp_dt)
            if current_msk_time() > exp_dt:
                cur.execute("DELETE FROM blacklist WHERE id = ?", (row["id"],))
                conn.commit()
                conn.close()
                return False
        except Exception:
            pass
    conn.close()
    return True


def is_muted(user_id: int):
    if not user_id:
        return False
    now = current_msk_time()
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT expires_at FROM chat_mutes WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
        (user_id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return False
    expires = row["expires_at"]
    if not expires:
        return True
    try:
        exp_dt = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
        exp_dt = pytz.timezone("Europe/Moscow").localize(exp_dt)
        return now <= exp_dt
    except Exception:
        return True


def current_msk_time():
    return datetime.now(pytz.timezone("Europe/Moscow"))


def save_upload(file_storage, user_id: int, kind: str, allow_gif: bool, allowed_ext=None, max_bytes=None):
    filename = secure_filename(file_storage.filename)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    allowed = allowed_ext or ALLOWED_IMAGE_EXT
    if ext not in allowed:
        raise ValueError("Invalid file type")
    file_bytes = file_storage.read()
    file_storage.seek(0)
    limit = max_bytes or MAX_GIF_BYTES
    # Per-kind overrides
    if not max_bytes:
        if kind == "avatar":
            limit = MAX_AVATAR_BYTES
        elif kind == "banner":
            limit = MAX_BANNER_BYTES
        elif kind == "background":
            limit = MAX_BACKGROUND_BYTES
    if ext == "gif" and not allow_gif:
        raise ValueError("GIF not allowed for this role")
    if len(file_bytes) > limit:
        raise ValueError("File exceeds size limit")

    ensure_upload_dirs(user_id)
    target_dir = os.path.join(UPLOAD_ROOT, str(user_id), kind)
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, f"{kind}.{ext}")
    file_storage.save(path)
    return path.replace(BASE_DIR, "").replace("\\", "/")


def remove_upload(path: str):
    if not path:
        return
    abs_path = os.path.join(BASE_DIR, path.lstrip("/"))
    if os.path.isfile(abs_path):
        os.remove(abs_path)


def delete_paste_file(pastname: str) -> bool:
    """Delete paste file from admin/anon storage."""
    for root in (ADMIN_PASTES, ANON_PASTES):
        path = os.path.join(root, pastname)
        if os.path.exists(path):
            try:
                os.remove(path)
                return True
            except FileNotFoundError:
                pass
    return False


def log_action(actor_id, action, target_type=None, target_id=None, detail=None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO logs (actor_id, action, target_type, target_id, detail, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """,
        (
            actor_id,
            action,
            target_type,
            target_id,
            json.dumps(detail or {}),
            current_msk_time().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()


def create_notification(user_id, ntype, payload=None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO notifications (user_id, type, payload, is_read, created_at)
        VALUES (?, ?, ?, 0, ?)
    """,
        (
            user_id,
            ntype,
            json.dumps(payload or {}),
            current_msk_time().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()


def ensure_profile(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM profiles WHERE user_id = ?", (user_id,))
    existing = cur.fetchone()
    if not existing:
        now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            """
            INSERT INTO profiles (user_id, created_at, updated_at, username_color, name_effect, glow_enabled, music_path)
            VALUES (?, ?, ?, ?, ?, 0, NULL)
        """,
            (user_id, now, now, "#2a9fd6", None),
        )
        conn.commit()
    conn.close()


def ensure_default_role(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM roles WHERE user_id = ?", (user_id,))
    exists = cur.fetchone()
    if not exists:
        now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            "INSERT INTO roles (user_id, role, created_at) VALUES (?, ?, ?)",
            (user_id, "user", now),
        )
        conn.commit()
    conn.close()


def add_badge(user_id: int, name: str, color="#202225", icon=None, tooltip=None, system=False, granted_by=None):
    conn = get_db()
    cur = conn.cursor()
    now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        "SELECT 1 FROM badges WHERE user_id = ? AND name = ?",
        (user_id, name),
    )
    if cur.fetchone():
        conn.close()
        return
    cur.execute(
        """
        INSERT INTO badges (user_id, name, color, icon, tooltip, system, granted_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (user_id, name, color, icon, tooltip, 1 if system else 0, granted_by, now),
    )
    conn.commit()
    conn.close()


def get_badges_for_user(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM badges WHERE user_id = ? ORDER BY created_at ASC", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return rows


def ensure_staff_badge(user_id: int):
    # staff badge for council and above
    top = highest_role_for_user(user_id)
    if ROLE_LEVELS.get(top, 0) >= 60:
        add_badge(
            user_id,
            "Staff",
            color="#202225",
            icon="https://cdn.discordapp.com/badge-icons/5e74e9b61934fc1f67c65515d1f7e60d.png",
            tooltip="Staff",
            system=True,
        )


def ensure_twofa_record(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM twofa WHERE user_id = ?", (user_id,))
    if not cur.fetchone():
        now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            "INSERT INTO twofa (user_id, enabled, forced, authed, secret, created_at, updated_at) VALUES (?, 0, 0, 0, NULL, ?, ?)",
            (user_id, now, now),
        )
        conn.commit()
    conn.close()


def record_session_activity(user_id: int):
    if not user_id:
        return
    ua = request.headers.get("User-Agent", "")
    ip = request.remote_addr
    now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM sessions WHERE user_id = ? AND ua = ? AND ip = ? ORDER BY last_seen DESC LIMIT 1",
        (user_id, ua, ip),
    )
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE sessions SET last_seen = ? WHERE id = ?", (now, row["id"]))
    else:
        cur.execute(
            "INSERT INTO sessions (user_id, ua, ip, last_seen) VALUES (?, ?, ?, ?)",
            (user_id, ua, ip, now),
        )
    conn.commit()
    conn.close()


@app.context_processor
def user_can_flag_template():
    def _user_can_flag():
        u = get_current_user()
        return bool(u and can_flag(u["id"]))

    user = get_current_user()
    username = user['username'] if user else None
    is_staff = False
    if user:
        top_role = highest_role_for_user(user['id'])
        is_staff = top_role in ['admin', 'founder', 'mod', 'council', 'manager']

    return {
        "user_can_flag": _user_can_flag,
        "user_can_see_admin": user_can_see_admin,
        "user_can_see_council": user_can_see_council,
        "username": username,
        "user_is_staff": is_staff,
    }


@app.before_request
def enforce_blacklist():
    # Relax cookie security in plain HTTP dev so session persists
    if not request.is_secure:
        app.config["SESSION_COOKIE_SECURE"] = False
    if request.endpoint in ("static",):
        return
    user = get_current_user()
    uid = user["id"] if user else None
    ip = request.remote_addr
    if is_blacklisted(uid, ip):
        session.clear()
        return abort(403)
    if uid:
        record_session_activity(uid)


@app.before_request
def global_rate_limit():
    # Disabled at user request
    return


@app.before_request
def vpn_gate():
    # Skip static/assets and the gate itself
    if request.endpoint in ("static", "vpn_check"):
        return
    path = request.path or ""
    if path.startswith("/assets") or path.startswith("/favicon"):
        return
    # Allow chat polling to keep working even if the gate is pending
    if path.startswith("/api/chat"):
        return

    now = time.time()
    ok_until = session.get("human_ok_until", 0)
    if ok_until and now < ok_until:
        return

    needs_check = False
    # First visit: always challenge once
    if not session.get("human_verified_once"):
        needs_check = True
    # VPN / proxy markers: challenge every 20 минут
    if is_vpn_request() or is_proxy_ip(request.remote_addr):
        needs_check = True

    if needs_check:
        session["vpn_next"] = request.full_path or path or "/"
        return redirect(url_for("vpn_check"))


@app.before_request
def rapid_refresh_guard():
    """
    Если один и тот же клиент обновляет страницу >25 раз в течение ~60с:
    - первый раз: отдаём 429 с кратким сообщением
    - последующие попытки: отправляем на vpn_check
    """
    if request.endpoint in ("static", "vpn_check"):
        return
    path = request.path or ""
    if path.startswith("/assets") or path.startswith("/favicon") or path.startswith("/api/chat"):
        return

    now = time.time()
    ip = request.remote_addr or "0.0.0.0"
    # Session-based counter (if cookie lives)
    start = session.get("rf_start", now)
    count = session.get("rf_count", 0)
    stage = session.get("rf_stage", 0)  # 0-normal, 1-warned
    # Fallback IP counter when session cookie не сохраняется (HTTP dev)
    ip_start, ip_count, ip_stage = RF_IP.get(ip, (now, 0, 0))

    if now - start > 60:
        start, count, stage = now, 0, 0
    if now - ip_start > 60:
        ip_start, ip_count, ip_stage = now, 0, 0

    count += 1
    ip_count += 1
    session["rf_start"] = start
    session["rf_count"] = count
    session["rf_stage"] = stage
    RF_IP[ip] = (ip_start, ip_count, ip_stage)

    over = count > 25 or ip_count > 25
    if over:
        if stage == 0 and ip_stage == 0:
            session["rf_stage"] = 1
            RF_IP[ip] = (ip_start, ip_count, 1)
            return Response("Rate limit exceeded. Please wait a moment.", status=429)
        session["vpn_next"] = request.full_path or path or "/"
        return redirect(url_for("vpn_check"))


@app.before_request
def block_suspicious_agents_and_admin_probing():
    if request.endpoint in ("static", "vpn_check"):
        return
    if request.path.startswith("/api/chat"):
        return  # Chat API is public
    path = (request.path or "").lower()
    ua = (request.headers.get("User-Agent") or "").lower()

    def _ua_is_suspicious():
        return (not ua) or any(key in ua for key in SUSPICIOUS_UA)

    # Harden admin surface: require non-suspicious UA and valid role, otherwise 403 with log.
    if path.startswith("/admin"):
        if _ua_is_suspicious():
            log_action(None, "admin_suspicious_ua", detail={"ip": request.remote_addr, "ua": ua, "path": path})
            return abort(403)
        user = get_current_user()
        # Admin panel proper is admin/founder only; council is allowed on chat moderation endpoints.
        allowed = False
        if user:
            if has_role(user["id"], "admin") or has_role(user["id"], "founder"):
                allowed = True
            elif path.startswith("/admin/chat") and has_role(user["id"], "council"):
                allowed = True
        if not allowed:
            bump_probe("admin_probe", ADMIN_PROBE_LIMIT, "admin probes")
            log_action(user["id"] if user else None, "admin_probe_blocked", detail={"ip": request.remote_addr, "ua": ua, "path": path})
            return abort(403)
        return

    if path.startswith("/council"):
        user = get_current_user()
        allowed = False
        if user and (has_role(user["id"], "council") or has_role(user["id"], "mod") or has_role(user["id"], "manager") or has_role(user["id"], "admin") or has_role(user["id"], "founder")):
            allowed = True
        if not allowed:
            bump_probe("council_probe", ADMIN_PROBE_LIMIT, "council probes")
            log_action(user["id"] if user else None, "council_probe_blocked", detail={"ip": request.remote_addr, "ua": ua, "path": path})
            return abort(403)
        if _ua_is_suspicious():
            log_action(user["id"], "council_suspicious_ua", detail={"ip": request.remote_addr, "ua": ua, "path": path})
            return abort(403)
        return

    # For general endpoints, silently block clearly automated/fake UAs to cut bot noise.
    if _ua_is_suspicious():
        log_action(None, "suspicious_request_blocked", detail={"ip": request.remote_addr, "ua": ua, "path": path})
        return abort(403)


@app.before_request
def block_sensitive_paths():
    """
    Prevent direct fetches of sensitive files/directories that should never be served.
    """
    path = (request.path or "")
    blocked_prefixes = ("/database.db", "/data", "/helpers", "/README", "/app.py", "/main.py", "/__pycache__")
    if any(path.startswith(p) for p in blocked_prefixes):
        return abort(404)


@app.after_request
def apply_security_headers(resp):
    csp = (
        "default-src 'self' https: data: blob:; "
        "script-src 'self' 'unsafe-inline' https:; "
        "style-src 'self' 'unsafe-inline' https: https://netdna.bootstrapcdn.com; "
        "img-src 'self' https: data: blob:; "
        "media-src 'self' https: data:; "
        "connect-src 'self' https:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    resp.headers.setdefault("Content-Security-Policy", csp)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    return resp


@app.errorhandler(404)
def handle_404(e):
    path = request.path or ""
    if path.startswith("/static") or path.startswith("/assets"):
        return e
    return redirect(url_for("index"))


def is_vpn_request():
    ua = (request.headers.get("User-Agent") or "").lower()
    if any(marker in ua for marker in SUSPICIOUS_VPN_MARKERS):
        return True
    via = request.headers.get("Via") or ""
    forwarded = request.headers.get("X-Forwarded-For") or ""
    if via or (forwarded and "," in forwarded):
        return True
    return False


@app.after_request
def track_probe_status(resp):
    try:
        if resp.status_code in (403, 404):
            path = (request.path or "").lower()
            if any(path.startswith(p) for p in SENSITIVE_PROBE_PATHS):
                ip = request.remote_addr
                if ip:
                    now = time.time()
                    history = PROBE_MEMORY.get(ip, [])
                    history = [t for t in history if now - t <= PROBE_WINDOW_SECONDS]
                    history.append(now)
                    PROBE_MEMORY[ip] = history
                    if len(history) >= SENSITIVE_PROBE_LIMIT:
                        add_temp_blacklist(ip, "probe flood", TEMP_BLACKLIST_MINUTES)
                        PROBE_MEMORY.pop(ip, None)
    except Exception:
        pass
    return resp

PROBE_MEMORY = {}
IP_RATE = {}


def add_temp_blacklist(ip: str, reason: str, minutes: int = TEMP_BLACKLIST_MINUTES):
    if not ip:
        return
    conn = get_db()
    cur = conn.cursor()
    now = current_msk_time()
    expires_at = now + timedelta(minutes=minutes)
    cur.execute(
        "INSERT INTO blacklist (ip, reason, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (ip, reason, now.strftime("%Y-%m-%d %H:%M:%S"), expires_at.strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()
    session.clear()


def bump_probe(tag: str, limit: int, reason: str):
    ip = request.remote_addr
    user = get_current_user()
    key = f"{tag}_count"
    count = session.get(key, 0) + 1
    session[key] = count
    log_action(user["id"] if user else None, tag, detail={"ip": ip, "ua": (request.headers.get("User-Agent") or ""), "count": count})
    if count >= limit:
        add_temp_blacklist(ip, reason, TEMP_BLACKLIST_MINUTES)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        if not verify_csrf_token(request.form.get("csrf_token")):
            error = "Invalid form token."
        if not verify_captcha_token(request.form.get("captcha_token")):
            error = "Captcha required."
        ok, remaining = rate_limit("register", 20)
        if not ok:
            error = f"Too fast. Wait {int(remaining)}s."
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip()
        if not username or not password:
            error = "Username and password required."
        else:
            conn = get_db()
            cur = conn.cursor()
            # Block creating multiple accounts from the same IP
            cur.execute("SELECT 1 FROM users WHERE ip_address = ? LIMIT 1", (request.remote_addr,))
            if cur.fetchone():
                error = "Registration blocked: an account already exists from your IP."
            cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                error = "Username already exists."
            else:
                hashed_password = generate_password_hash(password)
                now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
                cur.execute(
                    """
                    INSERT INTO users (username, password, ip_address, status, datejoin, email)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (username, hashed_password, request.remote_addr, "user", now, email),
                )
                conn.commit()
                cur.execute("SELECT id FROM users WHERE username = ?", (username,))
                user_id = cur.fetchone()["id"]
                ensure_profile(user_id)
                ensure_default_role(user_id)
                ensure_twofa_record(user_id)
                session["username"] = username
            conn.close()
            if not error:
                return redirect(url_for("index"))
    return render_template("register.html", error=error, username=session.get("username"), captcha_token=issue_captcha_token(), csrf_token=issue_csrf_token())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        now_ts = time.time()
        fail_ts = session.get("login_fail_ts", 0)
        fail_count = session.get("login_fail_count", 0)
        if now_ts - fail_ts > 60:
            fail_count = 0
            fail_ts = now_ts
        if fail_count >= 5:
            wait_sec = max(1, int(60 - (now_ts - fail_ts)))
            return render_template("login.html", error=f"Too many failed attempts. Try again in {wait_sec}s.", captcha_token=issue_captcha_token(), csrf_token=issue_csrf_token())
        if not verify_csrf_token(request.form.get("csrf_token")):
            error = "Invalid form token."
        if not verify_captcha_token(request.form.get("captcha_token")):
            error = "Captcha required."
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        if user and user["status"] not in ("locked", "deleted") and check_password_hash(user["password"], password):
            cur.execute("SELECT enabled, secret FROM twofa WHERE user_id = ?", (user["id"],))
            twofa_rec = cur.fetchone()
            if twofa_rec and twofa_rec["enabled"]:
                otp = request.form.get("otp")
                if not otp or not pyotp.TOTP(twofa_rec["secret"]).verify(otp, valid_window=1):
                    error = "Invalid 2FA code."
                    conn.close()
                    return render_template("login.html", error=error, captcha_token=issue_captcha_token(), csrf_token=issue_csrf_token())
            session["username"] = username
            ensure_profile(user["id"])
            ensure_default_role(user["id"])
            ensure_twofa_record(user["id"])
            session.pop("login_fail_count", None)
            session.pop("login_fail_ts", None)
        else:
            error = "Invalid credentials."
            fail_count += 1
            session["login_fail_count"] = fail_count
            session["login_fail_ts"] = fail_ts or now_ts
        conn.close()
        if not error:
            return redirect(url_for("index"))
    return render_template("login.html", error=error, username=session.get("username"), captcha_token=issue_captcha_token(), csrf_token=issue_csrf_token())


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


@app.route("/assets/<path:filename>")
def asset_file(filename):
    return send_from_directory(os.path.join(BASE_DIR, "assets"), filename)


@app.route("/")
def index():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM pasts WHERE status = 'active' ORDER BY date DESC, hour DESC"
    )
    pastes = cur.fetchall()
    def is_pinned(val):
        if val is None:
            return False
        s = str(val).lower()
        return s in ("true", "1", "on", "yes")
    pinned = [p for p in pastes if is_pinned(p["pin"])]
    regular = [p for p in pastes if not is_pinned(p["pin"])]
    cur.execute("SELECT paste_id, COUNT(*) as c FROM paste_comments GROUP BY paste_id")
    counts = {row["paste_id"]: row["c"] for row in cur.fetchall()}
    username = session.get("username")
    decorations = fetch_decorations_for_users([p["owner"] for p in pastes])
    cur.execute("SELECT * FROM announcements ORDER BY created_at DESC")
    announcements = cur.fetchall()
    conn.close()
    return render_template(
        "index.html",
        pinned_posts_list=pinned,
        anon_posts_list=regular,
        username=username,
        decorations=decorations,
        effects=NAME_EFFECTS,
        comment_counts=counts,
        announcements=announcements,
    )


@app.route("/searchp")
def search_pastes():
    query = request.args.get("search_query", "").strip()
    option = request.args.get("search_option", "title")
    if not query:
        return redirect(url_for("index"))
    conn = get_db()
    cur = conn.cursor()
    results = []
    if option == "content":
        # scan paste files for substring
        matches = []
        qlower = query.lower()
        for fname in os.listdir(ANON_PASTES):
            try:
                with open(os.path.join(ANON_PASTES, fname), "r", encoding="utf-8") as fh:
                    if qlower in fh.read().lower():
                        matches.append(fname)
            except OSError:
                continue
        if matches:
            placeholders = ",".join("?" for _ in matches)
            cur.execute(f"SELECT * FROM pasts WHERE pastname IN ({placeholders})", matches)
            results = cur.fetchall()
    else:
        like = f"%{query}%"
        cur.execute("SELECT * FROM pasts WHERE pastname LIKE ?", (like,))
        results = cur.fetchall()
    cur.execute("SELECT paste_id, COUNT(*) as c FROM paste_comments GROUP BY paste_id")
    counts = {row["paste_id"]: row["c"] for row in cur.fetchall()}
    decorations = fetch_decorations_for_users([p["owner"] for p in results])
    conn.close()
    return render_template(
        "index.html",
        pinned_posts_list=[],
        anon_posts_list=results,
        username=session.get("username"),
        decorations=decorations,
        effects=NAME_EFFECTS,
        comment_counts=counts,
    )


@app.route("/new")
def new_paste():
    token = issue_captcha_token()
    csrf_token = issue_csrf_token()
    return render_template("new.html", username=session.get("username"), captcha_token=token, csrf_token=csrf_token)


@app.route("/new_paste", methods=["POST"])
def new_paste_form_post():
    username = session.get("username")
    if not verify_csrf_token(request.form.get("csrf_token")):
        token = issue_captcha_token()
        return render_template("new.html", error="Invalid form token.", username=username, captcha_token=token, csrf_token=issue_csrf_token())
    if not verify_captcha_token(request.form.get("captcha_token")):
        token = issue_captcha_token()
        return render_template("new.html", error="Captcha required.", username=username, captcha_token=token, csrf_token=issue_csrf_token())
    ok, remaining = rate_limit("new_paste", 100)
    # Dynamic cooldown: first violation 80s, second 180s
    now_ts = time.time()
    last_ts = session.get("new_paste_last", 0)
    strikes = session.get("new_paste_strikes", 0)
    cooldown = 0
    if strikes >= 1:
        cooldown = 180
    else:
        cooldown = 80
    if now_ts - last_ts < cooldown:
        wait = int(cooldown - (now_ts - last_ts))
        token = issue_captcha_token()
        return render_template("new.html", error=f"Too fast. Wait {wait}s.", username=username, captcha_token=token, csrf_token=issue_csrf_token())
    pasteTitle = str(request.form.get("pasteTitle", "")).replace("/", "%2F")
    pasteContent = request.form.get("pasteContent", "")
    if len(pasteTitle) < 3 or len(pasteTitle) > 25:
        return render_template(
            "new.html",
            error="Title must be between 3 and 25 characters.",
            username=username,
            captcha_token=issue_captcha_token(),
            csrf_token=issue_csrf_token(),
        )
    if len(pasteContent) < 10 or len(pasteContent) > 25000:
        return render_template(
            "new.html",
            error="Content must be between 10 and 25,000 characters.",
            username=username,
            captcha_token=issue_captcha_token(),
            csrf_token=issue_csrf_token(),
        )

    # Record cooldown strike
    session["new_paste_last"] = time.time()
    session["new_paste_strikes"] = min(2, strikes + 1)
    file_path = os.path.join(ANON_PASTES, pasteTitle)
    if os.path.exists(file_path):
        return render_template(
            "new.html",
            error="This title is already taken.",
            username=username,
            captcha_token=issue_captcha_token(),
        )

    current_datetime = current_msk_time()
    date_formatted = current_datetime.strftime("%d-%m-%Y")
    hour_formatted = current_datetime.strftime("%H:%M:%S")
    owner = username if username else "Anonymous"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO pasts (owner, pastname, date, hour, view, pin, ip, status, flag_status, edit_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 'none', 'none')
    """,
        (owner, pasteTitle, date_formatted, hour_formatted, 0, 0, request.remote_addr),
    )
    conn.commit()
    conn.close()

    with open(file_path, "w", encoding="utf-8") as file:
        file.write(pasteContent)

    log_action(get_user_id(username), "paste_create", "paste", pasteTitle, {})
    return redirect(url_for("index"))


def get_user_id(username: str):
    if not username:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row["id"] if row else None


@app.route("/post/<file>")
def post(file):
    filename = os.path.join(ANON_PASTES, file)
    if not os.path.isfile(filename):
        return redirect(url_for("index"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM pasts WHERE pastname = ?",
        (file,),
    )
    past = cur.fetchone()
    if not past:
        conn.close()
        return redirect(url_for("index"))

    cur.execute("UPDATE pasts SET view = view + 1 WHERE pastname = ?", (file,))
    conn.commit()
    cur.execute(
        """
        SELECT pc.*, u.username AS author_username
        FROM paste_comments pc
        LEFT JOIN users u ON u.id = pc.author_user_id
        WHERE paste_id = ?
        ORDER BY created_at DESC
    """,
        (past["id"],),
    )
    comments = cur.fetchall()
    cur.execute(
        """
        SELECT f.*, u.username as raised_name, du.username as decided_name
        FROM flags f
        LEFT JOIN users u ON u.id = f.raised_by
        LEFT JOIN users du ON du.id = f.decided_by
        WHERE f.paste_id = ?
        ORDER BY f.created_at DESC
        LIMIT 1
    """,
        (past["id"],),
    )
    flag_info = cur.fetchone()
    decorations = fetch_decorations_for_users([past["owner"]] + [c["author_username"] for c in comments if c["author_username"]])
    conn.close()

    with open(filename, "r", encoding="utf-8") as filec:
        content = filec.read()

    if request.args.get("raw") in ("1", "true", "yes"):
        return Response(content, mimetype="text/plain; charset=utf-8")

    return render_template(
        "post.html",
        filename=file,
        ownerpast=past["owner"],
        file_content=content,
        creation_date=past["date"],
        creation_time=past["hour"],
        view=past["view"],
        is_pinned=past["pin"],
        comments=comments,
        username=session.get("username"),
        status=highest_role_for_user(get_user_id(session.get("username"))),
        decorations=decorations,
        effects=NAME_EFFECTS,
        flag_info=flag_info,
        csrf_token=get_csrf_token(),
        captcha_token=issue_captcha_token(),
    )


@app.route("/post/<file>/add_comment", methods=["POST"])
def add_comment(file):
    username = session.get("username")
    user_id = get_user_id(username) if username else None
    ip_address = request.remote_addr

    if not verify_csrf_token(request.form.get("csrf_token")):
        return abort(403)
    if not verify_captcha_token(request.form.get("captcha_token")):
        return redirect(url_for("post", file=file, error="Captcha required."))
    ok, remaining = rate_limit("comment", 10)
    if not ok:
        return redirect(url_for("post", file=file, error=f"Too fast. Wait {int(remaining)}s."))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM pasts WHERE pastname = ?", (file,))
    past = cur.fetchone()
    if not past:
        conn.close()
        return redirect(url_for("post", file=file))

    comment = request.form.get("comment", "").strip()
    if not comment:
        conn.close()
        return redirect(url_for("post", file=file))

    now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        """
        INSERT INTO paste_comments (paste_id, author_user_id, comment, created_at, ip, status_snapshot)
        VALUES (?, ?, ?, ?, ?, ?)
    """,
        (
            past["id"],
            user_id,
            comment,
            now,
            ip_address,
            highest_role_for_user(user_id) if user_id else "anonymous",
        ),
    )
    conn.commit()
    conn.close()
    log_action(user_id, "paste_comment_create", "paste", past["id"], {"comment": comment[:50]})
    return redirect(url_for("post", file=file))


@app.route("/post/<file>/flag", methods=["POST"])
def flag_paste(file):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    if not verify_csrf_token(request.form.get("csrf_token")):
        return abort(403)
    if not verify_captcha_token(request.form.get("captcha_token")):
        return redirect(url_for("post", file=file, error="Captcha required."))
    ok, remaining = rate_limit("flag", 30)
    if not ok:
        return redirect(url_for("post", file=file, error=f"Too fast. Wait {int(remaining)}s."))
    reason = request.form.get("reason")
    if reason not in FLAG_REASONS:
        return abort(400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, owner FROM pasts WHERE pastname = ?", (file,))
    past = cur.fetchone()
    if not past:
        conn.close()
        return redirect(url_for("index"))
    cur.execute("SELECT status FROM flags WHERE paste_id = ? ORDER BY created_at DESC LIMIT 1", (past["id"],))
    existing = cur.fetchone()
    if existing and existing["status"] == "pending":
        conn.close()
        return redirect(url_for("post", file=file))
    status = "pending"
    now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        """
        INSERT INTO flags (paste_id, raised_by, role_snapshot, reason, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """,
        (past["id"], user["id"], highest_role_for_user(user["id"]), reason, status, now),
    )
    cur.execute("UPDATE pasts SET flag_status = ? WHERE id = ?", ("pending", past["id"]))
    conn.commit()
    conn.close()
    log_action(user["id"], "flag_submit", "paste", past["id"], {"reason": reason})
    owner_id = get_user_id(past["owner"])
    if owner_id:
        create_notification(owner_id, "flag_submitted", {"paste": file, "reason": reason})
    return redirect(url_for("post", file=file))


@app.route("/post/<file>/pin", methods=["POST"])
def pin_paste(file):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    
    # Check if user is ADMIN or FOUNDER
    user_role = highest_role_for_user(user["id"])
    if user_role not in ["admin", "founder"]:
        return redirect(url_for("post", file=file))
    
    conn = get_db()
    cur = conn.cursor()
    
    # Get current pin status
    cur.execute("SELECT pin FROM pasts WHERE pastname = ?", (file,))
    result = cur.fetchone()
    if not result:
        conn.close()
        return redirect(url_for("index"))
    
    current_val = result[0]
    # Stored as TEXT/INT mix; normalize to int(0/1)
    if current_val in (None, ""):
        current_pin = 0
    elif isinstance(current_val, (int, float)):
        current_pin = 1 if int(current_val) else 0
    else:
        current_pin = 1 if str(current_val).lower() in ("1", "true", "t", "yes", "on") else 0
    new_pin = 0 if current_pin else 1
    
    # Update pin status
    cur.execute("UPDATE pasts SET pin = ? WHERE pastname = ?", (new_pin, file))
    conn.commit()
    conn.close()
    
    log_action(user["id"], "paste_pin" if new_pin else "paste_unpin", "user", user["id"], {"file": file})
    return redirect(url_for("post", file=file))


@app.route("/post/<file>/delete", methods=["POST"])
def delete_paste_route(file):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    role = highest_role_for_user(user["id"])
    if role not in ["admin", "founder"]:
        return redirect(url_for("post", file=file))
    if not verify_csrf_token(request.form.get("csrf_token")):
        abort(400)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM pasts WHERE pastname = ?", (file,))
    row = cur.fetchone()
    if row:
        cur.execute("DELETE FROM pasts WHERE pastname = ?", (file,))
        conn.commit()
        delete_paste_file(file)
        log_action(user["id"], "paste_delete_hard", "paste", row["id"], {"file": file})
    conn.close()
    return redirect(url_for("index"))


@app.route("/redeem/<code>")
def redeem(code):
    token = issue_csrf_token()
    return render_template("redeem.html", code=code, csrf_token=token, username=session.get("username"))


@app.route("/api/claimGift", methods=["POST"])
def api_claim_gift():
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "error": "Please login."}), 401
    if not verify_csrf_token(request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")):
        return jsonify({"success": False, "error": "Invalid form token."}), 400
    ok, remaining = rate_limit("claim_gift", 10)
    if not ok:
        return jsonify({"success": False, "error": f"Too fast. Wait {int(remaining)}s."}), 429
    payload = request.get_json(silent=True) or {}
    code = payload.get("code") or request.form.get("code")
    if not code:
        return jsonify({"success": False, "error": "Gift code required."}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM gift_codes WHERE code = ?", (code,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Invalid gift code."}), 400
    # Expiration
    expires_at = row.get("expires_at") if isinstance(row, dict) else row["expires_at"]
    if expires_at:
        try:
            if datetime.fromisoformat(expires_at) < datetime.utcnow():
                conn.close()
                return jsonify({"success": False, "error": "Gift expired."}), 400
        except Exception:
            pass
    max_uses = row["max_uses"] if row["max_uses"] is not None else 1
    if max_uses <= 0:
        conn.close()
        return jsonify({"success": False, "error": "Gift already claimed."}), 400
    now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
    new_uses = max_uses - 1 if max_uses is not None else 0
    cur.execute(
        "UPDATE gift_codes SET used_by = ?, used_at = ?, max_uses = ? WHERE id = ?",
        (user["id"], now, new_uses, row["id"]),
    )
    conn.commit()
    conn.close()
    log_action(user["id"], "gift_redeem", "gift", row["id"], {"code": code, "reward": row["reward"]})
    return jsonify({"success": True, "message": f"Gift redeemed: {row['reward'] or 'reward applied'}"})


@app.route("/admin/gifts", methods=["GET", "POST"])
def admin_gifts():
    user = get_current_user()
    if not user or highest_role_for_user(user["id"]) not in ("admin", "founder"):
        return redirect(url_for("index"))
    conn = get_db()
    cur = conn.cursor()
    message = None
    if request.method == "POST":
        if not verify_csrf_token(request.form.get("csrf_token")):
            conn.close()
            return abort(403)
        code = request.form.get("code", "").strip()
        reward = request.form.get("reward", "").strip()
        max_uses = int(request.form.get("max_uses", "1") or 1)
        expires = request.form.get("expires_at", "").strip()
        if not code:
            message = "Code required"
        else:
            cur.execute(
                "INSERT OR REPLACE INTO gift_codes (code, reward, max_uses, expires_at) VALUES (?, ?, ?, ?)",
                (code, reward, max_uses, expires or None),
            )
            conn.commit()
            message = "Saved"
    cur.execute("SELECT * FROM gift_codes ORDER BY created_at DESC")
    gifts = cur.fetchall()
    conn.close()
    return render_template("admin_gifts.html", csrf_token=get_csrf_token(), gifts=gifts, message=message)

@app.route("/post/<file>/edit", methods=["GET", "POST"])
def request_edit(file):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    csrf_token = get_csrf_token()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM pasts WHERE pastname = ?", (file,))
    past = cur.fetchone()
    if not past:
        conn.close()
        return redirect(url_for("index"))
    if past["owner"] != user["username"] and not has_role(user["id"], "mod"):
        conn.close()
        return abort(403)
    filename = os.path.join(ANON_PASTES, file)
    if not os.path.isfile(filename):
        conn.close()
        return redirect(url_for("index"))
    with open(filename, "r", encoding="utf-8") as fh:
        current_content = fh.read()
    if request.method == "POST":
        if not verify_csrf_token(request.form.get("csrf_token")):
            conn.close()
            return abort(403)
        if not verify_captcha_token(request.form.get("captcha_token")):
            conn.close()
            return render_template("edit_request.html", filename=file, content=current_content, error="Captcha required.", reason=request.form.get("reason",""), username=session.get("username"), captcha_token=issue_captcha_token(), csrf_token=issue_csrf_token())
        ok, remaining = rate_limit("edit_request", 100)
        if not ok:
            conn.close()
            return render_template("edit_request.html", filename=file, content=current_content, error=f"Too fast. Wait {int(remaining)}s.", reason=request.form.get("reason",""), username=session.get("username"), captcha_token=issue_captcha_token(), csrf_token=issue_csrf_token())
        new_content = request.form.get("content", "")
        reason = request.form.get("reason", "")
        if len(new_content) < 10:
            conn.close()
            return render_template("edit_request.html", filename=file, content=current_content, error="Content too short", reason=reason, username=session.get("username"), captcha_token=issue_captcha_token(), csrf_token=issue_csrf_token())
        now = current_msk_time().strftime("%Y%m%d%H%M%S")
        edit_path = os.path.join(EDIT_STORE, f"{file}_{now}.txt")
        with open(edit_path, "w", encoding="utf-8") as ef:
            ef.write(new_content)
        cur.execute(
            """
            INSERT INTO edit_requests (paste_id, requested_by, reason, new_body_path, status, created_at)
            VALUES (?, ?, ?, ?, 'pending', ?)
        """,
            (past["id"], user["id"], reason, edit_path.replace(BASE_DIR, "").replace("\\", "/"), current_msk_time().strftime("%Y-%m-%d %H:%M:%S")),
        )
        cur.execute("UPDATE pasts SET edit_status = ? WHERE id = ?", ("pending", past["id"]))
        conn.commit()
        conn.close()
        log_action(user["id"], "edit_submit", "paste", past["id"], {"reason": reason})
        return redirect(url_for("post", file=file))
    conn.close()
    return render_template("edit_request.html", filename=file, content=current_content, error=None, reason="", username=session.get("username"), captcha_token=issue_captcha_token(), csrf_token=csrf_token)


@app.route("/users")
def users():
    query = request.args.get("q", "").strip()
    conn = get_db()
    cur = conn.cursor()
    if query:
        like = f"%{query}%"
        cur.execute(
            """
            SELECT u.id, u.username, u.datejoin, p.username_color, p.name_effect
            FROM users u
            LEFT JOIN profiles p ON p.user_id = u.id
            WHERE u.username LIKE ?
            ORDER BY u.id DESC
        """,
            (like,),
        )
    else:
        cur.execute(
            """
            SELECT u.id, u.username, u.datejoin, p.username_color, p.name_effect
            FROM users u
            LEFT JOIN profiles p ON p.user_id = u.id
            ORDER BY u.id DESC
        """
        )
    rows = cur.fetchall()
    usernames = [r["username"] for r in rows]
    # counts
    pastes_count = {}
    comments_count = {}
    if usernames:
        placeholders = ",".join("?" for _ in usernames)
        cur.execute(
            f"SELECT owner, COUNT(*) c FROM pasts WHERE owner IN ({placeholders}) GROUP BY owner",
            usernames,
        )
        for r in cur.fetchall():
            pastes_count[r["owner"]] = r["c"]
        cur.execute(
            f"""
            SELECT p.owner, COUNT(pc.id) c
            FROM pasts p
            JOIN paste_comments pc ON pc.paste_id = p.id
            WHERE p.owner IN ({placeholders})
            GROUP BY p.owner
        """,
            usernames,
        )
        for r in cur.fetchall():
            comments_count[r["owner"]] = r["c"]
    conn.close()
    role_order = ["admin", "founder", "manager", "mod", "council", "clique", "rich", "vip", "criminal", "companion", "fbi", "user"]
    grouped = {role: [] for role in role_order}
    for row in rows:
        top = highest_role_for_user(row["id"])
        grouped.setdefault(top, []).append(
            {
                "id": row["id"],
                "username": row["username"],
                "datejoin": row["datejoin"],
                "username_color": row["username_color"],
                "name_effect": row["name_effect"],
                "role": top,
                "pastes": pastes_count.get(row["username"], 0),
                "comments": comments_count.get(row["username"], 0),
            }
        )
    total_count = sum(len(v) for v in grouped.values())
    return render_template(
        "users.html",
        grouped=grouped,
        username=session.get("username"),
        decorations=fetch_decorations_for_users([u["username"] for u in rows]),
        effects=NAME_EFFECTS,
        q=query,
        total=total_count,
    )


def fetch_decorations_for_users(usernames):
    clean = [u for u in usernames if u]
    if not clean:
        return {}
    conn = get_db()
    cur = conn.cursor()
    placeholders = ",".join("?" for _ in clean)
    cur.execute(
        f"""
        SELECT u.username, p.username_color, p.name_effect, p.glow_enabled, r.role
        FROM users u
        LEFT JOIN profiles p ON p.user_id = u.id
        LEFT JOIN roles r ON r.user_id = u.id
        WHERE u.username IN ({placeholders})
    """,
        clean,
    )
    rows = cur.fetchall()
    conn.close()
    decorations = {}
    for row in rows:
        current = decorations.get(row["username"], {"roles": set()})
        color = row["username_color"] or "#FFD700"
        effect = row["name_effect"]
        glow = bool(row["glow_enabled"]) if "glow_enabled" in row.keys() else False
        current["color"] = color
        current["name_effect"] = effect
        current["glow_enabled"] = glow
        if row["role"]:
            current["roles"].add(row["role"])
        decorations[row["username"]] = current
    # apply defaults for rich and above
    for uname, deco in decorations.items():
        roles = deco.get("roles", set())
        if not roles:
            continue
        top = max(roles, key=lambda r: ROLE_LEVELS.get(r, 0))
        if not deco.get("name_effect") and ROLE_LEVELS.get(top, 0) >= ROLE_LEVELS["rich"]:
            deco["name_effect"] = "gold" if top == "rich" else "sparkle-blue"
    return decorations


@app.route("/user/<username>")
def user_profile(username):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    if not user:
        conn.close()
        return redirect(url_for("index"))

    ensure_profile(user["id"])
    ensure_staff_badge(user["id"])

    cur.execute("SELECT * FROM profiles WHERE user_id = ?", (user["id"],))
    profile = cur.fetchone()
    if profile:
        profile = dict(profile)

    cur.execute("SELECT * FROM pasts WHERE owner = ? ORDER BY date DESC, hour DESC", (username,))
    pastes = cur.fetchall()
    paste_ids = [p["id"] for p in pastes]
    paste_comments_count = {}
    if paste_ids:
        placeholders = ",".join("?" for _ in paste_ids)
        cur.execute(
            f"SELECT paste_id, COUNT(*) as c FROM paste_comments WHERE paste_id IN ({placeholders}) GROUP BY paste_id",
            paste_ids,
        )
        for r in cur.fetchall():
            paste_comments_count[r["paste_id"]] = r["c"]

    cur.execute(
        """
        SELECT pc.*, au.username as author_username
        FROM profile_comments pc
        LEFT JOIN users au ON au.id = pc.author_user_id
        WHERE profile_user_id = ?
        ORDER BY created_at DESC
    """,
        (user["id"],),
    )
    profile_comments = cur.fetchall()
    decorations = fetch_decorations_for_users([username] + [c["author_username"] for c in profile_comments if c["author_username"]])
    badges = get_badges_for_user(user["id"])
    cur.execute("SELECT * FROM sessions WHERE user_id = ? ORDER BY last_seen DESC", (user["id"],))
    sessions_list = cur.fetchall()
    followers_count, following_count = get_follow_counts(user["id"])
    current_user = get_current_user()
    following_state = False
    if current_user:
        following_state = is_following(current_user["id"], user["id"])
    top_role = highest_role_for_user(user["id"])

    conn.close()

    # Admin/founder: show counts but do not allow opening lists
    allow_follow_lists = top_role not in ("admin", "founder")
    hide_follow_counts = False
    play_profile_music = bool(profile.get("music_path")) and top_role in ("admin", "founder", "rich")

    return render_template(
        "profile.html",
        user=user,
        profile=profile,
        pastes=pastes,
        paste_comments_count=paste_comments_count,
        comments=profile_comments,
        badges=badges,
        username=session.get("username"),
        decorations=decorations,
        effects=NAME_EFFECTS,
        top_role=highest_role_for_user(user["id"]),
        hide_follow_counts=hide_follow_counts,
        allow_follow_lists=allow_follow_lists,
        followers_count=followers_count,
        following_count=following_count,
        is_following=following_state,
        captcha_token=issue_captcha_token(),
        csrf_token=get_csrf_token(),
        play_profile_music=play_profile_music,
    )


@app.route("/profile/comment/<username>", methods=["POST"])
def add_profile_comment(username):
    commenter = get_current_user()
    if not commenter:
        return redirect(url_for("login"))
    if not verify_csrf_token(request.form.get("csrf_token")):
        return abort(403)
    if not verify_captcha_token(request.form.get("captcha_token")):
        return redirect(url_for("user_profile", username=username))
    ok, remaining = rate_limit("profile_comment", 10)
    if not ok:
        return redirect(url_for("user_profile", username=username))
    target_id = get_user_id(username)
    if not target_id:
        return redirect(url_for("user_profile", username=username))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT allow_profile_comments FROM profiles WHERE user_id = ?", (target_id,))
    allow = cur.fetchone()
    if allow and allow["allow_profile_comments"] == 0:
        conn.close()
        return redirect(url_for("user_profile", username=username))
    comment = request.form.get("comment", "").strip()
    if not comment:
        conn.close()
        return redirect(url_for("user_profile", username=username))
    now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        """
        INSERT INTO profile_comments (profile_user_id, author_user_id, comment, created_at, ip, status_snapshot)
        VALUES (?, ?, ?, ?, ?, ?)
    """,
        (
            target_id,
            commenter["id"] if commenter else None,
            comment,
            now,
            request.remote_addr,
            highest_role_for_user(commenter["id"]) if commenter else "anonymous",
        ),
    )
    conn.commit()
    conn.close()
    log_action(commenter["id"] if commenter else None, "profile_comment_create", "user", target_id, {"comment": comment[:50]})
    return redirect(url_for("user_profile", username=username))


@app.route("/follow/<username>", methods=["POST"])
def toggle_follow(username):
    current = get_current_user()
    if not current:
        return jsonify({"success": False, "error": "auth"}), 401
    if not verify_csrf_token(request.form.get("csrf_token")):
        return jsonify({"success": False, "error": "csrf"}), 403

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    target = cur.fetchone()
    if not target:
        conn.close()
        return jsonify({"success": False, "error": "not_found"}), 404
    target_top = highest_role_for_user(target["id"])
    if target_top in ("admin", "founder"):
        conn.close()
        return jsonify({"success": False, "error": "forbidden"}), 403

    if target["id"] == current["id"]:
        conn.close()
        return jsonify({"success": False, "error": "self"}), 400

    cur.execute(
        "SELECT id FROM followers WHERE follower_id = ? AND target_id = ?",
        (current["id"], target["id"]),
    )
    existing = cur.fetchone()
    now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
    if existing:
        cur.execute("DELETE FROM followers WHERE id = ?", (existing["id"],))
        following = False
    else:
        cur.execute(
            "INSERT INTO followers (follower_id, target_id, created_at) VALUES (?, ?, ?)",
            (current["id"], target["id"], now),
        )
        following = True
    conn.commit()

    cur.execute("SELECT COUNT(*) FROM followers WHERE target_id = ?", (target["id"],))
    followers = cur.fetchone()[0]
    # how many people target is following
    cur.execute("SELECT COUNT(*) FROM followers WHERE follower_id = ?", (target["id"],))
    target_following_count = cur.fetchone()[0]
    conn.close()

    return jsonify(
        {
            "success": True,
            "following": following,
            "followers": followers,
            "following_count": target_following_count,
        }
    )


@app.route("/followers/<username>/<kind>", methods=["GET"])
def follower_list(username, kind):
    if kind not in ("followers", "following"):
        return abort(400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    target = cur.fetchone()
    if not target:
        conn.close()
        return abort(404)
    top_role = highest_role_for_user(target["id"])
    # Admin/founder: показываем числа, но не отдаём список
    if top_role in ("admin", "founder"):
        conn.close()
        return abort(403)
    if kind == "followers":
        cur.execute(
            """
            SELECT u.id, u.username
            FROM followers f
            JOIN users u ON u.id = f.follower_id
            WHERE f.target_id = ?
            ORDER BY u.username COLLATE NOCASE
            """,
            (target["id"],),
        )
    else:
        cur.execute(
            """
            SELECT u.id, u.username
            FROM followers f
            JOIN users u ON u.id = f.target_id
            WHERE f.follower_id = ?
            ORDER BY u.username COLLATE NOCASE
            """,
            (target["id"],),
        )
    rows = cur.fetchall()
    conn.close()
    data = []
    for r in rows:
        role = highest_role_for_user(r["id"])
        data.append({"username": r["username"], "role": role})
    return jsonify({"success": True, "kind": kind, "list": data})


@app.route("/vpn_check", methods=["GET", "POST"])
def vpn_check():
    if request.method == "POST":
        if not verify_csrf_token(request.form.get("csrf_token")):
            return abort(403)
        token = request.form.get("cf-turnstile-response")
        if not token:
            return render_template(
                "vpn_check.html",
                csrf_token=get_csrf_token(),
                sitekey=TURNSTILE_SITE_KEY,
                error="Verification failed. Please try again.",
                success=False,
            )
        try:
            verify_resp = requests.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={
                    "secret": TURNSTILE_SECRET_KEY,
                    "response": token,
                    "remoteip": request.remote_addr,
                },
                timeout=6,
            ).json()
            if not verify_resp.get("success"):
                return render_template(
                    "vpn_check.html",
                    csrf_token=get_csrf_token(),
                    sitekey=TURNSTILE_SITE_KEY,
                    error="Verification failed. Please try again.",
                    success=False,
                )
        except Exception:
            return render_template(
                "vpn_check.html",
                csrf_token=get_csrf_token(),
                sitekey=TURNSTILE_SITE_KEY,
                error="Verification failed. Please try again.",
                success=False,
            )
        session["vpn_passed"] = True
        session["human_verified_once"] = True
        session["human_ok_until"] = time.time() + 20 * 60  # 20 minutes
        nxt = session.pop("vpn_next", "/")
        return render_template(
            "vpn_check.html",
            csrf_token=get_csrf_token(),
            sitekey=TURNSTILE_SITE_KEY,
            success=True,
            next_url=nxt or "/",
        )

    return render_template(
        "vpn_check.html",
        csrf_token=get_csrf_token(),
        sitekey=TURNSTILE_SITE_KEY,
        error=None,
        success=False,
    )


@app.route("/settings", methods=["GET", "POST"])
def settings():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    csrf_token = get_csrf_token()
    ensure_profile(user["id"])
    ensure_twofa_record(user["id"])
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM profiles WHERE user_id = ?", (user["id"],))
    profile = cur.fetchone()
    if profile:
        profile = dict(profile)
    cur.execute("SELECT * FROM twofa WHERE user_id = ?", (user["id"],))
    twofa_rec = cur.fetchone()
    badges = get_badges_for_user(user["id"])
    cur.execute("SELECT * FROM sessions WHERE user_id = ? ORDER BY last_seen DESC", (user["id"],))
    sessions_list = cur.fetchall()
    error = None

    if request.method == "POST":
        action = request.form.get("action")
        if action == "enable_2fa":
            secret = request.form.get("secret") or twofa_rec["secret"] or pyotp.random_base32()
            otp = request.form.get("otp")
            if not otp or not pyotp.TOTP(secret).verify(otp, valid_window=1):
                error = "Invalid OTP code."
            else:
                now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
                cur.execute(
                    "UPDATE twofa SET enabled = 1, authed = 1, secret = ?, updated_at = ? WHERE user_id = ?",
                    (secret, now, user["id"]),
                )
                conn.commit()
                log_action(user["id"], "2fa_enable", "user", user["id"], {})
                return redirect(url_for("settings"))
            twofa_rec = dict(twofa_rec)
            twofa_rec["secret"] = secret
        elif action == "disable_2fa":
            now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
            cur.execute(
                "UPDATE twofa SET enabled = 0, authed = 0, secret = NULL, updated_at = ? WHERE user_id = ?",
                (now, user["id"]),
            )
            conn.commit()
            log_action(user["id"], "2fa_disable", "user", user["id"], {})
            return redirect(url_for("settings"))
        else:
            bio = request.form.get("bio", "")
            username_color = request.form.get("username_color", "#FFD700")
            bio_animation = request.form.get("bio_animation_type")
            allow_comments = 1 if request.form.get("allow_comments") == "on" else 0
            chosen_effect = request.form.get("name_effect")

            top_role = highest_role_for_user(user["id"])
            bg_file = request.files.get("background")
            banner_file = request.files.get("banner")
            avatar_file = request.files.get("avatar")
            music_file = request.files.get("music")
            background_path = profile["background_path"]
            banner_path = profile["banner_path"]
            avatar_path = profile["avatar_path"]
            music_path = profile.get("music_path")
            background_scope = profile["background_scope"]

            try:
                if bg_file and bg_file.filename:
                    if ROLE_LEVELS.get(top_role, 0) < ROLE_LEVELS["rich"]:
                        raise ValueError("Backgrounds available for Rich+ only.")
                    allow_gif = ROLE_LEVELS.get(top_role, 0) >= ROLE_LEVELS["admin"]
                    saved = save_upload(bg_file, user["id"], "background", allow_gif)
                    remove_upload(background_path)
                    background_path = saved
                    background_scope = "owner"
                if banner_file and banner_file.filename:
                    saved = save_upload(banner_file, user["id"], "banner", True)
                    remove_upload(banner_path)
                    banner_path = saved
                if avatar_file and avatar_file.filename:
                    saved = save_upload(avatar_file, user["id"], "avatar", True)
                    remove_upload(avatar_path)
                    avatar_path = saved
                if music_file and music_file.filename:
                    # Music — only founder/admin
                    if highest_role_for_user(user["id"]) not in ["admin", "founder"]:
                        raise ValueError("Music available for Admin/Founder only.")
                    saved = save_upload(music_file, user["id"], "music", False, ALLOWED_MUSIC_EXT, MAX_MUSIC_BYTES)
                    remove_upload(music_path)
                    music_path = saved
            except ValueError as ve:
                error = str(ve)

            if top_role == "rich":
                chosen_effect = "gold"
            elif ROLE_LEVELS.get(top_role, 0) > ROLE_LEVELS["rich"]:
                if chosen_effect not in NAME_EFFECTS:
                    chosen_effect = "sparkle-blue"
            else:
                chosen_effect = None

            badge_color_updates = []
            if not error and badges:
                for b in badges:
                    key = f"badge_color_{b['id']}"
                    new_color = request.form.get(key, "").strip()
                    if new_color and new_color.startswith("#") and len(new_color) in (4, 7):
                        badge_color_updates.append((new_color, b["id"], user["id"]))
            if not error:
                now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
                cur.execute(
                    """
                    UPDATE profiles
                    SET bio = ?, bio_animation_type = ?, username_color = ?, allow_profile_comments = ?,
                        name_effect = ?, glow_enabled = ?, updated_at = ?, avatar_path = ?, banner_path = ?, background_path = ?, background_scope = ?, music_path = ?
                    WHERE user_id = ?
                """,
                    (
                        bio,
                        bio_animation if ROLE_LEVELS.get(top_role, 0) >= ROLE_LEVELS["rich"] else None,
                        username_color,
                        allow_comments,
                        chosen_effect,
                        1
                        if request.form.get("glow_enabled") == "on"
                        and ROLE_LEVELS.get(top_role, 0) >= ROLE_LEVELS["rich"]
                        else 0,
                        now,
                        avatar_path,
                        banner_path,
                        background_path,
                        background_scope,
                        music_path,
                        user["id"],
                    ),
                )
                if badge_color_updates:
                    cur.executemany(
                        "UPDATE badges SET color = ? WHERE id = ? AND user_id = ?",
                        badge_color_updates,
                    )
                conn.commit()
                log_action(user["id"], "profile_update", "user", user["id"], {})
                return redirect(url_for("settings"))

    conn.close()
    new_secret = twofa_rec["secret"] or pyotp.random_base32()
    return render_template(
        "settings.html",
        profile=profile,
        user=user,
        error=error,
        effects=NAME_EFFECTS,
        top_role=highest_role_for_user(user["id"]),
        twofa=twofa_rec,
        new_secret=new_secret,
        badges=badges,
        username=session.get("username"),
        ROLE_LEVELS=ROLE_LEVELS,
        sessions_list=sessions_list,
        current_ip=request.remote_addr,
        csrf_token=csrf_token,
    )


@app.route("/settings/remove/<kind>", methods=["POST"])
def remove_media(kind):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    if kind not in ("avatar", "banner", "background", "music"):
        return abort(400)
    if not verify_csrf_token(request.form.get("csrf_token", "")):
        return abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM profiles WHERE user_id = ?", (user["id"],))
    profile = cur.fetchone()
    if kind == "music":
        path = profile["music_path"]
    else:
        path = profile[f"{kind}_path"]
    remove_upload(path or "")
    
    # Safe SQL query - use column mapping instead of string formatting
    column_map = {
        "avatar": "avatar_path",
        "banner": "banner_path", 
        "background": "background_path",
        "music": "music_path",
    }
    column_name = column_map[kind]
    
    cur.execute(
        f"UPDATE profiles SET {column_name} = NULL, updated_at = ? WHERE user_id = ?",
        (current_msk_time().strftime("%Y-%m-%d %H:%M:%S"), user["id"]),
    )
    conn.commit()
    conn.close()
    log_action(user["id"], f"media_remove_{kind}", "user", user["id"], {})
    return redirect(url_for("settings"))


def user_can_see_admin():
    user = get_current_user()
    if not user:
        return False
    # Only Admin / Founder get the admin panel; lower roles (manager / mod / council) are excluded.
    return has_role(user["id"], "admin") or has_role(user["id"], "founder")


def user_can_see_council():
    user = get_current_user()
    if not user:
        return False
    return has_role(user["id"], "council")


@app.route("/notifications")
def notifications():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)
    )
    items = cur.fetchall()
    conn.close()
    return render_template(
        "notifications.html",
        notifications=items,
        username=session.get("username"),
    )


@app.route("/notifications/read", methods=["POST"])
def mark_notifications_read():
    user = get_current_user()
    if not user:
        return abort(403)
    if not verify_csrf_token(request.form.get("csrf_token")):
        return abort(403)
    ok, remaining = rate_limit("notifications_read", 5)
    if not ok:
        return abort(429)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user["id"],))
    conn.commit()
    conn.close()
    if request.accept_mimetypes["application/json"]:
        return jsonify({"ok": True})
    return redirect(url_for("notifications"))


@app.route("/tos")
def tos():
    with open(os.path.join(DATA, "tos"), "r", encoding="utf-8") as file:
        filec = file.read()
    return render_template("tos.html", file_content=filec, username=session.get("username"))


@app.route("/hoa")
def hall_of_loosers():
    with open(os.path.join(DATA, "hol.json"), "r", encoding="utf-8") as file:
        data = json.load(file)
    return render_template(
        "hoa.html",
        loosers_list=data.get("loosers", []),
        username=session.get("username"),
    )


@app.route("/upgrades")
def upgrades():
    return render_template("upgrades.html", username=session.get("username"))


@app.route("/my-flags")
def my_flags():
    """Show flag history for the current user (for council+ who raise flags)."""
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT f.*, p.pastname, du.username AS decided_name
        FROM flags f
        JOIN pasts p ON p.id = f.paste_id
        LEFT JOIN users du ON du.id = f.decided_by
        WHERE f.raised_by = ?
        ORDER BY f.created_at DESC
        """,
        (user["id"],),
    )
    flags = cur.fetchall()
    conn.close()
    return render_template("flag_history.html", flags=flags, username=session.get("username"))


@app.route("/council")
def council_dashboard():
    user = get_current_user()
    if not user or not has_role(user["id"], "council"):
        return abort(403)
    is_moderator = can_decide_flag(user["id"])
    conn = get_db()
    cur = conn.cursor()
    pending_flags = pending_edits = 0
    recent_flags = []
    recent_edits = []
    my_flags = []
    if is_moderator:
        cur.execute("SELECT COUNT(*) as c FROM flags WHERE status = 'pending'")
        pending_flags = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM edit_requests WHERE status = 'pending'")
        pending_edits = cur.fetchone()["c"]
        cur.execute(
            """
            SELECT f.*, p.pastname, ru.username as raised_name
            FROM flags f
            JOIN pasts p ON p.id = f.paste_id
            JOIN users ru ON ru.id = f.raised_by
            ORDER BY f.created_at DESC
            LIMIT 5
        """
        )
        recent_flags = cur.fetchall()
        cur.execute(
            """
            SELECT e.*, p.pastname, u.username as requester
            FROM edit_requests e
            JOIN pasts p ON p.id = e.paste_id
            JOIN users u ON u.id = e.requested_by
            ORDER BY e.created_at DESC
            LIMIT 5
        """
        )
        recent_edits = cur.fetchall()
    else:
        cur.execute(
            """
            SELECT f.*, p.pastname, du.username as decided_name
            FROM flags f
            JOIN pasts p ON p.id = f.paste_id
            LEFT JOIN users du ON du.id = f.decided_by
            WHERE f.raised_by = ?
            ORDER BY f.created_at DESC
            LIMIT 10
        """,
            (user["id"],),
        )
        my_flags = cur.fetchall()
    conn.close()
    return render_template(
        "council_dashboard.html",
        pending_flags=pending_flags,
        pending_edits=pending_edits,
        recent_flags=recent_flags,
        recent_edits=recent_edits,
        my_flags=my_flags,
        can_moderate=is_moderator,
        username=session.get("username"),
    )


@app.route("/council/flags")
def council_flags():
    user = get_current_user()
    if not user or not can_decide_flag(user["id"]):
        return abort(403)
    csrf_token = get_csrf_token()
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT f.*, p.pastname, ru.username as raised_name, du.username as decided_name
        FROM flags f
        JOIN pasts p ON p.id = f.paste_id
        JOIN users ru ON ru.id = f.raised_by
        LEFT JOIN users du ON du.id = f.decided_by
        ORDER BY CASE WHEN f.status = 'pending' THEN 0 ELSE 1 END, f.created_at DESC
    """
    )
    flags = cur.fetchall()
    conn.close()
    return render_template("council_flags.html", flags=flags, username=session.get("username"), csrf_token=csrf_token)


@app.route("/council/edits")
def council_edits():
    user = get_current_user()
    if not user or not can_decide_edit(user["id"]):
        return abort(403)
    csrf_token = get_csrf_token()
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT e.*, p.pastname, u.username as requester, d.username as decider
        FROM edit_requests e
        JOIN pasts p ON p.id = e.paste_id
        JOIN users u ON u.id = e.requested_by
        LEFT JOIN users d ON d.id = e.decided_by
        ORDER BY CASE WHEN e.status = 'pending' THEN 0 ELSE 1 END, e.created_at DESC
    """
    )
    edits = cur.fetchall()
    conn.close()
    return render_template("council_edits.html", edits=edits, username=session.get("username"), csrf_token=csrf_token)

@app.route("/admin")
def admin_dashboard():
    user = get_current_user()
    if not user or highest_role_for_user(user["id"]) not in ("admin", "founder"):
        _bump_admin_probe()
        return abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM users")
    user_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM flags WHERE status = 'pending'")
    flag_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM edit_requests WHERE status = 'pending'")
    edit_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM logs")
    log_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM announcements")
    ann_count = cur.fetchone()["c"]
    conn.close()
    return render_template(
        "admin_dashboard.html",
        user_count=user_count,
        flag_count=flag_count,
        edit_count=edit_count,
        log_count=log_count,
        ann_count=ann_count,
        username=session.get("username"),
    )

@app.route("/admin/announcements", methods=["GET", "POST"])
def admin_announcements():
    user = get_current_user()
    if not user or highest_role_for_user(user["id"]) not in ("admin", "founder"):
        return abort(403)
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        if not verify_csrf_token(request.form.get("csrf_token")):
            conn.close()
            return abort(403)
        action = request.form.get("action")
        if action == "create":
            title = request.form.get("title", "").strip()
            body = request.form.get("body", "").strip()
            link = request.form.get("link", "").strip()
            color = request.form.get("color", "#25ABEE").strip() or "#25ABEE"
            if title and body:
                cur.execute(
                    "INSERT INTO announcements (title, body, link, color, created_at) VALUES (?, ?, ?, ?, ?)",
                    (title, body, link, color, current_msk_time().strftime("%Y-%m-%d %H:%M:%S")),
                )
                conn.commit()
        elif action == "update":
            ann_id = request.form.get("id")
            title = request.form.get("title", "").strip()
            body = request.form.get("body", "").strip()
            link = request.form.get("link", "").strip()
            color = request.form.get("color", "#25ABEE").strip() or "#25ABEE"
            if ann_id and title and body:
                cur.execute(
                    "UPDATE announcements SET title = ?, body = ?, link = ?, color = ? WHERE id = ?",
                    (title, body, link, color, ann_id),
                )
                conn.commit()
        elif action == "delete":
            ann_id = request.form.get("id")
            if ann_id:
                cur.execute("DELETE FROM announcements WHERE id = ?", (ann_id,))
                conn.commit()
    cur.execute("SELECT * FROM announcements ORDER BY created_at DESC")
    announcements = cur.fetchall()
    conn.close()
    return render_template(
        "admin_announcements.html",
        announcements=announcements,
        username=session.get("username"),
        csrf_token=get_csrf_token(),
    )


@app.route("/admin/flags")
def admin_flags():
    user = get_current_user()
    if not user or not can_decide_flag(user["id"]):
        return abort(403)
    csrf_token = get_csrf_token()
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT f.*, p.pastname, ru.username as raised_name, du.username as decided_name
        FROM flags f
        JOIN pasts p ON p.id = f.paste_id
        JOIN users ru ON ru.id = f.raised_by
        LEFT JOIN users du ON du.id = f.decided_by
        ORDER BY f.created_at DESC
    """
    )
    flags = cur.fetchall()
    conn.close()
    return render_template(
        "admin_flags.html",
        flags=flags,
        username=session.get("username"),
        csrf_token=csrf_token,
    )


@app.route("/admin/flags/<int:flag_id>/decide", methods=["POST"])
def decide_flag(flag_id):
    user = get_current_user()
    if not user or not can_decide_flag(user["id"]):
        return abort(403)
    if not verify_csrf_token(request.form.get("csrf_token")):
        return abort(403)
    decision = request.form.get("decision")
    if decision not in ("approved", "denied"):
        return abort(400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM flags WHERE id = ?", (flag_id,))
    flag = cur.fetchone()
    if not flag or flag["status"] != "pending":
        conn.close()
        return redirect(url_for("admin_flags"))
    cur.execute("SELECT pastname FROM pasts WHERE id = ?", (flag["paste_id"],))
    paste_row = cur.fetchone()
    now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        "UPDATE flags SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?",
        (decision, user["id"], now, flag_id),
    )
    if decision == "approved":
        cur.execute(
            "UPDATE pasts SET flag_status = ?, status = ?, deleted_by = ?, deleted_reason = ? WHERE id = ?",
            (decision, "deleted", user["username"], "Flag approved", flag["paste_id"]),
        )
        if paste_row and paste_row["pastname"]:
            delete_paste_file(paste_row["pastname"])
    else:
        cur.execute("UPDATE pasts SET flag_status = ? WHERE id = ?", (decision, flag["paste_id"]))
    conn.commit()
    conn.close()
    create_notification(flag["raised_by"], "flag_decision", {"decision": decision, "flag_id": flag_id})
    log_action(user["id"], "flag_decide", "flag", flag_id, {"decision": decision})
    target = "admin_flags" if user_can_see_admin() else "council_flags"
    return redirect(url_for(target))


@app.route("/admin/edits")
def admin_edits():
    user = get_current_user()
    if not user or not can_decide_edit(user["id"]):
        return abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT e.*, p.pastname, u.username as requester, d.username as decider
        FROM edit_requests e
        JOIN pasts p ON p.id = e.paste_id
        JOIN users u ON u.id = e.requested_by
        LEFT JOIN users d ON d.id = e.decided_by
        ORDER BY e.created_at DESC
    """
    )
    edits = cur.fetchall()
    conn.close()
    return render_template("admin_edits.html", edits=edits, username=session.get("username"))


@app.route("/admin/edits/<int:edit_id>/decide", methods=["POST"])
def decide_edit(edit_id):
    user = get_current_user()
    if not user or not can_decide_edit(user["id"]):
        return abort(403)
    if not verify_csrf_token(request.form.get("csrf_token")):
        return abort(403)
    decision = request.form.get("decision")
    if decision not in ("approved", "denied"):
        return abort(400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM edit_requests WHERE id = ?", (edit_id,))
    edit = cur.fetchone()
    if not edit or edit["status"] != "pending":
        conn.close()
        return redirect(url_for("admin_edits"))
    now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
    if decision == "approved":
        new_path = os.path.join(BASE_DIR, edit["new_body_path"].lstrip("/"))
        with open(new_path, "r", encoding="utf-8") as nf:
            new_body = nf.read()
        # write into paste
        cur.execute("SELECT pastname FROM pasts WHERE id = ?", (edit["paste_id"],))
        paste_row = cur.fetchone()
        if paste_row:
            paste_file = os.path.join(ANON_PASTES, paste_row["pastname"])
            with open(paste_file, "w", encoding="utf-8") as pf:
                pf.write(new_body)
        cur.execute("UPDATE pasts SET edit_status = ? WHERE id = ?", ("approved", edit["paste_id"]))
    else:
        cur.execute("UPDATE pasts SET edit_status = ? WHERE id = ?", ("denied", edit["paste_id"]))
    cur.execute(
        "UPDATE edit_requests SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?",
        (decision, user["id"], now, edit_id),
    )
    conn.commit()
    conn.close()
    create_notification(edit["requested_by"], "edit_decision", {"decision": decision, "edit_id": edit_id})
    log_action(user["id"], "edit_decide", "edit_request", edit_id, {"decision": decision})
    target = "admin_edits" if user_can_see_admin() else "council_edits"
    return redirect(url_for(target))


@app.route("/admin/blacklist", methods=["GET", "POST"])
def admin_blacklist():
    user = get_current_user()
    if not user or highest_role_for_user(user["id"]) not in ("admin", "founder"):
        return abort(403)
    conn = get_db()
    cur = conn.cursor()
    error = None
    if request.method == "POST":
        bl_user = request.form.get("username")
        bl_ip = request.form.get("ip")
        reason = request.form.get("reason", "")
        target_id = get_user_id(bl_user) if bl_user else None
        now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            "INSERT INTO blacklist (user_id, ip, reason, created_at) VALUES (?, ?, ?, ?)",
            (target_id, bl_ip, reason, now),
        )
        conn.commit()
        log_action(user["id"], "blacklist_add", "user", target_id, {"ip": bl_ip, "reason": reason})
    cur.execute(
        """
        SELECT b.*, u.username
        FROM blacklist b
        LEFT JOIN users u ON u.id = b.user_id
        ORDER BY b.created_at DESC
    """
    )
    entries = cur.fetchall()
    conn.close()
    return render_template("admin_blacklist.html", entries=entries, error=error, username=session.get("username"), csrf_token=get_csrf_token())


@app.route("/admin/logs")
def admin_logs():
    user = get_current_user()
    if not user or highest_role_for_user(user["id"]) not in ("admin", "founder"):
        return abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT l.*, u.username as actor
        FROM logs l
        LEFT JOIN users u ON u.id = l.actor_id
        ORDER BY l.created_at DESC
        LIMIT 200
    """
    )
    logs = cur.fetchall()
    conn.close()
    return render_template("admin_logs.html", logs=logs, username=session.get("username"))


@app.route("/admin/spam", methods=["GET", "POST"])
def admin_spam():
    user = get_current_user()
    if not user or highest_role_for_user(user["id"]) not in ("admin", "founder"):
        return abort(403)
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        target = request.form.get("username")
        minutes = int(request.form.get("minutes") or 0)
        reason = request.form.get("reason", "")
        target_id = get_user_id(target)
        if target_id:
            expires = None
            if minutes > 0:
                expires = (current_msk_time() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
            cur.execute(
                "INSERT INTO chat_mutes (user_id, muted_by, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (
                    target_id,
                    user["id"],
                    reason,
                    current_msk_time().strftime("%Y-%m-%d %H:%M:%S"),
                    expires,
                ),
            )
            conn.commit()
            create_notification(target_id, "mute", {"reason": reason, "expires_at": expires})
            log_action(user["id"], "chat_mute", "user", target_id, {"reason": reason, "expires_at": expires})
    cur.execute(
        """
        SELECT m.*, u.username as muted_name, a.username as muted_by_name
        FROM chat_mutes m
        JOIN users u ON u.id = m.user_id
        JOIN users a ON a.id = m.muted_by
        ORDER BY m.created_at DESC
    """
    )
    mutes = cur.fetchall()
    conn.close()
    return render_template("admin_spam.html", mutes=mutes, username=session.get("username"), csrf_token=get_csrf_token())


@app.route("/admin/chat")
def admin_chat():
    user = get_current_user()
    if not user or highest_role_for_user(user["id"]) not in ("admin", "founder"):
        return abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT m.id, m.body, m.created_at, u.username, u.id as user_id
        FROM chat_messages m
        LEFT JOIN users u ON u.id = m.user_id
        ORDER BY m.created_at DESC
        LIMIT 100
        """
    )
    messages = cur.fetchall()
    conn.close()
    return render_template(
        "admin_chat.html",
        messages=messages,
        username=session.get("username"),
        csrf_token=get_csrf_token(),
    )

@app.route("/admin/user/<int:user_id>", methods=["GET", "POST"])
def admin_user_detail(user_id):
    admin = get_current_user()
    if not admin or highest_role_for_user(admin["id"]) not in ("admin", "founder"):
        return abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    target = cur.fetchone()
    if not target:
        conn.close()
        return redirect(url_for("admin_dashboard"))
    ensure_profile(user_id)
    ensure_twofa_record(user_id)
    error = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "generate_reset":
            token = secrets.token_urlsafe(24)
            expires = (current_msk_time() + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
            cur.execute(
                "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
                (user_id, token, expires),
            )
            conn.commit()
            log_action(admin["id"], "password_reset_generate", "user", user_id, {})
        elif action == "lock":
            cur.execute("UPDATE users SET status = 'locked' WHERE id = ?", (user_id,))
            conn.commit()
            log_action(admin["id"], "account_lock", "user", user_id, {})
        elif action == "delete":
            cur.execute("UPDATE users SET status = 'deleted' WHERE id = ?", (user_id,))
            conn.commit()
            log_action(admin["id"], "account_delete", "user", user_id, {})
        elif action == "grant_role":
            role = request.form.get("role")
            reason = request.form.get("reason", "")
            if role in ROLE_LEVELS:
                now = current_msk_time().strftime("%Y-%m-%d %H:%M:%S")
                cur.execute(
                    "INSERT INTO roles (user_id, role, granted_by, reason, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, role, admin["id"], reason, now),
                )
                conn.commit()
                create_notification(user_id, "role_grant", {"role": role, "reason": reason})
                log_action(admin["id"], "role_grant", "user", user_id, {"role": role})
                ensure_staff_badge(user_id)
            else:
                error = "Invalid role"
        elif action == "grant_badge":
            name = request.form.get("badge_name", "").strip()
            color = request.form.get("badge_color", "#202225").strip() or "#202225"
            icon = request.form.get("badge_icon", "").strip() or None
            tooltip = request.form.get("badge_tooltip", "").strip() or name
            if not name:
                error = "Badge name required"
            else:
                add_badge(user_id, name, color=color, icon=icon, tooltip=tooltip, system=False, granted_by=admin["id"])
                log_action(admin["id"], "badge_grant", "user", user_id, {"badge": name})
                create_notification(user_id, "badge_grant", {"badge": name})
    cur.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,))
    profile = cur.fetchone()
    cur.execute("SELECT * FROM roles WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    roles = cur.fetchall()
    cur.execute("SELECT * FROM badges WHERE user_id = ? ORDER BY created_at ASC", (user_id,))
    badges = cur.fetchall()
    cur.execute("SELECT * FROM order_history WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    orders = cur.fetchall()
    cur.execute("SELECT * FROM username_history WHERE user_id = ? ORDER BY changed_at DESC", (user_id,))
    uname_hist = cur.fetchall()
    cur.execute("SELECT * FROM password_reset_tokens WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    resets = cur.fetchall()
    cur.execute("SELECT * FROM twofa WHERE user_id = ?", (user_id,))
    twofa_rec = cur.fetchone()
    cur.execute("SELECT * FROM sessions WHERE user_id = ? ORDER BY last_seen DESC", (user_id,))
    sessions_list = cur.fetchall()
    conn.close()
    return render_template(
        "admin_user.html",
        target=target,
        profile=profile,
        roles=roles,
        badges=badges,
        orders=orders,
        uname_hist=uname_hist,
        resets=resets,
        twofa=twofa_rec,
        sessions_list=sessions_list,
        error=error,
        username=session.get("username"),
    )


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM password_reset_tokens WHERE token = ?", (token,))
    rec = cur.fetchone()
    if not rec:
        conn.close()
        return "Invalid token", 400
    if rec["used_at"]:
        conn.close()
        return "Token already used", 400
    exp = datetime.strptime(rec["expires_at"], "%Y-%m-%d %H:%M:%S")
    if current_msk_time().replace(tzinfo=None) > exp:
        conn.close()
        return "Token expired", 400
    error = None
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if len(pwd) < 6:
            error = "Password too short"
        else:
            hashed = generate_password_hash(pwd)
            cur.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, rec["user_id"]))
            cur.execute(
                "UPDATE password_reset_tokens SET used_at = ? WHERE id = ?",
                (current_msk_time().strftime("%Y-%m-%d %H:%M:%S"), rec["id"]),
            )
            conn.commit()
            conn.close()
            return "Password reset successful"
    conn.close()
    return render_template("reset.html", token=token, error=error)


@app.route("/api/chat/messages")
def get_chat_messages():
    ok, remaining = rate_limit("chat_messages", 2)
    if not ok:
        return jsonify({"success": False, "error": "Slow down"}), 429
    try:
        conn = sqlite3.connect("database.db")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Get last 50 messages with user info
        cur.execute("""
            SELECT 
                m.user_id as userID,
                COALESCE(u.username, 'Unknown') as displayName,
                m.body as content,
                m.created_at as createdAt,
                m.id as messageID,
                COALESCE(p.username_color, '#2a9fd6') as usernameColor,
                COALESCE(p.name_effect, NULL) as nameEffect,
                (SELECT role FROM roles WHERE user_id = m.user_id ORDER BY 
                    CASE role 
                        WHEN 'founder' THEN 1
                        WHEN 'admin' THEN 2
                        WHEN 'manager' THEN 3
                        WHEN 'mod' THEN 4
                        WHEN 'council' THEN 5
                        WHEN 'vip' THEN 6
                        WHEN 'rich' THEN 7
                        ELSE 999
                    END LIMIT 1) as role
            FROM chat_messages m
            LEFT JOIN users u ON m.user_id = u.id
            LEFT JOIN profiles p ON m.user_id = p.user_id
            ORDER BY m.created_at DESC
            LIMIT 50
        """)
        
        messages = [dict(row) for row in cur.fetchall()]
        messages.reverse()
        
        conn.close()
        
        return jsonify({"success": True, "messages": messages})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/chat/send", methods=["POST"])
def send_chat_message():
    user = get_current_user()
    
    if not user:
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    # CSRF for JSON requests
    if not verify_json_csrf():
        return jsonify({"success": False, "error": "CSRF"}), 403
    
    data = request.get_json() or {}
    content = (data.get("content", "") or "").strip()
    
    if not content:
        return jsonify({"success": False, "error": "Empty message"}), 400
    
    if len(content) > 200:
        return jsonify({"success": False, "error": "Message too long"}), 400
    
    # ============== ANTI-SPAM & ANTI-BYPASS SYSTEM ==============
    
    # Extract URLs first (multiple patterns)
    url_patterns = [
        r'https?://[^\s<>\[\]{}|"\']+',  # Standard URLs
        r'www\.[^\s<>\[\]{}|"\']+',       # www URLs
        r'(?:http|https)?:?/?/?[^\s]*(?:ghost|doxbin|pastebin|anonfiles|gofile)[^\s]*',  # Specific bypass patterns
    ]
    
    all_urls = []
    for pattern in url_patterns:
        urls = re.findall(pattern, content.lower())
        all_urls.extend(urls)
    
    # Remove duplicates
    all_urls = list(set(all_urls))
    
    # ===== RULE 1: ONLY ADMINS CAN SEND LINKS =====
    if all_urls:  # If message contains ANY links
        is_admin = has_role(user['id'], 'admin') or has_role(user['id'], 'founder')
        if not is_admin:
            return jsonify({"success": False, "error": "Only admins can send links"}), 403
    
    # ===== RULE 2: BLACKLISTED DOMAINS (for admins too) =====
    BLACKLIST = [
        # Pastebin-like
        'ghost.ru', 'ghostbin', 'ghostbin.fun', 'doxbin', 'pastebin', 'rentry', 
        'hastebin', 'termbin', 'privatepaste', 'dpaste', 'paste2code',
        # File hosts
        'anonfiles', 'gofile', 'mega', 'mediafire', 'sendspace', 'zippyshare',
        # Other
        'discord.gg', 'telegram.me', 't.me', 'tg://',
        # Social
        'instagram', 'tiktok', 'youtube.com', 'twitch.tv', 'rumble',
        # VK/CIS
        'vkontakte', 'vk.com', 'ok.ru', 'odnoklassniki'
    ]
    
    # Normalize text to detect bypass attempts
    def normalize_for_detection(text):
        # Remove common bypass characters
        text = text.lower()
        # Replace variations
        text = text.replace(' ', '').replace('-', '').replace('_', '').replace('[', '').replace(']', '')
        text = text.replace('(', '').replace(')', '').replace('{', '').replace('}', '')
        # Replace common bypass: . → dot, / → slash
        text = text.replace('(dot)', '.').replace('[dot]', '.').replace('(slash)', '/')
        text = text.replace('[slash]', '/').replace('(.))', '.').replace('(://)', '://')
        return text
    
    normalized_content = normalize_for_detection(content)
    
    # Check for blacklisted domains (even admins cannot send these)
    spam_detected = False
    spam_reason = None
    
    for url in all_urls:
        url_lower = url.lower()
        for blocked in BLACKLIST:
            if blocked in url_lower:
                spam_detected = True
                spam_reason = f"Blacklisted domain: {blocked}"
                break
        if spam_detected:
            break
    
    # Additionally check normalized version for bypass attempts
    if not spam_detected:
        for blocked in BLACKLIST:
            blocked_normalized = normalize_for_detection(blocked)
            if blocked_normalized in normalized_content and len(blocked_normalized) > 3:
                spam_detected = True
                spam_reason = f"Bypass attempt detected: {blocked}"
                break
    
    # Count total URLs
    url_count = len(all_urls)
    
    # Mute for 5 minutes if spam detected
    if spam_detected:
        try:
            conn = sqlite3.connect("database.db")
            cur = conn.cursor()
            mute_until = (current_msk_time() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            cur.execute("""
                INSERT INTO chat_mutes (user_id, muted_until, reason)
                VALUES (?, ?, ?)
            """, (user['id'], mute_until, spam_reason))
            conn.commit()
            conn.close()
        except:
            pass
        
        return jsonify({"success": False, "error": f"Message blocked: {spam_reason}. Muted for 5 minutes."}), 403
    
    try:
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        
        # Check if user is muted
        cur.execute("""
            SELECT muted_until FROM chat_mutes 
            WHERE user_id = ? AND muted_until > datetime('now')
        """, (user['id'],))
        mute = cur.fetchone()
        if mute:
            return jsonify({"success": False, "error": "You are muted"}), 403
        
        # Rate limiting: check if user sent message in last 3 seconds
        cur.execute("""
            SELECT created_at FROM chat_messages 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT 1
        """, (user['id'],))
        
        last_msg = cur.fetchone()
        current_time = current_msk_time()
        if last_msg:
            try:
                # Parse stored time (naive datetime) and make it aware with MSK timezone
                last_time = datetime.strptime(last_msg[0], "%Y-%m-%d %H:%M:%S")
                last_time = pytz.timezone("Europe/Moscow").localize(last_time)
                if (current_time - last_time).total_seconds() < 3:
                    conn.close()
                    return jsonify({"success": False, "error": "Please wait before sending another message"}), 429
            except:
                pass  # If time parsing fails, allow the message
        
        # Check for link spam (5+ URLs in one message)
        if url_count >= 5:
            mute_until = (current_time + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            cur.execute("""
                INSERT INTO chat_mutes (user_id, muted_until, reason)
                VALUES (?, ?, ?)
            """, (user['id'], mute_until, 'Too many links'))
            conn.commit()
            conn.close()
            
            return jsonify({"success": False, "error": "Muted for 5 minutes (excessive links)"}), 403
        
        # Insert message
        cur.execute("""
            INSERT INTO chat_messages (user_id, body, created_at, ip)
            VALUES (?, ?, ?, ?)
        """, (user['id'], content, current_time.strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr))
        
        conn.commit()
        conn.close()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/chat/delete/<int:message_id>", methods=["POST"])
def delete_chat_message(message_id):
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    if not verify_json_csrf():
        return jsonify({"success": False, "error": "CSRF"}), 403
    
    # Check if staff (only admin / founder may delete)
    top_role = highest_role_for_user(user['id'])
    if top_role not in ['admin', 'founder']:
        return jsonify({"success": False, "error": "Not authorized"}), 403
    
    try:
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("DELETE FROM chat_messages WHERE id = ?", (message_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/chat/ban", methods=["POST"])
def ban_chat_user():
    user = get_current_user()
    if not user:
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    # Check if staff
    top_role = highest_role_for_user(user['id'])
    if top_role not in ['admin', 'founder']:
        return jsonify({"success": False, "error": "Not authorized"}), 403
    
    data = request.get_json() or {}
    user_id = data.get("userID")
    
    if not user_id:
        return jsonify({"success": False, "error": "User ID required"}), 400
    
    try:
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        # Mark user as banned or add to banlist (implement as needed)
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/flag/<int:flag_id>/cancel", methods=["POST"])
def cancel_flag(flag_id):
    user = get_current_user()
    if not user:
        return abort(403)
    if not verify_csrf_token(request.form.get("csrf_token")):
        return abort(403)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM flags WHERE id = ?", (flag_id,))
    flag = cur.fetchone()
    if not flag or flag["status"] != "pending":
        conn.close()
        return redirect(request.referrer or url_for("index"))
    # Only flag owner or admin/founder
    if flag["raised_by"] != user["id"] and not has_role(user["id"], "admin") and not has_role(user["id"], "founder"):
        conn.close()
        return abort(403)
    cur.execute("DELETE FROM flags WHERE id = ?", (flag_id,))
    # If no other pending flags for this paste, reset flag_status
    cur.execute("SELECT COUNT(*) as c FROM flags WHERE paste_id = ? AND status = 'pending'", (flag["paste_id"],))
    if cur.fetchone()["c"] == 0:
        cur.execute("UPDATE pasts SET flag_status = NULL WHERE id = ?", (flag["paste_id"],))
    conn.commit()
    conn.close()
    log_action(user["id"], "flag_cancel", "flag", flag_id, {})
    return redirect(request.referrer or url_for("post", file=flag.get("pastname", "")))


if __name__ == "__main__":
    run_migrations()
    app.run(host="0.0.0.0", port=8080, debug=False)
