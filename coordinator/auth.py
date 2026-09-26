"""
HIVEMIND auth: one owner, password + 2FA, device sessions, QR phone pairing.

  * password hashed with scrypt (stdlib)
  * TOTP 2FA (RFC 6238, works with any authenticator app) with replay protection
  * single-use recovery codes for when your phone is lost
  * server-side sessions in sqlite, HttpOnly + SameSite=Strict cookies, idle + absolute expiry
  * CSRF token required on every state-changing request made with a session cookie
  * brute-force lockout per IP and globally
  * one-time, 5-minute QR pairing links for phones (never contain the hive key)

Machines (nodes, scripts, /v1 clients) keep using the hive key as a bearer token.
People use sessions. Nothing ever accepts a key in the URL.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from pathlib import Path

from flask import Blueprint, abort, g, jsonify, redirect, render_template, request

import segno

bp = Blueprint("auth", __name__)

SESSION_COOKIE = "hive_session"
IDLE_SECONDS = float(os.environ.get("HIVE_SESSION_IDLE_HOURS", 72)) * 3600
ABSOLUTE_SECONDS = float(os.environ.get("HIVE_SESSION_MAX_DAYS", 30)) * 86400
PAIR_SECONDS = 300
LOCKOUT_FAILS, LOCKOUT_WINDOW = 5, 900      # 5 misses per IP per 15 min
GLOBAL_FAILS = 25                           # across all IPs per 15 min
MIN_PASSWORD = 10

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,   -- public id, safe to show
    token_hash  TEXT UNIQUE NOT NULL,
    csrf        TEXT NOT NULL,
    device      TEXT,
    ip          TEXT,
    user_agent  TEXT,
    created     REAL NOT NULL,
    last_seen   REAL NOT NULL,
    expires     REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS pair_tokens (
    token_hash  TEXT PRIMARY KEY,
    created     REAL NOT NULL,
    expires     REAL NOT NULL,
    used        INTEGER DEFAULT 0
);
"""

_db = _tx = None
_hive_key = ""
_setup_token_file = None
_fails = []                 # (time, ip)
_fail_lock = threading.Lock()
_pending_setup = {}         # setup token -> {"pw": hash, "secret": b32, "t": time}


def init(app, db, tx, hive_key, base_dir):
    global _db, _tx, _hive_key, _setup_token_file
    _db, _tx, _hive_key = db, tx, hive_key
    _setup_token_file = Path(base_dir) / "setup_token.txt"
    db().executescript(SCHEMA)
    app.register_blueprint(bp)
    app.after_request(security_headers)
    if not owner_exists():
        ensure_setup_token()


def now():
    return time.time()


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


# --------------------------------------------------------------------------- settings

def get_setting(key, default=None):
    r = _db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return json.loads(r["value"]) if r else default


def set_setting(c, key, value):
    c.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
              (key, json.dumps(value)))


def owner_exists():
    return bool(get_setting("password_hash"))


def ensure_setup_token():
    """First-run claim token. Printed to the console and written next to the db so only
    someone with access to the coordinator machine can create the owner account."""
    if _setup_token_file.exists() and _setup_token_file.read_text().strip():
        return _setup_token_file.read_text().strip()
    t = secrets.token_urlsafe(18)
    _setup_token_file.write_text(t + "\n")
    try:
        os.chmod(_setup_token_file, 0o600)
    except OSError:
        pass
    return t


def reset_owner(tx):
    """CLI recovery: wipes the owner, all sessions and pairing tokens. Nodes are untouched."""
    with tx() as c:
        c.execute("DELETE FROM settings WHERE key IN ('password_hash','totp_secret','totp_last','recovery')")
        c.execute("DELETE FROM sessions")
        c.execute("DELETE FROM pair_tokens")


# --------------------------------------------------------------------------- crypto

def hash_password(pw):
    salt = secrets.token_bytes(16)
    n, r, p = 2 ** 15, 8, 1
    h = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${h.hex()}"


def check_password(pw, stored):
    try:
        _, n, r, p, salt, h = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=64 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(got.hex(), h)
    except (ValueError, AttributeError):
        return False


def totp_at(secret_b32, counter):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return f"{(struct.unpack('>I', mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def totp_match(secret_b32, code, at=None):
    """returns the matching time-step counter (±1 step of clock drift) or None"""
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != 6:
        return None
    t = int((at or now()) // 30)
    for c in (t - 1, t, t + 1):
        if hmac.compare_digest(totp_at(secret_b32, c), code):
            return c
    return None


def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def otpauth_uri(secret):
    return f"otpauth://totp/HIVEMIND:owner?secret={secret}&issuer=HIVEMIND&algorithm=SHA1&digits=6&period=30"


def qr_svg(data):
    return segno.make(data, error="m").svg_inline(scale=5, border=2, dark="#111", light="#fff")


def new_recovery_codes():
    codes = ["-".join(secrets.token_hex(2) for _ in range(3)) for _ in range(8)]
    return codes, [sha(c) for c in codes]


# --------------------------------------------------------------------------- brute force

def client_ip():
    # CF-Connecting-IP is only trustworthy behind a cloudflare tunnel; otherwise use the socket peer
    if os.environ.get("HIVE_BEHIND_CLOUDFLARE") == "1":
        return request.headers.get("CF-Connecting-IP") or request.remote_addr
    return request.remote_addr


def locked_out(ip):
    cutoff = now() - LOCKOUT_WINDOW
    with _fail_lock:
        _fails[:] = [f for f in _fails if f[0] >= cutoff]
        mine = sum(1 for _, fip in _fails if fip == ip)
        return mine >= LOCKOUT_FAILS or len(_fails) >= GLOBAL_FAILS


def record_fail(ip):
    with _fail_lock:
        _fails.append((now(), ip))


def clear_fails(ip):
    with _fail_lock:
        _fails[:] = [f for f in _fails if f[1] != ip]


# --------------------------------------------------------------------------- sessions

def secure_cookies():
    if os.environ.get("HIVE_SECURE_COOKIES") == "1":
        return True
    return request.is_secure


def create_session(c, device):
    token = secrets.token_urlsafe(32)
    sid = "ses_" + secrets.token_hex(8)
    t = now()
    c.execute("""INSERT INTO sessions (id, token_hash, csrf, device, ip, user_agent, created, last_seen, expires)
                 VALUES (?,?,?,?,?,?,?,?,?)""",
              (sid, sha(token), secrets.token_urlsafe(24), (device or "browser")[:60], client_ip(),
               (request.headers.get("User-Agent") or "")[:200], t, t, t + ABSOLUTE_SECONDS))
    return token


def set_session_cookie(resp, token):
    resp.set_cookie(SESSION_COOKIE, token, max_age=int(ABSOLUTE_SECONDS), httponly=True,
                    samesite="Strict", secure=secure_cookies(), path="/")
    return resp


def current_session():
    """the valid session for this request, or None. cached on flask.g"""
    if "hive_session" in g:
        return g.hive_session
    g.hive_session = None
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    s = _db().execute("SELECT * FROM sessions WHERE token_hash=?", (sha(token),)).fetchone()
    t = now()
    if not s:
        return None
    if s["expires"] < t or s["last_seen"] + IDLE_SECONDS < t:
        with _tx() as c:
            c.execute("DELETE FROM sessions WHERE id=?", (s["id"],))
        return None
    if t - s["last_seen"] > 60:  # don't write on every request
        with _tx() as c:
            c.execute("UPDATE sessions SET last_seen=?, ip=? WHERE id=?", (t, client_ip(), s["id"]))
    g.hive_session = dict(s)
    return g.hive_session


def bearer_ok():
    a = request.headers.get("Authorization", "")
    k = a[7:].strip() if a.lower().startswith("bearer ") else request.headers.get("X-Hive-Key", "")
    return bool(k) and hmac.compare_digest(k.encode(), _hive_key.encode())


def require_user():
    """people (session cookie + csrf on writes) or machines (hive key bearer)."""
    if bearer_ok():
        return
    s = current_session()
    if not s:
        abort(401)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get("X-Hive-CSRF", "")
        if not sent or not hmac.compare_digest(sent, s["csrf"]):
            abort(403)


def require_session():
    """only a logged-in person, never a bare key (for secrets and account changes)"""
    s = current_session()
    if not s:
        abort(401)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get("X-Hive-CSRF", "")
        if not sent or not hmac.compare_digest(sent, s["csrf"]):
            abort(403)
    return s


def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'self'; object-src 'none'")
    if request.cookies.get(SESSION_COOKIE) or request.path.startswith("/api/auth"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


def body():
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        abort(400)
    return d


def public_base():
    base = os.environ.get("HIVE_PUBLIC_URL", "").strip().rstrip("/")
    return base or request.host_url.rstrip("/")


# --------------------------------------------------------------------------- pages

@bp.get("/login")
def login_page():
    if not owner_exists():
        return redirect("/setup")
    if current_session():
        return redirect("/")
    return render_template("auth.html", mode="login")


@bp.get("/setup")
def setup_page():
    if owner_exists():
        return redirect("/login")
    return render_template("auth.html", mode="setup")


@bp.get("/pair")
def pair_page():
    # GET never consumes the token (link previewers and camera apps prefetch URLs)
    return render_template("auth.html", mode="pair")


# --------------------------------------------------------------------------- api

@bp.post("/api/auth/setup/start")
def setup_start():
    if owner_exists():
        abort(409)
    d = body()
    ip = client_ip()
    if locked_out(ip):
        return jsonify({"error": "too many attempts, wait 15 minutes"}), 429
    token = str(d.get("setup_token") or "").strip()
    expected = _setup_token_file.read_text().strip() if _setup_token_file.exists() else ""
    if not expected or not hmac.compare_digest(token, expected):
        record_fail(ip)
        return jsonify({"error": "wrong setup token (it's in coordinator/setup_token.txt)"}), 403
    pw = str(d.get("password") or "")
    if len(pw) < MIN_PASSWORD:
        return jsonify({"error": f"password must be at least {MIN_PASSWORD} characters"}), 400
    secret = new_totp_secret()
    _pending_setup.clear()
    _pending_setup[token] = {"pw": hash_password(pw), "secret": secret, "t": now()}
    uri = otpauth_uri(secret)
    return jsonify({"otpauth": uri, "secret": secret, "qr": qr_svg(uri)})


@bp.post("/api/auth/setup/finish")
def setup_finish():
    if owner_exists():
        abort(409)
    d = body()
    if locked_out(client_ip()):
        return jsonify({"error": "too many attempts, wait 15 minutes"}), 429
    token = str(d.get("setup_token") or "").strip()
    p = _pending_setup.get(token)
    if not p or now() - p["t"] > 900:
        return jsonify({"error": "setup expired, start again"}), 400
    counter = totp_match(p["secret"], d.get("code"))
    if counter is None:
        record_fail(client_ip())
        return jsonify({"error": "that code didn't match. check your phone's clock and try the current code"}), 403
    codes, hashes = new_recovery_codes()
    with _tx() as c:
        set_setting(c, "password_hash", p["pw"])
        set_setting(c, "totp_secret", p["secret"])
        set_setting(c, "totp_last", counter)
        set_setting(c, "recovery", hashes)
        session_token = create_session(c, str(d.get("device") or "setup browser"))
    _pending_setup.clear()
    try:
        _setup_token_file.unlink()
    except OSError:
        pass
    return set_session_cookie(jsonify({"ok": True, "recovery_codes": codes}), session_token)


def verify_second_factor(c, code):
    """TOTP code (replay-protected) or a single-use recovery code. call inside a tx."""
    code = str(code or "").strip().lower()
    secret = get_setting("totp_secret")
    counter = totp_match(secret, code) if secret else None
    if counter is not None:
        if counter <= int(get_setting("totp_last", -1)):
            return False  # already used this code
        set_setting(c, "totp_last", counter)
        return True
    hashes = get_setting("recovery", [])
    h = sha(code)
    if h in hashes:
        hashes.remove(h)
        set_setting(c, "recovery", hashes)
        return True
    return False


@bp.post("/api/auth/login")
def login():
    if not owner_exists():
        return jsonify({"error": "no owner yet, go to /setup"}), 409
    d = body()
    ip = client_ip()
    if locked_out(ip):
        return jsonify({"error": "too many attempts, wait 15 minutes"}), 429
    ok_pw = check_password(str(d.get("password") or ""), get_setting("password_hash", ""))
    with _tx() as c:
        # the 2fa code is only consumed when the password is right, so a guesser can't burn codes
        ok_2fa = verify_second_factor(c, d.get("code")) if ok_pw else False
        if not (ok_pw and ok_2fa):
            record_fail(ip)
            return jsonify({"error": "wrong password or code"}), 401
        token = create_session(c, str(d.get("device") or "browser"))
    clear_fails(ip)
    return set_session_cookie(jsonify({"ok": True, "recovery_left": len(get_setting("recovery", []))}), token)


@bp.post("/api/auth/logout")
def logout():
    s = require_session()
    with _tx() as c:
        c.execute("DELETE FROM sessions WHERE id=?", (s["id"],))
    resp = jsonify({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@bp.get("/api/auth/me")
def me():
    s = current_session()
    if not s:
        return jsonify({"logged_in": False, "owner_exists": owner_exists()}), 401
    return jsonify({"logged_in": True, "csrf": s["csrf"], "session_id": s["id"], "device": s["device"],
                    "recovery_left": len(get_setting("recovery", [])), "public_url": public_base()})


@bp.get("/api/auth/hive-key")
def hive_key():
    require_session()
    return jsonify({"hive_key": _hive_key})


@bp.get("/api/auth/sessions")
def sessions():
    s = require_session()
    rows = _db().execute("SELECT id, device, ip, user_agent, created, last_seen, expires FROM sessions "
                         "ORDER BY last_seen DESC").fetchall()
    return jsonify([{**dict(r), "current": r["id"] == s["id"]} for r in rows])


@bp.delete("/api/auth/sessions/<sid>")
def revoke(sid):
    require_session()
    with _tx() as c:
        c.execute("DELETE FROM sessions WHERE id=?", (sid,))
    return jsonify({"ok": True})


@bp.post("/api/auth/sessions/revoke-others")
def revoke_others():
    s = require_session()
    with _tx() as c:
        c.execute("DELETE FROM sessions WHERE id != ?", (s["id"],))
    return jsonify({"ok": True})


@bp.post("/api/auth/password")
def change_password():
    require_session()
    d = body()
    ip = client_ip()
    if locked_out(ip):
        return jsonify({"error": "too many attempts, wait 15 minutes"}), 429
    new = str(d.get("new_password") or "")
    if len(new) < MIN_PASSWORD:
        return jsonify({"error": f"password must be at least {MIN_PASSWORD} characters"}), 400
    with _tx() as c:
        if not check_password(str(d.get("current_password") or ""), get_setting("password_hash", "")) \
                or not verify_second_factor(c, d.get("code")):
            record_fail(ip)
            return jsonify({"error": "wrong password or code"}), 401
        set_setting(c, "password_hash", hash_password(new))
    return jsonify({"ok": True})


@bp.post("/api/auth/recovery/regenerate")
def regenerate_recovery():
    require_session()
    d = body()
    with _tx() as c:
        if not verify_second_factor(c, d.get("code")):
            record_fail(client_ip())
            return jsonify({"error": "wrong code"}), 401
        codes, hashes = new_recovery_codes()
        set_setting(c, "recovery", hashes)
    return jsonify({"recovery_codes": codes})


@bp.post("/api/auth/pair")
def pair_create():
    require_session()
    token = secrets.token_urlsafe(24)
    t = now()
    with _tx() as c:
        c.execute("DELETE FROM pair_tokens WHERE expires < ? OR used = 1", (t,))
        c.execute("INSERT INTO pair_tokens (token_hash, created, expires) VALUES (?,?,?)",
                  (sha(token), t, t + PAIR_SECONDS))
    url = f"{public_base()}/pair#{token}"   # fragment: never sent to servers, never logged
    return jsonify({"url": url, "qr": qr_svg(url), "expires_in": PAIR_SECONDS})


@bp.post("/api/auth/pair/claim")
def pair_claim():
    d = body()
    ip = client_ip()
    if locked_out(ip):
        return jsonify({"error": "too many attempts, wait 15 minutes"}), 429
    token = str(d.get("token") or "")
    with _tx() as c:
        r = c.execute("SELECT * FROM pair_tokens WHERE token_hash=?", (sha(token),)).fetchone()
        if not r or r["used"] or r["expires"] < now():
            record_fail(ip)
            return jsonify({"error": "this pairing code is expired or already used. make a new one"}), 403
        c.execute("UPDATE pair_tokens SET used=1 WHERE token_hash=?", (r["token_hash"],))
        session_token = create_session(c, str(d.get("device") or "phone"))
    return set_session_cookie(jsonify({"ok": True}), session_token)
