#!/usr/bin/env python3
"""
Auth tests: setup, 2fa, replay, lockout, csrf, sessions, pairing, recovery codes.
Runs in-process against a throwaway database.

    python3 tools/auth_test.py
"""

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
tmp = tempfile.mkdtemp()
os.environ.update({"HIVE_DB": f"{tmp}/hive.db", "HIVE_KEY": "hive-test-key"})
sys.path.insert(0, str(ROOT / "coordinator"))

import app as hive  # noqa: E402
import auth  # noqa: E402

assert auth._setup_token_file.parent == Path(tmp), "setup token must live next to the test db"
SETUP_TOKEN = auth.ensure_setup_token()
PW = "correct horse battery"

passed = 0


def check(cond, label):
    global passed
    print(("  ✔ " if cond else "  ✖ ") + label, flush=True)
    if not cond:
        raise SystemExit(1)
    passed += 1


def fresh_ip(c, n):
    c.environ_base["REMOTE_ADDR"] = f"10.0.0.{n}"


def code_now(secret, offset=0):
    return auth.totp_at(secret, int(time.time() // 30) + offset)


def csrf(c):
    return c.get("/api/auth/me").get_json()["csrf"]


def main():
    c = hive.app.test_client()
    fresh_ip(c, 1)

    print("first run")
    check(c.get("/").headers["Location"].endswith("/setup"), "no owner yet: / redirects to /setup")
    check(c.get("/api/state").status_code == 401, "api is locked before setup")
    r = c.post("/api/auth/setup/start", json={"setup_token": "nope", "password": PW})
    check(r.status_code == 403, "wrong setup token rejected")
    r = c.post("/api/auth/setup/start", json={"setup_token": SETUP_TOKEN, "password": "short"})
    check(r.status_code == 400, "short password rejected")
    r = c.post("/api/auth/setup/start", json={"setup_token": SETUP_TOKEN, "password": PW})
    secret = r.get_json()["secret"]
    check(r.status_code == 200 and "<svg" in r.get_json()["qr"], "setup returns totp secret + qr")
    r = c.post("/api/auth/setup/finish", json={"setup_token": SETUP_TOKEN, "code": "000000"})
    check(r.status_code == 403, "wrong first 2fa code rejected")
    # the previous time step is accepted (clock drift) and leaves the current one free for the login test
    r = c.post("/api/auth/setup/finish", json={"setup_token": SETUP_TOKEN, "code": code_now(secret, -1)})
    recovery = r.get_json()["recovery_codes"]
    check(r.status_code == 200 and len(recovery) == 8, "setup finished, 8 recovery codes issued")
    check(not auth._setup_token_file.exists(), "setup token destroyed after use")
    check(c.post("/api/auth/setup/start", json={"setup_token": SETUP_TOKEN, "password": PW}).status_code == 409,
          "setup can't be run twice")
    check(c.get("/").status_code == 200, "setup browser is logged in")

    print("csrf")
    check(c.post("/api/swarms", json={"goal": "x"}).status_code == 403, "cookie write without csrf blocked")
    check(c.post("/api/swarms", json={"goal": "x"}, headers={"X-Hive-CSRF": "wrong"}).status_code == 403,
          "cookie write with wrong csrf blocked")
    check(c.post("/api/jobs/job_nope/cancel", headers={"X-Hive-CSRF": csrf(c)}, json={}).status_code == 200,
          "cookie write with csrf allowed")

    print("login")
    c2 = hive.app.test_client()
    fresh_ip(c2, 2)
    check(c2.get("/").headers["Location"].endswith("/login"), "logged-out / redirects to /login")
    r = c2.post("/api/auth/login", json={"password": "wrong password", "code": code_now(secret)})
    check(r.status_code == 401, "wrong password rejected")
    r = c2.post("/api/auth/login", json={"password": PW, "code": "123456"})
    check(r.status_code == 401, "wrong code rejected")
    good = code_now(secret)
    r = c2.post("/api/auth/login", json={"password": PW, "code": good, "device": "laptop"})
    check(r.status_code == 200, "password + current code logs in")
    cookie = r.headers.get("Set-Cookie", "")
    check("HttpOnly" in cookie and "SameSite=Strict" in cookie, "session cookie is HttpOnly + SameSite=Strict")
    c3 = hive.app.test_client()
    fresh_ip(c3, 3)
    check(c3.post("/api/auth/login", json={"password": PW, "code": good}).status_code == 401,
          "the same 2fa code can't be replayed")
    r = c3.post("/api/auth/login", json={"password": PW, "code": recovery[0]})
    check(r.status_code == 200, "recovery code works in place of 2fa")
    c4 = hive.app.test_client()
    fresh_ip(c4, 4)
    check(c4.post("/api/auth/login", json={"password": PW, "code": recovery[0]}).status_code == 401,
          "recovery codes are single use")

    print("lockout")
    c5 = hive.app.test_client()
    fresh_ip(c5, 5)
    for _ in range(auth.LOCKOUT_FAILS):
        c5.post("/api/auth/login", json={"password": "guess", "code": "000000"})
    r = c5.post("/api/auth/login", json={"password": PW, "code": code_now(secret, 1)})
    check(r.status_code == 429, "5 misses locks the ip out, even with the right password")
    auth._fails.clear()

    print("machines")
    k = {"Authorization": "Bearer hive-test-key"}
    check(hive.app.test_client().get("/api/state", headers=k).status_code == 200, "hive key still works for scripts")
    check(hive.app.test_client().get("/api/state?key=hive-test-key").status_code == 401, "key in url is ignored")
    check(hive.app.test_client().get("/api/auth/hive-key", headers=k).status_code == 401,
          "hive key can't read account endpoints")
    check(c.get("/api/auth/hive-key").get_json()["hive_key"] == "hive-test-key", "logged-in owner can see the key")

    print("pairing")
    r = c.post("/api/auth/pair", headers={"X-Hive-CSRF": csrf(c)}, json={})
    url = r.get_json()["url"]
    token = url.split("#", 1)[1]
    check("/pair#" in url and "<svg" in r.get_json()["qr"], "pair link uses a url fragment + qr")
    phone = hive.app.test_client()
    fresh_ip(phone, 6)
    check(phone.get("/pair").status_code == 200, "pair page loads without consuming anything")
    check(phone.post("/api/auth/pair/claim", json={"token": token, "device": "phone"}).status_code == 200,
          "phone claims the pairing link")
    check(phone.get("/api/state").status_code == 200, "paired phone is logged in")
    other = hive.app.test_client()
    fresh_ip(other, 7)
    check(other.post("/api/auth/pair/claim", json={"token": token}).status_code == 403, "pairing links are single use")
    r = c.post("/api/auth/pair", headers={"X-Hive-CSRF": csrf(c)}, json={})
    old = r.get_json()["url"].split("#", 1)[1]
    with hive.tx() as cx:
        cx.execute("UPDATE pair_tokens SET expires=? WHERE token_hash=?", (time.time() - 1, auth.sha(old)))
    check(other.post("/api/auth/pair/claim", json={"token": old}).status_code == 403, "expired pairing link rejected")
    check(hive.app.test_client().post("/api/auth/pair", json={}).status_code == 401, "only logged-in owner can pair")

    print("sessions")
    sessions = c.get("/api/auth/sessions").get_json()
    check(any(s["device"] == "phone" for s in sessions), "phone shows up in device list")
    phone_id = next(s["id"] for s in sessions if s["device"] == "phone")
    c.delete(f"/api/auth/sessions/{phone_id}", headers={"X-Hive-CSRF": csrf(c)})
    check(phone.get("/api/state").status_code == 401, "revoked device is signed out instantly")
    with hive.tx() as cx:
        cx.execute("UPDATE sessions SET last_seen=?", (time.time() - auth.IDLE_SECONDS - 5,))
    check(c2.get("/api/state").status_code == 401, "idle sessions expire")

    print("account")
    c6 = hive.app.test_client()
    fresh_ip(c6, 8)
    r = c6.post("/api/auth/login", json={"password": PW, "code": recovery[1]})
    check(r.status_code == 200, "log back in")
    h = {"X-Hive-CSRF": csrf(c6)}
    r = c6.post("/api/auth/password", headers=h, json={"current_password": "nope", "new_password": "a new long password",
                                                       "code": recovery[2]})
    check(r.status_code == 401, "password change needs the current password")
    r = c6.post("/api/auth/password", headers=h, json={"current_password": PW, "new_password": "a new long password",
                                                       "code": recovery[2]})
    check(r.status_code == 200, "password change with password + 2fa")
    r = c6.post("/api/auth/logout", headers=h, json={})
    check(r.status_code == 200 and c6.get("/api/state").status_code == 401, "logout kills the session")

    print("headers")
    r = c.get("/login")
    check(r.headers.get("X-Frame-Options") == "DENY" and "frame-ancestors 'none'" in r.headers.get(
        "Content-Security-Policy", ""), "clickjacking protection on")

    print("wireguard keys")
    sys.path.insert(0, str(ROOT / "tools"))
    from wireguard_setup import x25519
    k = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    check(x25519(k, (9).to_bytes(32, "little")).hex() ==
          "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "x25519 matches RFC 7748 test vector")

    print(f"\nall {passed} auth checks green.")


if __name__ == "__main__":
    main()
