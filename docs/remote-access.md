# using your hive from anywhere

The goal: open HIVEMIND on your phone at a coffee shop, while the coordinator stays **off the open internet**.

There are three layers, and each one would stop an attacker on its own:

1. **WireGuard.** Your phone gets a private, encrypted line home. Without the key, the coordinator is invisible, since WireGuard doesn't even answer packets it can't authenticate.
2. **Password + 2FA.** Even from inside the tunnel, you need your password and the 6-digit code from your authenticator app.
3. **Device sessions.** Every signed-in device shows up in 🔒 security. You can sign any of them out instantly, and idle sessions expire on their own.

## 0. first run (at home)

```bash
python3 coordinator/app.py
```

The console prints a **setup token**. Open `http://<coordinator-ip>:7777/setup`, paste the token, pick a password, scan the 2FA QR with an authenticator app (Aegis, 2FAS, Google Authenticator, and the iPhone Passwords app all work), and **save the 8 recovery codes**. The setup token self-destructs after it's used.

Locked out? On the coordinator machine run `python3 coordinator/app.py --reset-auth`. That wipes the owner account and all sessions, keeps your nodes and history, and prints a new setup token.

## 1. make the wireguard network

On the coordinator machine:

```bash
pip install segno            # already there if you installed requirements.txt
python3 tools/wireguard_setup.py --endpoint <your-public-ip-or-ddns-name> --peers phone,laptop
```

- **endpoint** is how your phone finds home from outside. If your home IP changes, get a free DDNS name (duckdns.org works) and use that.
- It writes `wireguard/hive.conf` for the coordinator, plus one `.conf` and QR code per device. These are private keys, and `wireguard/` is gitignored.
- Add a device later: `python3 tools/wireguard_setup.py --add-peer tablet`, then reload `hive.conf` on the coordinator.

## 2. turn it on

**Coordinator (linux / raspberry pi):**
```bash
sudo apt install wireguard-tools
sudo cp wireguard/hive.conf /etc/wireguard/hive.conf
sudo wg-quick up hive
sudo systemctl enable wg-quick@hive     # start on boot
```

**Coordinator (mac):** install the free WireGuard app, then import tunnel from file → `wireguard/hive.conf` → activate.

**Router:** forward **UDP 51820** to the coordinator machine. That's the only port you open, and it's WireGuard, not the dashboard.

**Phone:** install the free WireGuard app, tap + → create from QR code, and scan the QR the script printed.

## 3. point the hive at the tunnel

```bash
HIVE_PUBLIC_URL=http://10.44.0.1:7777 python3 coordinator/app.py
```

`HIVE_PUBLIC_URL` is what the 🔒 security → pairing QR points at.

On your phone: WireGuard on → open `http://10.44.0.1:7777`. Either log in with password + 2FA, or at home open 🔒 security → **show pairing qr** on the dashboard and scan it with the phone camera. The pairing link works once and dies after 5 minutes.

Tip: on your phone, use the browser's "add to home screen" and it opens like an app.

## no port forwarding? (CGNAT, some ISPs, starlink, cellular home internet)

If your ISP doesn't give you a real public IP, the router port forward won't work. You have two options:

- **Put WireGuard on a machine that has a public IP** (a small VPS you already have) and route both your phone and the coordinator through it. It's more setup, but everything is still yours.
- **Cloudflare Tunnel** (`cloudflared tunnel --url http://localhost:7777`). Your hive gets an https address with no open ports. The dashboard is then on the internet behind your password + 2FA, so also set:
  ```bash
  HIVE_SECURE_COOKIES=1 HIVE_BEHIND_CLOUDFLARE=1 HIVE_PUBLIC_URL=https://<your-tunnel-host> python3 coordinator/app.py
  ```
  `HIVE_BEHIND_CLOUDFLARE=1` makes the brute-force lockout use the real client IP. Only set it when you actually run behind cloudflare.

## what protects what

| thing | protected by |
|---|---|
| dashboard, chat, swarms | session cookie (HttpOnly, SameSite=Strict) + CSRF token on every change |
| login | scrypt password + TOTP 2FA (replay-protected), 5 misses per IP → 15 min lockout |
| lost phone | 8 single-use recovery codes, or `--reset-auth` on the coordinator |
| phone pairing | one-time link, 5 min expiry, token in the URL fragment (never sent to logs), claimed by POST only |
| nodes and scripts | the hive key (`coordinator/hive_key.txt`) as a bearer token, never accepted in URLs |
| account changes, seeing the hive key | a logged-in session only; the hive key alone can't do these |

## settings

| env | default | |
|---|---|---|
| `HIVE_PUBLIC_URL` | the address you're browsing from | where pairing QRs point |
| `HIVE_SESSION_IDLE_HOURS` | `72` | sign a device out after this long unused |
| `HIVE_SESSION_MAX_DAYS` | `30` | hard limit, then log in again |
| `HIVE_SECURE_COOKIES` | off | set `1` when serving over https |
| `HIVE_BEHIND_CLOUDFLARE` | off | set `1` only behind a cloudflare tunnel |
