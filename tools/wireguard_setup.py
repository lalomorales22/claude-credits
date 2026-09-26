#!/usr/bin/env python3
"""
Private WireGuard network for your hive. Your phone and laptop get a direct
encrypted line to the coordinator, and the coordinator never has to be on the
open internet.

    python3 tools/wireguard_setup.py --endpoint myhome.duckdns.org --peers phone,laptop
    python3 tools/wireguard_setup.py --add-peer tablet

Writes wireguard/hive.conf (for the coordinator machine) and one .conf per
device, and prints a QR code per device. Scan it with the free WireGuard app
(iOS / Android): + → "Create from QR code".

Split tunnel: devices only send hive traffic (10.44.0.0/24) through the tunnel,
so the rest of your phone's internet is untouched.

Keys are made with a pure-python X25519 (RFC 7748), so there's nothing to install.
"""

import argparse
import base64
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "wireguard"
STATE = OUT / "state.json"
SUBNET = "10.44.0"
PORT = 51820

# --------------------------------------------------------------------------- x25519 (RFC 7748)

P = 2 ** 255 - 19
A24 = 121665


def _clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(scalar: bytes, u: bytes) -> bytes:
    k = _clamp(scalar)
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3, z3 = (da + cb) ** 2 % P, x1 * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def keypair():
    priv = bytearray(secrets.token_bytes(32))
    priv[0] &= 248
    priv[31] = (priv[31] & 127) | 64
    pub = x25519(bytes(priv), (9).to_bytes(32, "little"))
    return base64.b64encode(bytes(priv)).decode(), base64.b64encode(pub).decode()


def psk():
    return base64.b64encode(secrets.token_bytes(32)).decode()


# --------------------------------------------------------------------------- configs

def server_conf(st):
    lines = ["# HIVEMIND coordinator side. install: see docs/remote-access.md", "[Interface]",
             f"Address = {SUBNET}.1/24", f"ListenPort = {st['port']}", f"PrivateKey = {st['server']['private']}", ""]
    for name, p in st["peers"].items():
        lines += [f"[Peer]  # {name}", f"PublicKey = {p['public']}", f"PresharedKey = {p['psk']}",
                  f"AllowedIPs = {SUBNET}.{p['ip']}/32", ""]
    return "\n".join(lines)


def peer_conf(st, name):
    p = st["peers"][name]
    return "\n".join([
        f"# HIVEMIND device: {name}", "[Interface]", f"Address = {SUBNET}.{p['ip']}/32",
        f"PrivateKey = {p['private']}", "", "[Peer]  # hive coordinator", f"PublicKey = {st['server']['public']}",
        f"PresharedKey = {p['psk']}", f"Endpoint = {st['endpoint']}:{st['port']}",
        f"AllowedIPs = {SUBNET}.0/24", "PersistentKeepalive = 25", ""])


def write_private(path, text):
    path.write_text(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def add_peer(st, name):
    if name in st["peers"]:
        sys.exit(f"device '{name}' already exists")
    used = {p["ip"] for p in st["peers"].values()}
    ip = next(i for i in range(2, 255) if i not in used)
    priv, pub = keypair()
    st["peers"][name] = {"ip": ip, "private": priv, "public": pub, "psk": psk()}


def show_qr(text, name):
    try:
        import segno
    except ImportError:
        print(f"  (pip install segno to show a qr; or import wireguard/{name}.conf by hand)")
        return
    print(f"\n  scan with the WireGuard app to add '{name}':\n")
    segno.make(text, error="l").terminal(compact=True)


def main():
    ap = argparse.ArgumentParser(description="WireGuard network for HIVEMIND")
    ap.add_argument("--endpoint", help="how devices reach your home from outside: public ip or a (free) ddns name")
    ap.add_argument("--peers", default="phone", help="comma list of device names to create")
    ap.add_argument("--add-peer", help="add one device to an existing setup")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--no-qr", action="store_true")
    a = ap.parse_args()

    OUT.mkdir(exist_ok=True)
    try:
        os.chmod(OUT, 0o700)
    except OSError:
        pass

    if a.add_peer:
        if not STATE.exists():
            sys.exit("no setup yet. run with --endpoint first")
        st = json.loads(STATE.read_text())
        add_peer(st, a.add_peer)
        names = [a.add_peer]
    else:
        if STATE.exists():
            sys.exit("wireguard/ already set up. use --add-peer NAME, or delete wireguard/ to start over")
        if not a.endpoint:
            sys.exit("--endpoint is required (your public ip or ddns name)")
        priv, pub = keypair()
        st = {"endpoint": a.endpoint, "port": a.port, "server": {"private": priv, "public": pub}, "peers": {}}
        names = [n.strip() for n in a.peers.split(",") if n.strip()]
        for n in names:
            add_peer(st, n)

    write_private(STATE, json.dumps(st, indent=2))
    write_private(OUT / "hive.conf", server_conf(st))
    for n in names:
        conf = peer_conf(st, n)
        write_private(OUT / f"{n}.conf", conf)
        if not a.no_qr:
            show_qr(conf, n)

    print(f"""
  wrote wireguard/hive.conf  (coordinator)  +  {', '.join(f'wireguard/{n}.conf' for n in names)}
  these files are secret keys: never commit them (wireguard/ is gitignored).

  next:
   1. load wireguard/hive.conf on the coordinator machine{' (again, it changed)' if a.add_peer else ''}
        linux:  sudo cp wireguard/hive.conf /etc/wireguard/hive.conf && sudo wg-quick up hive
                sudo systemctl enable wg-quick@hive      # start on boot
        mac:    WireGuard app → import tunnel from file → wireguard/hive.conf → activate
   2. on your router, forward UDP {st['port']} to the coordinator machine
   3. start the coordinator with   HIVE_PUBLIC_URL=http://{SUBNET}.1:7777
   4. on your phone: WireGuard on → open http://{SUBNET}.1:7777 → log in, or scan the pairing qr
""")


if __name__ == "__main__":
    main()
