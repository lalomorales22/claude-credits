#!/usr/bin/env python3
"""
HIVEMIND node agent.

Turns any machine with Ollama into a worker for your hive. Pure python stdlib,
so it runs on a mac mini, a jetson, a raspberry pi, or a 2012 laptop with zero
installs. It only makes OUTBOUND requests to the coordinator, so no port
forwarding is ever needed.

    python3 hive_node.py --hive http://192.168.1.50:7777 --key hive-xxxx

Options:
    --name NAME            display name (default: hostname)
    --ollama URL           local ollama (default http://127.0.0.1:11434)
    --slots N              jobs to run at once (default 1; raise on big machines)
    --default-model NAME   model used for "auto" jobs (default: biggest installed)
    --models a,b,c         only offer these models to the hive
"""

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

VERSION = "1.0.0"
ID_FILE = Path.home() / ".hivemind_node_id"


# --------------------------------------------------------------------------- http

def http(method, url, data=None, headers=None, timeout=30):
    body = json.dumps(data).encode() if data is not None else None
    h = {"Content-Type": "application/json", "User-Agent": f"hivemind-node/{VERSION}"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        if r.status == 204 or not raw:
            return r.status, None
        return r.status, json.loads(raw)


# --------------------------------------------------------------------------- hardware

def sh(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def ram_gb():
    try:
        if sys.platform == "darwin":
            return round(int(sh(["sysctl", "-n", "hw.memsize"])) / 1024 ** 3, 1)
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return round(int(line.split()[1]) / 1024 ** 2, 1)
    except (OSError, ValueError):
        pass
    return None


def cpu_name():
    if sys.platform == "darwin":
        return sh(["sysctl", "-n", "machdep.cpu.brand_string"]) or platform.processor()
    try:
        with open("/proc/cpuinfo") as f:
            txt = f.read()
        m = re.search(r"model name\s*:\s*(.+)", txt) or re.search(r"Model\s*:\s*(.+)", txt)
        if m:
            return m.group(1).strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def gpu_info():
    if sys.platform == "darwin" and platform.machine() == "arm64":
        chip = sh(["sysctl", "-n", "machdep.cpu.brand_string"])
        return {"type": "apple", "name": f"{chip} GPU (unified memory)"}
    if Path("/etc/nv_tegra_release").exists() or "tegra" in platform.release().lower():
        model = ""
        try:
            model = Path("/proc/device-tree/model").read_text().strip("\x00 \n")
        except OSError:
            pass
        return {"type": "jetson", "name": model or "NVIDIA Jetson"}
    if shutil.which("nvidia-smi"):
        out = sh(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
        if out:
            gpus = []
            for line in out.splitlines():
                parts = [p.strip() for p in line.split(",")]
                gpus.append({"name": parts[0], "vram_gb": round(float(parts[1]) / 1024, 1) if len(parts) > 1 else None})
            return {"type": "nvidia", "name": ", ".join(g["name"] for g in gpus),
                    "vram_gb": sum(g["vram_gb"] or 0 for g in gpus)}
    if shutil.which("rocm-smi"):
        return {"type": "amd", "name": "AMD GPU (ROCm)"}
    try:
        model = Path("/proc/device-tree/model").read_text().strip("\x00 \n")
        if "raspberry" in model.lower():
            return {"type": "none", "name": model}
    except OSError:
        pass
    return {"type": "none", "name": "CPU only"}


def hardware():
    return {
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "cpu": cpu_name(),
        "cores": os.cpu_count(),
        "ram_gb": ram_gb(),
        "gpu": gpu_info(),
        "python": platform.python_version(),
        "agent": VERSION,
    }


def node_id(name, ollama):
    # one id per (machine, ollama) pair, so several agents on one box never collide
    id_file = ID_FILE if ollama == "http://127.0.0.1:11434" else \
        ID_FILE.with_name(ID_FILE.name + "-" + uuid.uuid5(uuid.NAMESPACE_URL, ollama).hex[:8])
    try:
        if id_file.exists():
            v = id_file.read_text().strip()
            if v:
                return v
        v = "node_" + uuid.uuid4().hex[:16]
        id_file.write_text(v)
        return v
    except OSError:
        return "node_" + uuid.uuid5(uuid.NAMESPACE_DNS, f"{socket.gethostname()}|{name}|{ollama}").hex[:16]


# --------------------------------------------------------------------------- agent

def param_billions(m):
    ps = (m.get("details") or {}).get("parameter_size") or ""
    mt = re.match(r"([\d.]+)\s*([BbMm])", ps)
    if mt:
        v = float(mt.group(1))
        return v if mt.group(2).lower() == "b" else v / 1000
    return (m.get("size") or 0) / 1e9  # fall back to file size


class Node:
    def __init__(self, args):
        self.hive = args.hive.rstrip("/")
        self.key = args.key
        self.ollama = args.ollama.rstrip("/")
        self.name = args.name or socket.gethostname().split(".")[0]
        self.slots = max(1, args.slots)
        self.default_model = args.default_model
        self.only = [m.strip() for m in (args.models or "").split(",") if m.strip()]
        self.id = node_id(self.name, self.ollama)
        self.hw = hardware()
        self.models = []
        self.enabled = True
        self.active = 0
        self.lock = threading.Lock()
        self.stop = threading.Event()

    @property
    def headers(self):
        return {"X-Hive-Key": self.key}

    def log(self, msg):
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

    # ---- ollama

    def refresh_models(self):
        try:
            _, data = http("GET", f"{self.ollama}/api/tags", timeout=10)
            models = []
            for m in (data or {}).get("models", []):
                name = m.get("name") or m.get("model")
                if not name or (self.only and name not in self.only and name.split(":")[0] not in self.only):
                    continue
                if "embed" in name.lower():  # embedding models can't chat
                    continue
                d = m.get("details") or {}
                models.append({"name": name, "size_gb": round((m.get("size") or 0) / 1e9, 2),
                               "params": d.get("parameter_size"), "quant": d.get("quantization_level"),
                               "family": d.get("family"), "_b": param_billions(m)})
            models.sort(key=lambda x: x["_b"], reverse=True)
            self.models = models
        except (urllib.error.URLError, OSError, ValueError) as e:
            if self.models:
                self.log(f"lost ollama at {self.ollama}: {e}")
            self.models = []

    def model_names(self):
        return [m["name"] for m in self.models]

    def resolve_model(self, requested):
        names = self.model_names()
        if requested and not requested.startswith("auto"):
            if requested in names:
                return requested
            if ":" not in requested:  # bare family name -> biggest installed tag of it
                tagged = [n for n in names if n.split(":")[0] == requested]
                if tagged:
                    return f"{requested}:latest" if f"{requested}:latest" in tagged else tagged[0]
        if requested == "auto:small" and self.models:
            return self.models[-1]["name"]
        if self.default_model and self.default_model in names:
            return self.default_model
        return names[0] if names else None

    # ---- loops

    def heartbeat_loop(self):
        backoff = 2
        while not self.stop.is_set():
            self.refresh_models()
            try:
                _, r = http("POST", f"{self.hive}/api/node/heartbeat", {
                    "node_id": self.id, "name": self.name, "hardware": self.hw,
                    "models": [{k: v for k, v in m.items() if not k.startswith("_")} for m in self.models],
                    "slots": self.slots, "busy": self.active,
                }, self.headers, timeout=15)
                was = self.enabled
                self.enabled = bool((r or {}).get("enabled", True))
                if was != self.enabled:
                    self.log("enabled by coordinator" if self.enabled else "paused by coordinator")
                backoff = 2
                self.stop.wait(5)
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    self.log("coordinator rejected our key. check --key")
                else:
                    self.log(f"heartbeat failed: HTTP {e.code}")
                self.stop.wait(backoff)
                backoff = min(backoff * 2, 30)
            except (urllib.error.URLError, OSError, ValueError) as e:
                self.log(f"can't reach hive at {self.hive}: {e}")
                self.stop.wait(backoff)
                backoff = min(backoff * 2, 30)

    def worker_loop(self, slot):
        idle = 0.5
        while not self.stop.is_set():
            if not self.enabled or not self.models:
                self.stop.wait(2)
                continue
            try:
                status, job = http("POST", f"{self.hive}/api/node/claim",
                                   {"node_id": self.id, "models": self.model_names()}, self.headers, timeout=15)
            except (urllib.error.URLError, OSError, ValueError):
                self.stop.wait(3)
                continue
            if status == 204 or not job:
                self.stop.wait(idle)
                idle = min(idle * 1.3, 1.5)  # poll fast when busy, relax when quiet
                continue
            idle = 0.3
            with self.lock:
                self.active += 1
            try:
                self.run_job(job, slot)
            finally:
                with self.lock:
                    self.active -= 1

    def post(self, path, data):
        for attempt in range(4):
            try:
                return http("POST", f"{self.hive}{path}", data, self.headers, timeout=30)[1]
            except urllib.error.HTTPError as e:
                if e.code in (401, 404, 409):
                    return None
            except (urllib.error.URLError, OSError, ValueError):
                pass
            time.sleep(2 ** attempt)
        return None

    def run_job(self, job, slot):
        jid = job["job_id"]
        model = self.resolve_model(job.get("model"))
        if not model:
            self.post("/api/node/result", {"job_id": jid, "node_id": self.id, "ok": False,
                                           "error": f"no model for {job.get('model')} on {self.name}"})
            return
        self.log(f"slot{slot} ▶ {job.get('kind')} {jid} on {model}")
        t0 = time.time()
        out = []
        thinking = []
        tin = tout = 0
        tps = 0.0
        last_push = 0.0
        try:
            req = urllib.request.Request(
                f"{self.ollama}/api/chat",
                data=json.dumps({"model": model, "messages": job["messages"], "stream": True,
                                 "options": job.get("options") or {}, "keep_alive": "30m"}).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=600) as r:
                for line in r:
                    line = line.strip()
                    if not line:
                        continue
                    ev = json.loads(line)
                    if ev.get("error"):
                        raise RuntimeError(ev["error"])
                    msg = ev.get("message") or {}
                    if msg.get("thinking"):
                        # newer ollama splits reasoning out; show it live but keep it out of the answer
                        thinking.append(msg["thinking"])
                    piece = msg.get("content") or ""
                    if piece:
                        out.append(piece)
                    if ev.get("done"):
                        tin = ev.get("prompt_eval_count") or 0
                        tout = ev.get("eval_count") or 0
                        dur = (ev.get("eval_duration") or 0) / 1e9
                        tps = round(tout / dur, 2) if dur > 0 else 0
                        break
                    if time.time() - last_push > 0.6:
                        last_push = time.time()
                        live = "".join(out) if out else ("<think>" + "".join(thinking)[-2000:] if thinking else "")
                        r2 = self.post("/api/node/progress", {"job_id": jid, "node_id": self.id,
                                                              "partial": live, "model": model})
                        if r2 is not None and not r2.get("continue", True):
                            self.log(f"slot{slot} ✕ {jid} cancelled by coordinator")
                            return
            text = "".join(out)
            if not tps and tout:
                tps = round(tout / max(time.time() - t0, 0.001), 2)
            self.post("/api/node/result", {"job_id": jid, "node_id": self.id, "ok": True, "output": text,
                                           "model": model, "tokens_in": tin, "tokens_out": tout, "tps": tps})
            self.log(f"slot{slot} ✔ {jid} {tout} tok @ {tps} tok/s ({time.time() - t0:.1f}s)")
        except Exception as e:  # noqa: BLE001 - every failure gets reported so the job can be retried elsewhere
            self.log(f"slot{slot} ✖ {jid} {e}")
            self.post("/api/node/result", {"job_id": jid, "node_id": self.id, "ok": False,
                                           "error": f"{self.name}: {e}", "model": model})

    def run(self):
        self.log(f"hivemind node '{self.name}' ({self.id}) -> {self.hive}")
        self.log(f"{self.hw['cpu']} | {self.hw['cores']} cores | {self.hw['ram_gb']} GB | {self.hw['gpu']['name']}")
        self.refresh_models()
        if self.models:
            self.log("models: " + ", ".join(self.model_names()))
        else:
            self.log(f"no chat models found at {self.ollama}. install ollama and run: ollama pull llama3.2")
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        for s in range(self.slots):
            threading.Thread(target=self.worker_loop, args=(s,), daemon=True).start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.log("shutting down")
            self.stop.set()


def main():
    p = argparse.ArgumentParser(description="HIVEMIND node agent")
    p.add_argument("--hive", default=os.environ.get("HIVE_URL", "http://127.0.0.1:7777"))
    p.add_argument("--key", default=os.environ.get("HIVE_KEY", ""))
    p.add_argument("--name", default=os.environ.get("HIVE_NODE_NAME"))
    p.add_argument("--ollama", default=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
    p.add_argument("--slots", type=int, default=int(os.environ.get("HIVE_SLOTS", 1)))
    p.add_argument("--default-model", default=os.environ.get("HIVE_DEFAULT_MODEL"))
    p.add_argument("--models", default=os.environ.get("HIVE_MODELS"))
    args = p.parse_args()
    if not args.key:
        p.error("--key is required (it's in coordinator/hive_key.txt)")
    Node(args).run()


if __name__ == "__main__":
    main()
