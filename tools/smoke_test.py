#!/usr/bin/env python3
"""
End-to-end test: boots a coordinator, two mock ollamas, two nodes, then drives
chat (blocking + streaming), a swarm, a council, and a node dying mid-job.

    python3 tools/smoke_test.py
"""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = 17777
HIVE = f"http://127.0.0.1:{PORT}"
KEY = "hive-test-key"
PY = sys.executable
procs = []


def spawn(*args, env=None):
    p = subprocess.Popen([PY, *args], cwd=ROOT, env={**os.environ, **(env or {})},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    procs.append(p)
    return p


def call(method, path, data=None, key=KEY, raw=False):
    req = urllib.request.Request(HIVE + path, data=json.dumps(data).encode() if data is not None else None,
                                 method=method, headers={"Content-Type": "application/json",
                                                         "Authorization": f"Bearer {key}"})
    r = urllib.request.urlopen(req, timeout=120)
    return r if raw else json.loads(r.read() or b"null")


def wait_until(fn, timeout=30, msg="condition"):
    end = time.time() + timeout
    while time.time() < end:
        try:
            v = fn()
            if v:
                return v
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.3)
    raise AssertionError(f"timed out waiting for {msg}")


def check(cond, label):
    print(("  ✔ " if cond else "  ✖ ") + label, flush=True)
    if not cond:
        raise AssertionError(label)


def main():
    tmp = tempfile.mkdtemp()
    env = {"HIVE_KEY": KEY, "HIVE_PORT": str(PORT), "HIVE_HOST": "127.0.0.1",
           "HIVE_DB": f"{tmp}/hive.db", "HIVE_NODE_TIMEOUT": "6"}
    spawn("coordinator/app.py", env=env)
    spawn("tools/mock_ollama.py", "--port", "11601", "--models", "llama3.2:3b", "--tps", "80")
    spawn("tools/mock_ollama.py", "--port", "11602", "--models", "qwen2.5:14b,llama3.2:3b", "--tps", "120")
    wait_until(lambda: call("GET", "/health")["ok"], msg="coordinator")
    home_a, home_b = tempfile.mkdtemp(), tempfile.mkdtemp()  # separate node ids
    spawn("node/hive_node.py", "--hive", HIVE, "--key", KEY, "--name", "node-small", "--ollama",
          "http://127.0.0.1:11601", env={"HOME": home_a})
    node_b = spawn("node/hive_node.py", "--hive", HIVE, "--key", KEY, "--name", "node-big", "--ollama",
                   "http://127.0.0.1:11602", "--slots", "2", env={"HOME": home_b})

    print("fleet")
    st = wait_until(lambda: (s := call("GET", "/api/state"))["stats"]["nodes_online"] == 2 and s, msg="2 nodes")
    check(set(st["stats"]["models"]) == {"llama3.2:3b", "qwen2.5:14b"}, "fleet models merged")
    try:
        call("GET", "/api/state", key="wrong")
        check(False, "bad key rejected")
    except urllib.error.HTTPError as e:
        check(e.code == 401, "bad key rejected")
    ids = [m["id"] for m in call("GET", "/v1/models")["data"]]
    check({"auto", "hive-swarm", "hive-council", "qwen2.5:14b"} <= set(ids), "/v1/models lists fleet + virtual models")

    print("openai api")
    r = call("POST", "/v1/chat/completions", {"model": "qwen2.5:14b", "messages": [{"role": "user", "content": "hi"}]})
    check(r["choices"][0]["message"]["content"].startswith("[qwen2.5:14b]"), "specific model routed to the node that has it")
    check(r["usage"]["completion_tokens"] > 0, "usage reported")
    r = call("POST", "/v1/chat/completions", {"model": "auto", "messages": [{"role": "user", "content": "hi"}]})
    check(bool(r["choices"][0]["message"]["content"]), "auto model works")
    resp = call("POST", "/v1/chat/completions", {"model": "llama3.2", "stream": True,
                                                 "messages": [{"role": "user", "content": "stream please"}]}, raw=True)
    chunks, text = 0, ""
    for line in resp:
        line = line.decode().strip()
        if line.startswith("data:") and line[5:].strip() != "[DONE]":
            ev = json.loads(line[5:])
            text += ev["choices"][0]["delta"].get("content", "")
            chunks += 1
    check(chunks > 3 and text.startswith("[llama3.2:3b]"), f"streaming works ({chunks} chunks, ':latest'-less name resolved)")

    print("swarm")
    sid = call("POST", "/api/swarms", {"goal": "plan a launch", "mode": "swarm"})["id"]
    s = wait_until(lambda: (x := call("GET", f"/api/swarms/{sid}"))["status"] in ("done", "failed") and x,
                   timeout=60, msg="swarm")
    check(s["status"] == "done", f"swarm finished ({s.get('error')})")
    workers = [j for j in s["jobs"] if j["kind"] == "subtask"]
    check(len(workers) == 3, "planner JSON parsed into 3 parallel subtasks")
    check(len({j["node_id"] for j in workers}) == 2, "subtasks spread across both nodes")
    check(bool(s["final"]), "synthesizer produced final answer")
    lead = [j for j in s["jobs"] if j["kind"] in ("plan", "synth")]
    check(all(j["model_used"] == "qwen2.5:14b" for j in lead), "planner + synthesizer ran on the biggest model")

    print("council")
    sid = call("POST", "/api/swarms", {"goal": "best language?", "mode": "council"})["id"]
    s = wait_until(lambda: (x := call("GET", f"/api/swarms/{sid}"))["status"] in ("done", "failed") and x,
                   timeout=60, msg="council")
    check(s["status"] == "done", "council finished")
    members = [j for j in s["jobs"] if j["kind"] == "council"]
    check(len(members) == 2 and len({j["node_id"] for j in members}) == 2, "every node sat on the council")

    print("virtual model through openai api")
    r = call("POST", "/v1/chat/completions", {"model": "hive-swarm", "messages": [{"role": "user", "content": "go"}]})
    check(bool(r["choices"][0]["message"]["content"]), "hive-swarm usable as a model name")

    print("fault tolerance")
    # queue work only the big node can run, kill it mid-job, bring up a replacement with that model
    jid_holder = {}

    def fire():
        jid_holder["r"] = call("POST", "/v1/chat/completions",
                               {"model": "qwen2.5:14b", "messages": [{"role": "user", "content": "survive"}]})
    import threading
    t = threading.Thread(target=fire)
    t.start()
    wait_until(lambda: any(j["status"] == "running" and j["model"] == "qwen2.5:14b"
                           for j in call("GET", "/api/state")["jobs"]), msg="job running")
    os.killpg(node_b.pid, signal.SIGKILL)
    spawn("tools/mock_ollama.py", "--port", "11603", "--models", "qwen2.5:14b", "--tps", "120")
    time.sleep(0.5)
    spawn("node/hive_node.py", "--hive", HIVE, "--key", KEY, "--name", "node-backup", "--ollama",
          "http://127.0.0.1:11603", env={"HOME": tempfile.mkdtemp()})
    t.join(90)
    r = jid_holder.get("r")
    check(bool(r and r["choices"][0]["message"]["content"]), "job survived its node dying and finished elsewhere")
    print("\nall green. the hive lives.")


if __name__ == "__main__":
    try:
        main()
    finally:
        for p in procs:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except OSError:
                pass
