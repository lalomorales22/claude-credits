#!/usr/bin/env python3
"""
Fake Ollama server for demos and tests. Speaks just enough of the Ollama API
(/api/tags, /api/chat streaming) for a hive node to use it.

    python3 tools/mock_ollama.py --port 11500 --models llama3.2:3b,qwen2.5:7b --tps 40
"""

import argparse
import json
import random
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOREM = ("the hive is a distributed intelligence where every machine contributes what it can "
         "and the coordinator turns many small minds into one large one").split()


def make_handler(models, tps, fail_rate):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path == "/api/tags":
                return self._json(200, {"models": [
                    {"name": m, "model": m, "size": int(float(m.split(":")[-1].rstrip("b") or 3) * 6e8)
                     if m.split(":")[-1].rstrip("b").replace(".", "").isdigit() else 2_000_000_000,
                     "details": {"parameter_size": m.split(":")[-1].upper() if ":" in m else "3B",
                                 "quantization_level": "Q4_K_M", "family": m.split(":")[0]}}
                    for m in models]})
            self._json(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/api/chat":
                return self._json(404, {"error": "not found"})
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            if req.get("model") not in models:
                return self._json(404, {"error": f"model '{req.get('model')}' not found"})
            if random.random() < fail_rate:
                return self._json(500, {"error": "simulated GPU meltdown"})
            prompt = (req.get("messages") or [{}])[-1].get("content", "")
            if "planner for a swarm" in prompt:
                text = json.dumps({"subtasks": [
                    {"title": "Research", "prompt": "Research the topic thoroughly."},
                    {"title": "Draft", "prompt": "Draft the main content."},
                    {"title": "Critique", "prompt": "List risks and weaknesses."}]})
            else:
                n = random.randint(25, 45)
                text = f"[{req['model']}] " + " ".join(random.choice(LOREM) for _ in range(n)) + "."
            words = text.split(" ")
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.end_headers()
            t0 = time.time()
            for i, w in enumerate(words):
                piece = w if i == 0 else " " + w
                self.wfile.write((json.dumps({"model": req["model"], "message": {"role": "assistant", "content": piece},
                                              "done": False}) + "\n").encode())
                self.wfile.flush()
                time.sleep(1 / tps)
            dur = time.time() - t0
            self.wfile.write((json.dumps({"model": req["model"], "message": {"role": "assistant", "content": ""},
                                          "done": True, "prompt_eval_count": len(prompt.split()),
                                          "eval_count": len(words), "eval_duration": int(dur * 1e9)}) + "\n").encode())
    return H


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=11434)
    p.add_argument("--models", default="llama3.2:3b")
    p.add_argument("--tps", type=float, default=40)
    p.add_argument("--fail-rate", type=float, default=0.0)
    a = p.parse_args()
    models = [m.strip() for m in a.models.split(",") if m.strip()]
    print(f"mock ollama on :{a.port} serving {models} at ~{a.tps} tok/s", flush=True)
    ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(models, a.tps, a.fail_rate)).serve_forever()


if __name__ == "__main__":
    main()
