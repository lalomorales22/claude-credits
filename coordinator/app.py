"""
HIVEMIND coordinator.

One brain, many bodies. Every machine you own runs a tiny node agent
(node/hive_node.py) that pulls work from this coordinator and runs it on its
local Ollama. The coordinator:

  * tracks the fleet (hardware, models, speed, health)
  * queues jobs and hands them to whichever node can run them
  * exposes an OpenAI-compatible API (/v1/chat/completions, /v1/models) so any
    tool that speaks OpenAI can use your whole fleet as one endpoint
  * runs multi-node "swarms": plan -> fan out -> synthesize, or a council of
    every node answering the same question and a judge merging them
  * serves a live dashboard at /

Nodes only make OUTBOUND requests, so they work behind NAT, on other networks,
or through a cloudflare tunnel with zero port forwarding.

Run:  python3 coordinator/app.py            (HIVE_KEY auto-generated to hive_key.txt)
"""

import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from flask import Flask, Response, abort, jsonify, redirect, render_template, request, send_file, stream_with_context

import auth

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
DB_PATH = Path(os.environ.get("HIVE_DB", BASE_DIR / "hivemind.db"))
KEY_FILE = BASE_DIR / "hive_key.txt"
NODE_SCRIPT = ROOT_DIR / "node" / "hive_node.py"

NODE_OFFLINE_AFTER = float(os.environ.get("HIVE_NODE_TIMEOUT", 20))   # seconds without heartbeat
JOB_MAX_ATTEMPTS = 3
JOB_WAIT_TIMEOUT = float(os.environ.get("HIVE_JOB_TIMEOUT", 900))      # seconds a caller waits
MAX_SUBTASKS = 8
IDLE_PEER_WINDOW = 3.0  # seconds; idle nodes poll at least this often


# --------------------------------------------------------------------------- key

def load_key():
    env = os.environ.get("HIVE_KEY", "").strip()
    if env:
        return env
    if KEY_FILE.exists():
        k = KEY_FILE.read_text().strip()
        if k:
            return k
    k = "hive-" + secrets.token_urlsafe(24)
    KEY_FILE.write_text(k + "\n")
    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass
    return k


HIVE_KEY = load_key()


# --------------------------------------------------------------------------- db

_local = threading.local()
_write_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    host         TEXT,
    hardware     TEXT DEFAULT '{}',
    models       TEXT DEFAULT '[]',
    slots        INTEGER DEFAULT 1,
    busy         INTEGER DEFAULT 0,
    enabled      INTEGER DEFAULT 1,
    jobs_done    INTEGER DEFAULT 0,
    tokens_out   INTEGER DEFAULT 0,
    avg_tps      REAL DEFAULT 0,
    first_seen   REAL,
    last_seen    REAL
);
CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,           -- chat | plan | subtask | synth | council | judge
    model        TEXT NOT NULL DEFAULT 'auto',
    payload      TEXT NOT NULL,           -- {"messages": [...], "options": {...}}
    status       TEXT NOT NULL DEFAULT 'queued',  -- queued | running | done | failed | cancelled
    target_node  TEXT,
    node_id      TEXT,
    model_used   TEXT,
    partial      TEXT DEFAULT '',
    result       TEXT,
    error        TEXT,
    attempts     INTEGER DEFAULT 0,
    priority     INTEGER DEFAULT 5,
    swarm_id     TEXT,
    title        TEXT,
    tokens_in    INTEGER DEFAULT 0,
    tokens_out   INTEGER DEFAULT 0,
    tps          REAL DEFAULT 0,
    created      REAL NOT NULL,
    started      REAL,
    finished     REAL
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, priority, created);
CREATE INDEX IF NOT EXISTS idx_jobs_swarm ON jobs(swarm_id);
CREATE TABLE IF NOT EXISTS swarms (
    id           TEXT PRIMARY KEY,
    goal         TEXT NOT NULL,
    mode         TEXT NOT NULL,           -- swarm | council
    status       TEXT NOT NULL DEFAULT 'planning',
    plan         TEXT DEFAULT '[]',
    final        TEXT,
    error        TEXT,
    options      TEXT DEFAULT '{}',
    created      REAL NOT NULL,
    finished     REAL
);
"""


def db():
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn = conn
    return conn


@contextmanager
def tx():
    """Serialized write transaction. One process, so a lock + BEGIN IMMEDIATE is bulletproof."""
    with _write_lock:
        c = db()
        c.execute("BEGIN IMMEDIATE")
        try:
            yield c
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise


def init_db():
    c = db()
    c.executescript(SCHEMA)


def row(r):
    return dict(r) if r is not None else None


def now():
    return time.time()


# --------------------------------------------------------------------------- fleet helpers

def online_nodes():
    cutoff = now() - NODE_OFFLINE_AFTER
    rows = db().execute(
        "SELECT * FROM nodes WHERE last_seen >= ? AND enabled = 1 ORDER BY avg_tps DESC", (cutoff,)
    ).fetchall()
    return [row(r) for r in rows]


def node_model_names(node):
    try:
        return [m["name"] for m in json.loads(node.get("models") or "[]")]
    except (ValueError, TypeError, KeyError):
        return []


def model_size_b(m):
    """billions of params from ollama's parameter_size ("14.8B", "630M"), falling back to file size."""
    mt = re.match(r"([\d.]+)\s*([BbMm])", str(m.get("params") or ""))
    if mt:
        v = float(mt.group(1))
        return v if mt.group(2).lower() == "b" else v / 1000
    return float(m.get("size_gb") or 0)


def best_model():
    """the biggest brain currently online. lead roles (planner/synth/judge) go here, not to whoever polls first."""
    best, best_b = None, -1.0
    for n in online_nodes():
        for m in json.loads(n.get("models") or "[]"):
            b = model_size_b(m)
            if b > best_b:
                best, best_b = m["name"], b
    return best


def fleet_models():
    names = set()
    for n in online_nodes():
        names.update(node_model_names(n))
    return sorted(names)


# --------------------------------------------------------------------------- jobs

def create_job(kind, messages, model="auto", options=None, target_node=None,
               swarm_id=None, title=None, priority=5):
    jid = "job_" + uuid.uuid4().hex[:16]
    payload = json.dumps({"messages": messages, "options": options or {}})
    with tx() as c:
        c.execute(
            """INSERT INTO jobs (id, kind, model, payload, target_node, swarm_id, title, priority, created)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (jid, kind, model or "auto", payload, target_node, swarm_id, title, priority, now()),
        )
    return jid


def get_job(jid):
    return row(db().execute("SELECT * FROM jobs WHERE id = ?", (jid,)).fetchone())


def wait_job(jid, timeout=JOB_WAIT_TIMEOUT, poll=0.25):
    deadline = now() + timeout
    while now() < deadline:
        j = get_job(jid)
        if j is None:
            return None
        if j["status"] in ("done", "failed", "cancelled"):
            return j
        time.sleep(poll)
    with tx() as c:
        c.execute(
            "UPDATE jobs SET status='failed', error='timed out waiting for a node', finished=? "
            "WHERE id=? AND status IN ('queued','running')",
            (now(), jid),
        )
    return get_job(jid)


def job_can_run_on(job, node_id, models):
    if job["target_node"] and job["target_node"] != node_id:
        return False
    if job["model"] == "auto" or job["model"].startswith("auto:"):
        return bool(models)
    return model_matches(job["model"], models)


def model_matches(requested, models):
    """exact name, or a bare family name ("llama3.2") matching any installed tag of it ("llama3.2:3b")."""
    if requested in models:
        return True
    if ":" not in requested:
        return any(m.split(":")[0] == requested for m in models)
    return False


def claim_job(node_id, models):
    with tx() as c:
        candidates = c.execute(
            """SELECT * FROM jobs WHERE status='queued'
               AND (target_node IS NULL OR target_node = ?)
               ORDER BY priority ASC, created ASC LIMIT 200""",
            (node_id,),
        ).fetchall()
        # targeted jobs for this node first, then everything else in priority order
        candidates = sorted(candidates, key=lambda r: 0 if r["target_node"] == node_id else 1)
        me = c.execute("SELECT busy FROM nodes WHERE id=?", (node_id,)).fetchone()
        idle_peers = []
        if me and me["busy"] > 0:
            # spread work: a busy node leaves fresh jobs for idle nodes that are actively polling
            idle_peers = [(r["id"], node_model_names(row(r))) for r in c.execute(
                "SELECT * FROM nodes WHERE busy=0 AND enabled=1 AND id != ? AND last_seen >= ?",
                (node_id, now() - IDLE_PEER_WINDOW))]
        for j in candidates:
            if job_can_run_on(j, node_id, models):
                fresh = now() - j["created"] < IDLE_PEER_WINDOW
                if fresh and not j["target_node"] and any(job_can_run_on(j, pid, pm) for pid, pm in idle_peers):
                    continue
                c.execute(
                    """UPDATE jobs SET status='running', node_id=?, started=?, attempts=attempts+1, partial=''
                       WHERE id=? AND status='queued'""",
                    (node_id, now(), j["id"]),
                )
                c.execute("UPDATE nodes SET busy = busy + 1 WHERE id=?", (node_id,))
                return row(j)
    return None


# --------------------------------------------------------------------------- swarm engine

PLANNER_PROMPT = """You are the planner for a swarm of AI workers running on separate machines.
Break the GOAL into between 2 and {max_n} independent subtasks that can be worked on IN PARALLEL
by different workers who cannot see each other's work. Each subtask must be self-contained:
include all context the worker needs inside its prompt.

Reply with ONLY valid JSON, no markdown, in exactly this shape:
{{"subtasks": [{{"title": "short title", "prompt": "full standalone instructions for the worker"}}]}}

GOAL:
{goal}"""

SYNTH_PROMPT = """You are the synthesizer for a swarm of AI workers. The original goal was:

{goal}

Workers completed these parallel subtasks:

{results}

Merge their work into ONE complete, coherent, high-quality final answer to the original goal.
Resolve contradictions, remove duplication, fill small gaps yourself, and do not mention the workers or subtasks."""

JUDGE_PROMPT = """You are the judge of a council of independent AI models, each running on a different machine.
They were all asked:

{goal}

Their answers:

{results}

Produce the single best final answer. Take the strongest ideas from each, correct any errors,
and if the answers genuinely disagree on something important, say so briefly at the end
under a heading "Where the council disagreed"."""


def extract_json(text):
    if not text:
        return None
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)  # reasoning models
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.S)
    if fence:
        text = fence.group(1)
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except ValueError:
                        break
        start = text.find("{", start + 1)
    return None


def strip_think(text):
    return re.sub(r"<think>.*?</think>\s*", "", text or "", flags=re.S).strip()


def set_swarm(sid, **fields):
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    with tx() as c:
        c.execute(f"UPDATE swarms SET {cols} WHERE id=?", (*fields.values(), sid))


def swarm_cancelled(sid):
    r = db().execute("SELECT status FROM swarms WHERE id=?", (sid,)).fetchone()
    return r is None or r["status"] == "cancelled"


def wait_many(job_ids, sid):
    pending = set(job_ids)
    deadline = now() + JOB_WAIT_TIMEOUT
    while pending and now() < deadline:
        if swarm_cancelled(sid):
            return False
        for jid in list(pending):
            j = get_job(jid)
            if j is None or j["status"] in ("done", "failed", "cancelled"):
                pending.discard(jid)
        time.sleep(0.4)
    return not pending


def format_results(jobs):
    parts = []
    for i, j in enumerate(jobs, 1):
        label = j.get("title") or f"Answer {i}"
        body = strip_think(j["result"]) if j["status"] == "done" else f"(failed: {j.get('error')})"
        parts.append(f"### {i}. {label}\n{body}")
    return "\n\n".join(parts)


def run_swarm(sid):
    s = row(db().execute("SELECT * FROM swarms WHERE id=?", (sid,)).fetchone())
    goal = s["goal"]
    opts = json.loads(s["options"] or "{}")
    model = opts.get("model") or "auto"
    lead = opts.get("lead_model") or best_model() or model
    max_n = max(2, min(MAX_SUBTASKS, int(opts.get("max_subtasks") or 5)))
    try:
        if s["mode"] == "council":
            nodes = online_nodes()
            if not nodes:
                raise RuntimeError("no nodes online")
            ids = []
            for n in nodes:
                models = node_model_names(n)
                if not models:
                    continue
                ids.append(create_job("council", [{"role": "user", "content": goal}], model="auto",
                                      target_node=n["id"], swarm_id=sid, title=f"{n['name']}", priority=3))
            plan = [{"title": get_job(i)["title"], "job_id": i} for i in ids]
            set_swarm(sid, status="working", plan=json.dumps(plan))
            if not wait_many(ids, sid):
                return
            done = [get_job(i) for i in ids]
            # tag each answer with the model that produced it
            for d in done:
                d["title"] = f"{d['title']} ({d.get('model_used') or '?'})"
            if not any(d["status"] == "done" for d in done):
                raise RuntimeError("every council member failed")
            set_swarm(sid, status="synthesizing")
            final_id = create_job("judge", [{"role": "user", "content": JUDGE_PROMPT.format(
                goal=goal, results=format_results(done))}], model=lead, swarm_id=sid, title="Judge", priority=2)
        else:
            plan_id = create_job("plan", [{"role": "user", "content": PLANNER_PROMPT.format(
                goal=goal, max_n=max_n)}], model=lead, swarm_id=sid, title="Planner", priority=2,
                options={"temperature": 0.2})
            pj = wait_job(plan_id)
            if swarm_cancelled(sid):
                return
            subtasks = []
            if pj and pj["status"] == "done":
                parsed = extract_json(pj["result"]) or {}
                for st in (parsed.get("subtasks") or [])[:max_n]:
                    if isinstance(st, dict) and str(st.get("prompt", "")).strip():
                        subtasks.append({"title": str(st.get("title") or "Subtask")[:120],
                                         "prompt": str(st["prompt"])})
            if not subtasks:
                subtasks = [{"title": "Direct attempt", "prompt": goal}]
            ids = []
            for st in subtasks:
                ids.append(create_job("subtask", [
                    {"role": "system", "content": "You are one worker in a swarm. Do your subtask thoroughly. "
                                                  f"The overall goal of the swarm is: {goal}"},
                    {"role": "user", "content": st["prompt"]}],
                    model=model, swarm_id=sid, title=st["title"], priority=3))
            plan = [{"title": st["title"], "prompt": st["prompt"], "job_id": i} for st, i in zip(subtasks, ids)]
            set_swarm(sid, status="working", plan=json.dumps(plan))
            if not wait_many(ids, sid):
                return
            done = [get_job(i) for i in ids]
            if not any(d["status"] == "done" for d in done):
                raise RuntimeError("every subtask failed")
            set_swarm(sid, status="synthesizing")
            final_id = create_job("synth", [{"role": "user", "content": SYNTH_PROMPT.format(
                goal=goal, results=format_results(done))}], model=lead, swarm_id=sid, title="Synthesizer",
                priority=2)
        fj = wait_job(final_id)
        if swarm_cancelled(sid):
            return
        if not fj or fj["status"] != "done":
            raise RuntimeError(f"final step failed: {fj and fj.get('error')}")
        set_swarm(sid, status="done", final=strip_think(fj["result"]), finished=now())
    except Exception as e:  # noqa: BLE001 - surface every failure to the dashboard
        set_swarm(sid, status="failed", error=str(e), finished=now())


def start_swarm(goal, mode="swarm", options=None):
    sid = "swm_" + uuid.uuid4().hex[:12]
    with tx() as c:
        c.execute("INSERT INTO swarms (id, goal, mode, status, options, created) VALUES (?,?,?,?,?,?)",
                  (sid, goal, mode, "planning" if mode == "swarm" else "working", json.dumps(options or {}), now()))
    threading.Thread(target=run_swarm, args=(sid,), daemon=True, name=f"swarm-{sid}").start()
    return sid


# --------------------------------------------------------------------------- reaper

def reaper():
    """Requeue work stranded on dead nodes so a yanked power cord never loses a job."""
    while True:
        try:
            cutoff = now() - NODE_OFFLINE_AFTER
            with tx() as c:
                dead = [r["id"] for r in c.execute("SELECT id FROM nodes WHERE last_seen < ?", (cutoff,))]
                for nid in dead:
                    c.execute("UPDATE nodes SET busy=0 WHERE id=?", (nid,))
                    stranded = c.execute("SELECT id, attempts FROM jobs WHERE status='running' AND node_id=?",
                                         (nid,)).fetchall()
                    for j in stranded:
                        if j["attempts"] >= JOB_MAX_ATTEMPTS:
                            c.execute("UPDATE jobs SET status='failed', error='node died too many times', "
                                      "finished=? WHERE id=?", (now(), j["id"]))
                        else:
                            c.execute("UPDATE jobs SET status='queued', node_id=NULL, target_node=NULL, "
                                      "partial='' WHERE id=?", (j["id"],))
                # targeted jobs waiting on a node that is gone: let anyone take them
                if dead:
                    q = ",".join("?" * len(dead))
                    c.execute(f"UPDATE jobs SET target_node=NULL WHERE status='queued' AND target_node IN ({q})",
                              dead)
        except Exception as e:  # noqa: BLE001
            print(f"[reaper] {e}")
        time.sleep(5)


# --------------------------------------------------------------------------- app

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
auth.init(app, db, tx, HIVE_KEY, DB_PATH.parent)  # setup token lives next to the db


def provided_key():
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("X-Hive-Key", "")  # never from the url: urls end up in logs


def require_key():
    """machines only: nodes authenticate with the hive key."""
    k = provided_key()
    if not k or not hmac.compare_digest(k.encode(), HIVE_KEY.encode()):
        abort(401)


require_user = auth.require_user  # people (session + csrf) or machines (hive key)


@app.errorhandler(401)
def unauthorized(_):
    return jsonify({"error": {"message": "log in, or send the hive key as a bearer token", "type": "unauthorized"}}), 401


@app.errorhandler(403)
def forbidden(_):
    return jsonify({"error": {"message": "missing or bad csrf token", "type": "forbidden"}}), 403


def body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, "expected a JSON object")
    return data


# ---- pages

@app.get("/")
def index():
    if not auth.owner_exists():
        return redirect("/setup")
    if not auth.current_session():
        return redirect("/login")
    return render_template("index.html")


@app.get("/node.py")
def node_script():
    # public on purpose: the script contains no secrets, and it makes onboarding a one-liner
    return send_file(NODE_SCRIPT, mimetype="text/x-python", as_attachment=True, download_name="hive_node.py")


@app.get("/health")
def health():
    return jsonify({"ok": True})


# ---- node protocol

@app.post("/api/node/heartbeat")
def node_heartbeat():
    require_key()
    d = body()
    nid = str(d.get("node_id") or "")[:64]
    if not nid:
        abort(400, "node_id required")
    name = str(d.get("name") or "node")[:64]
    hw = json.dumps(d.get("hardware") or {})[:8000]
    models = json.dumps(d.get("models") or [])[:64000]
    slots = max(1, min(16, int(d.get("slots") or 1)))
    host = request.headers.get("CF-Connecting-IP") or request.remote_addr
    t = now()
    with tx() as c:
        c.execute(
            """INSERT INTO nodes (id, name, host, hardware, models, slots, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET name=excluded.name, host=excluded.host, hardware=excluded.hardware,
               models=excluded.models, slots=excluded.slots, last_seen=excluded.last_seen""",
            (nid, name, host, hw, models, slots, t, t),
        )
        # busy count is authoritative from the coordinator's side
        c.execute("UPDATE nodes SET busy=(SELECT COUNT(*) FROM jobs WHERE status='running' AND node_id=?) "
                  "WHERE id=?", (nid, nid))
        enabled = c.execute("SELECT enabled FROM nodes WHERE id=?", (nid,)).fetchone()["enabled"]
    return jsonify({"ok": True, "enabled": bool(enabled)})


@app.post("/api/node/claim")
def node_claim():
    require_key()
    d = body()
    nid = str(d.get("node_id") or "")
    n = row(db().execute("SELECT * FROM nodes WHERE id=?", (nid,)).fetchone())
    if not n:
        return jsonify({"error": "unknown node, send a heartbeat first"}), 409
    if not n["enabled"]:
        return "", 204
    with tx() as c:
        c.execute("UPDATE nodes SET last_seen=? WHERE id=?", (now(), nid))
    models = d.get("models") or node_model_names(n)
    j = claim_job(nid, models)
    if not j:
        return "", 204
    p = json.loads(j["payload"])
    return jsonify({"job_id": j["id"], "model": j["model"], "kind": j["kind"],
                    "messages": p["messages"], "options": p.get("options") or {}})


@app.post("/api/node/progress")
def node_progress():
    require_key()
    d = body()
    with tx() as c:
        c.execute("UPDATE jobs SET partial=?, model_used=COALESCE(?, model_used) "
                  "WHERE id=? AND node_id=? AND status='running'",
                  (str(d.get("partial") or "")[-200000:], d.get("model"), d.get("job_id"), d.get("node_id")))
        c.execute("UPDATE nodes SET last_seen=? WHERE id=?", (now(), d.get("node_id")))
        st = c.execute("SELECT status FROM jobs WHERE id=?", (d.get("job_id"),)).fetchone()
    # tell the node to stop if the job was cancelled or reassigned
    return jsonify({"continue": bool(st and st["status"] == "running")})


@app.post("/api/node/result")
def node_result():
    require_key()
    d = body()
    jid, nid = d.get("job_id"), d.get("node_id")
    ok = bool(d.get("ok"))
    tin = int(d.get("tokens_in") or 0)
    tout = int(d.get("tokens_out") or 0)
    tps = float(d.get("tps") or 0)
    t = now()
    with tx() as c:
        j = c.execute("SELECT * FROM jobs WHERE id=? AND node_id=?", (jid, nid)).fetchone()
        if not j or j["status"] != "running":
            return jsonify({"ok": False, "reason": "job not running on this node"}), 409
        if ok:
            c.execute("""UPDATE jobs SET status='done', result=?, partial='', model_used=?, tokens_in=?,
                         tokens_out=?, tps=?, finished=? WHERE id=?""",
                      (str(d.get("output") or ""), d.get("model"), tin, tout, tps, t, jid))
            c.execute("""UPDATE nodes SET jobs_done=jobs_done+1, tokens_out=tokens_out+?,
                         avg_tps=CASE WHEN avg_tps=0 THEN ? ELSE avg_tps*0.7 + ?*0.3 END,
                         busy=MAX(0, busy-1), last_seen=? WHERE id=?""",
                      (tout, tps, tps, t, nid))
        else:
            err = str(d.get("error") or "unknown error")[:4000]
            retry = j["attempts"] < JOB_MAX_ATTEMPTS and not j["target_node"]
            if retry:
                c.execute("UPDATE jobs SET status='queued', node_id=NULL, error=?, partial='' WHERE id=?", (err, jid))
            else:
                c.execute("UPDATE jobs SET status='failed', error=?, finished=? WHERE id=?", (err, t, jid))
            c.execute("UPDATE nodes SET busy=MAX(0, busy-1), last_seen=? WHERE id=?", (t, nid))
    return jsonify({"ok": True})


# ---- dashboard api

def node_view(n):
    n = dict(n)
    n["hardware"] = json.loads(n.get("hardware") or "{}")
    n["models"] = json.loads(n.get("models") or "[]")
    n["online"] = (n["last_seen"] or 0) >= now() - NODE_OFFLINE_AFTER
    return n


def job_view(j, full=False):
    j = dict(j)
    p = json.loads(j.pop("payload") or "{}")
    msgs = p.get("messages") or []
    last_user = next((m.get("content", "") for m in reversed(msgs) if m.get("role") == "user"), "")
    j["prompt_preview"] = last_user[:400]
    if full:
        j["messages"] = msgs
    else:
        if j.get("result"):
            j["result"] = j["result"][:4000]
        if j.get("partial"):
            j["partial"] = j["partial"][-4000:]
    return j


@app.get("/api/state")
def api_state():
    require_user()
    c = db()
    nodes = [node_view(r) for r in c.execute("SELECT * FROM nodes ORDER BY first_seen ASC")]
    jobs = [job_view(r) for r in c.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT 40")]
    swarms = [dict(r) for r in c.execute(
        "SELECT id, goal, mode, status, created, finished FROM swarms ORDER BY created DESC LIMIT 20")]
    stats = row(c.execute("""SELECT
        COALESCE(SUM(status='queued'),0) AS queued, COALESCE(SUM(status='running'),0) AS running,
        COALESCE(SUM(status='done'),0) AS done, COALESCE(SUM(status='failed'),0) AS failed,
        COALESCE(SUM(tokens_out),0) AS tokens_out FROM jobs""").fetchone())
    online = [n for n in nodes if n["online"]]
    stats.update({
        "nodes_total": len(nodes),
        "nodes_online": len(online),
        "fleet_tps": round(sum(n["avg_tps"] or 0 for n in online), 1),
        "fleet_ram_gb": round(sum((n["hardware"].get("ram_gb") or 0) for n in online), 1),
        "models": fleet_models(),
    })
    return jsonify({"nodes": nodes, "jobs": jobs, "swarms": swarms, "stats": stats, "now": now()})


@app.get("/api/jobs/<jid>")
def api_job(jid):
    require_user()
    j = get_job(jid)
    if not j:
        abort(404)
    return jsonify(job_view(j, full=True))


@app.post("/api/jobs/<jid>/cancel")
def api_job_cancel(jid):
    require_user()
    with tx() as c:
        c.execute("UPDATE jobs SET status='cancelled', finished=? WHERE id=? AND status IN ('queued','running')",
                  (now(), jid))
    return jsonify({"ok": True})


@app.post("/api/nodes/<nid>/toggle")
def api_node_toggle(nid):
    require_user()
    with tx() as c:
        c.execute("UPDATE nodes SET enabled = 1 - enabled WHERE id=?", (nid,))
    return jsonify({"ok": True})


@app.delete("/api/nodes/<nid>")
def api_node_delete(nid):
    require_user()
    with tx() as c:
        c.execute("DELETE FROM nodes WHERE id=?", (nid,))
    return jsonify({"ok": True})


@app.post("/api/swarms")
def api_swarm_create():
    require_user()
    d = body()
    goal = str(d.get("goal") or "").strip()
    if not goal:
        abort(400, "goal required")
    mode = d.get("mode") if d.get("mode") in ("swarm", "council") else "swarm"
    opts = {k: d[k] for k in ("model", "lead_model", "max_subtasks") if d.get(k)}
    return jsonify({"id": start_swarm(goal[:50000], mode, opts)})


@app.get("/api/swarms/<sid>")
def api_swarm(sid):
    require_user()
    s = row(db().execute("SELECT * FROM swarms WHERE id=?", (sid,)).fetchone())
    if not s:
        abort(404)
    s["plan"] = json.loads(s["plan"] or "[]")
    s["jobs"] = [job_view(r) for r in db().execute(
        "SELECT * FROM jobs WHERE swarm_id=? ORDER BY created ASC", (sid,))]
    return jsonify(s)


@app.post("/api/swarms/<sid>/cancel")
def api_swarm_cancel(sid):
    require_user()
    with tx() as c:
        c.execute("UPDATE swarms SET status='cancelled', finished=? WHERE id=? AND status NOT IN ('done','failed')",
                  (now(), sid))
        c.execute("UPDATE jobs SET status='cancelled', finished=? WHERE swarm_id=? AND status IN ('queued','running')",
                  (now(), sid))
    return jsonify({"ok": True})


# ---- OpenAI-compatible api

def normalize_messages(msgs):
    out = []
    for m in msgs or []:
        if not isinstance(m, dict):
            continue
        content = m.get("content", "")
        if isinstance(content, list):  # openai content parts -> plain text
            content = "\n".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
        out.append({"role": m.get("role", "user"), "content": str(content or "")})
    return out


def openai_options(d):
    opts = {}
    if d.get("temperature") is not None:
        opts["temperature"] = float(d["temperature"])
    if d.get("top_p") is not None:
        opts["top_p"] = float(d["top_p"])
    if d.get("max_tokens") or d.get("max_completion_tokens"):
        opts["num_predict"] = int(d.get("max_tokens") or d.get("max_completion_tokens"))
    if d.get("seed") is not None:
        opts["seed"] = int(d["seed"])
    if d.get("stop"):
        opts["stop"] = d["stop"] if isinstance(d["stop"], list) else [d["stop"]]
    return opts


@app.get("/v1/models")
def v1_models():
    require_user()
    t = int(now())
    data = [{"id": "auto", "object": "model", "created": t, "owned_by": "hivemind"},
            {"id": "hive-swarm", "object": "model", "created": t, "owned_by": "hivemind"},
            {"id": "hive-council", "object": "model", "created": t, "owned_by": "hivemind"}]
    data += [{"id": m, "object": "model", "created": t, "owned_by": "hivemind"} for m in fleet_models()]
    return jsonify({"object": "list", "data": data})


@app.post("/v1/chat/completions")
def v1_chat():
    require_user()
    d = body()
    model = str(d.get("model") or "auto")
    msgs = normalize_messages(d.get("messages"))
    if not msgs:
        abort(400, "messages required")
    stream = bool(d.get("stream"))
    cid = "chatcmpl-" + uuid.uuid4().hex[:24]
    created = int(now())

    # virtual models: the whole fleet collaborates on one answer
    if model in ("hive-swarm", "hive-council"):
        convo = "\n\n".join(f"{m['role'].upper()}: {m['content']}" for m in msgs) if len(msgs) > 1 else msgs[0]["content"]
        sid = start_swarm(convo, "swarm" if model == "hive-swarm" else "council")
        return swarm_as_completion(sid, cid, created, model, stream)

    if model != "auto" and not model.startswith("auto:") and not model_matches(model, fleet_models()):
        return jsonify({"error": {"message": f"no online node has model '{model}'. available: "
                                             f"{', '.join(fleet_models()) or 'none'}", "type": "model_not_found"}}), 404

    jid = create_job("chat", msgs, model=model, options=openai_options(d), priority=4)

    if not stream:
        j = wait_job(jid)
        if not j or j["status"] != "done":
            return jsonify({"error": {"message": (j or {}).get("error") or "job failed", "type": "hive_error"}}), 502
        return jsonify(completion_body(cid, created, j.get("model_used") or model, j["result"] or "",
                                       j["tokens_in"], j["tokens_out"]))

    def gen():
        sent = 0
        deadline = now() + JOB_WAIT_TIMEOUT
        yield sse(chunk(cid, created, model, {"role": "assistant", "content": ""}))
        while now() < deadline:
            j = get_job(jid)
            text = (j["result"] if j["status"] == "done" else j["partial"]) or ""
            if len(text) > sent:
                yield sse(chunk(cid, created, j.get("model_used") or model, {"content": text[sent:]}))
                sent = len(text)
            if j["status"] in ("done", "failed", "cancelled"):
                if j["status"] != "done":
                    yield sse({"error": {"message": j.get("error") or j["status"]}})
                yield sse(chunk(cid, created, j.get("model_used") or model, {}, finish="stop"))
                yield "data: [DONE]\n\n"
                return
            time.sleep(0.15)
        yield sse({"error": {"message": "timed out"}})
        yield "data: [DONE]\n\n"

    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def completion_body(cid, created, model, content, tin=0, tout=0):
    return {"id": cid, "object": "chat.completion", "created": created, "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": tin, "completion_tokens": tout, "total_tokens": tin + tout}}


def chunk(cid, created, model, delta, finish=None):
    return {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}


def sse(obj):
    return f"data: {json.dumps(obj)}\n\n"


def swarm_as_completion(sid, cid, created, model, stream):
    def final_state():
        deadline = now() + JOB_WAIT_TIMEOUT * 2
        while now() < deadline:
            s = row(db().execute("SELECT * FROM swarms WHERE id=?", (sid,)).fetchone())
            if s["status"] in ("done", "failed", "cancelled"):
                return s
            yield s
            time.sleep(0.5)

    if not stream:
        for _ in final_state():
            pass
        s = row(db().execute("SELECT * FROM swarms WHERE id=?", (sid,)).fetchone())
        if s["status"] != "done":
            return jsonify({"error": {"message": s.get("error") or s["status"], "type": "hive_error"}}), 502
        return jsonify(completion_body(cid, created, model, s["final"]))

    def gen():
        yield sse(chunk(cid, created, model, {"role": "assistant", "content": ""}))
        last = None
        for s in final_state():
            # status updates arrive as reasoning so clients that show it get a live view of the swarm
            if s["status"] != last:
                last = s["status"]
                yield sse(chunk(cid, created, model, {"reasoning_content": f"[hivemind] {last}...\n"}))
        s = row(db().execute("SELECT * FROM swarms WHERE id=?", (sid,)).fetchone())
        if s["status"] == "done":
            yield sse(chunk(cid, created, model, {"content": s["final"]}))
        else:
            yield sse({"error": {"message": s.get("error") or s["status"]}})
        yield sse(chunk(cid, created, model, {}, finish="stop"))
        yield "data: [DONE]\n\n"

    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# --------------------------------------------------------------------------- boot

def boot():
    init_db()
    # anything that was running when the coordinator died goes back in the queue
    with tx() as c:
        c.execute("UPDATE jobs SET status='queued', node_id=NULL, partial='' WHERE status='running'")
        c.execute("UPDATE nodes SET busy=0")
        c.execute("UPDATE swarms SET status='failed', error='coordinator restarted', finished=? "
                  "WHERE status NOT IN ('done','failed','cancelled')", (now(),))
    threading.Thread(target=reaper, daemon=True, name="reaper").start()


boot()

if __name__ == "__main__":
    import sys
    if "--reset-auth" in sys.argv:
        auth.reset_owner(tx)
        print(f"owner account, sessions and 2fa wiped. new setup token: {auth.ensure_setup_token()}")
        sys.exit(0)
    host = os.environ.get("HIVE_HOST", "0.0.0.0")
    port = int(os.environ.get("HIVE_PORT", 7777))
    print(f"""
  ╦ ╦╦╦  ╦╔═╗╔╦╗╦╔╗╔╔╦╗
  ╠═╣║╚╗╔╝║╣ ║║║║║║║ ║║   coordinator on http://{host}:{port}
  ╩ ╩╩ ╚╝ ╚═╝╩ ╩╩╝╚╝═╩╝   node key: coordinator/hive_key.txt
""")
    if not auth.owner_exists():
        print(f"  first run: open http://<this-machine>:{port}/setup  with setup token  {auth.ensure_setup_token()}\n")
    try:
        from waitress import serve  # optional, free, better under load
        serve(app, host=host, port=port, threads=64)
    except ImportError:
        app.run(host=host, port=port, threaded=True)
