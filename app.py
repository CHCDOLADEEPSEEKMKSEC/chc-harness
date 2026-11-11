#!/usr/bin/env python3
"""CHC HARNESS — product site + app (BAFOUNE-NET / CHCFLASH33).

One file, aiohttp, SQLite. Landing with the fire/neo design, signup + login with TOTP 2FA,
signed session cookie, and an app shell modelled on the DeepSeek Harness layout but built
for smaller models: chat, workspaces, permissions, plugins store, automation, search, settings.

Env:
  CHC_AI_PORT        listen port (default 8895)
  CHC_AI_DB          sqlite path (default /opt/chc-ai/chc.db)
  CHC_AI_SECRET      session signing secret (or a file path CHC_AI_SECRET_FILE)
  CHC_AI_LLM_URL     upstream chat completions (default http://127.0.0.1:8098/v1/chat/completions)
  CHC_AI_UPSTREAM_KEY file with a paid upstream key (optional)
  CHC_AI_PAY_ENV     file with payment details to display on the plan page (optional)
"""
import asyncio, base64, hashlib, hmac, json, os, pathlib, re, secrets, smtplib, sqlite3, struct, time
import datetime, urllib.request, urllib.parse, threading, uuid, subprocess
from aiohttp import web

# ----------------------------------------------------------------------------- cli
def _parse_cli():
    """One consistent command line. Every setting is a flag AND an env var; a flag wins."""
    import argparse
    ap = argparse.ArgumentParser(
        prog="chc-harness",
        description="CHC HARNESS — product site + agent app (BAFOUNE-NET / CHCFLASH33). "
                    "Settings come from flags or environment variables; flags win.")
    ap.add_argument("--name", default=os.environ.get("CHC_AI_NAME", "CHC"),
                    help="agent name used in the UI and the system prompt (default: CHC)")
    ap.add_argument("--host", default=os.environ.get("CHC_AI_HOST", "127.0.0.1"),
                    help="bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("CHC_AI_PORT", "8895")),
                    help="listen port (default 8895)")
    ap.add_argument("--db", default=os.environ.get("CHC_AI_DB", "/opt/chc-ai/chc.db"),
                    help="sqlite database path")
    ap.add_argument("--secret-file", default=os.environ.get("CHC_AI_SECRET_FILE", ""),
                    help="file holding the session signing secret")
    ap.add_argument("--secret", default=os.environ.get("CHC_AI_SECRET", ""),
                    help="session signing secret (prefer --secret-file)")
    ap.add_argument("--llm-url", default=os.environ.get("CHC_AI_LLM_URL",
                                                        "http://127.0.0.1:8098/v1/chat/completions"),
                    help="OpenAI-compatible chat completions endpoint for the local model")
    ap.add_argument("--model", default=os.environ.get("CHC_AI_MODEL", "local"),
                    help="model name sent to --llm-url (default: local)")
    ap.add_argument("--upstream-key", default=os.environ.get("CHC_AI_UPSTREAM_KEY",
                                                             "/opt/chc-ai/upstream.key"),
                    help="file with a paid upstream key (optional)")
    ap.add_argument("--smtp-env", default=os.environ.get("CHC_AI_SMTP_ENV", "/opt/chc-ai/smtp.env"))
    ap.add_argument("--pay-env", default=os.environ.get("CHC_AI_PAY_ENV", "/opt/chc-ai/pay.env"))
    ap.add_argument("--chainapi", default=os.environ.get("CHC_AI_CHAINAPI", "/opt/chc-ai/chainapi.env"),
                    help="file with the self-serve coin rails (address, price, api)")
    ap.add_argument("--billing-log", default=os.environ.get("CHC_AI_BILLING_LOG", "/opt/chc-ai/billing.log"),
                    help="append-only log of invoice and credit events")
    ap.add_argument("--files", default=os.environ.get("CHC_AI_FILES", "/opt/chc-ai/files"),
                    help="upload directory")
    ap.add_argument("--work", default=os.environ.get("CHC_AI_WORK", "/opt/chc-ai/work"),
                    help="tool workspace root")
    ap.add_argument("--free-day", type=int, default=int(os.environ.get("CHC_AI_FREE_DAY", "60")),
                    help="free-plan messages per day")
    ap.add_argument("--base", default=os.environ.get("CHC_AI_BASE", ""),
                    help="URL prefix when served behind a path proxy")
    ap.add_argument("--max-tool-calls", type=int, default=int(os.environ.get("CHC_AI_MAX_TOOL_CALLS", "0")),
                    help="max tool-call rounds per turn; 0 = UNLIMITED (default)")
    ap.add_argument("--purge-file-text", type=int, default=0, metavar="DAYS",
                    help="delete stored OCR/extracted text for files older than DAYS, then exit")
    ap.add_argument("--magic-ttl", type=int, default=900,
                    help="seconds a magic login link stays valid (default 900)")
    ap.add_argument("--make-user", default="", metavar="EMAIL",
                    help="create this account if missing, then print a login link")
    ap.add_argument("--set-password", default="", metavar="EMAIL",
                    help="set (or generate) this account's login password and print it once")
    ap.add_argument("--password", default="", metavar="PW",
                    help="use this password with --set-password instead of generating one")
    ap.add_argument("--magic-link", default="", metavar="EMAIL",
                    help="mint a one-time login link for EMAIL and exit")
    ap.add_argument("--public-url", default=os.environ.get("CHC_AI_PUBLIC_URL", ""),
                    help="public base URL used when printing a magic link")
    ap.add_argument("--admin-token", default=os.environ.get("CHC_AI_ADMIN_TOKEN", ""),
                    help="token for /admin/usage billing report")
    ap.add_argument("--new-key", default="", help="create an API key for this email, print it once, and exit")
    ap.add_argument("--label", default="default", help="label for --new-key")
    ap.add_argument("--revoke-key", default="", help="revoke a key by prefix and exit")
    ap.add_argument("--max-rounds", type=int, default=int(os.environ.get("CHC_AI_MAX_ROUNDS", "3")),
                    help="times a cut-short turn is asked to continue (default 3)")
    ap.add_argument("--max-tokens", type=int, default=int(os.environ.get("CHC_AI_MAX_TOKENS", "900")),
                    help="per-round output cap (default 1200)")
    return ap.parse_args()

CLI = _parse_cli()
AGENT_NAME = CLI.name
PORT = CLI.port
DBP = pathlib.Path(CLI.db)
# a fresh customer box mints its own 0600 session secret instead of dying on a missing file
_SECRET_PATH = pathlib.Path(CLI.secret_file) if CLI.secret_file else None
if _SECRET_PATH is not None:
    try:
        _SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not _SECRET_PATH.exists() or not _SECRET_PATH.read_text().strip():
            import secrets as _sec
            _SECRET_PATH.write_text(_sec.token_hex(32))
            os.chmod(_SECRET_PATH, 0o600)
    except Exception:
        pass
SECRET = (_SECRET_PATH.read_text().strip() if _SECRET_PATH else CLI.secret)
if not SECRET:
    SECRET = "dev-" + hashlib.sha256(str(DBP).encode()).hexdigest()  # dev only
def _ver():
    for c in (pathlib.Path(__file__).resolve().parent / "VERSION",):
        try:
            return c.read_text().strip()
        except Exception:
            return "dev"
VERSION = _ver()
LLM_URL = CLI.llm_url
LLM_MODEL = CLI.model

# ---- MODEL AUTODETECT: a box rarely has the model on the port we guessed. Probe the usual
# local servers, take the first that answers /v1/models, and pick a real model id from it.
# This is why a fresh install used to sit there with a dead model and no error.
def _probe_servers(cands, timeout=0.7):
    import urllib.request as _u
    for base in cands:
        try:
            with _u.urlopen(base + "/v1/models", timeout=timeout) as f:
                data = json.loads(f.read().decode())
            # ollama/openai style: {"data":[{"id":...}]}   llama.cpp style: {"models":[{"name":...}]}
            raw = data.get("data") or data.get("models") or []
            ids = [m.get("id") or m.get("name") or "" for m in raw if (m.get("id") or m.get("name"))]
            if ids:
                return base, ids
        except Exception:
            continue
    return None, []

_LLM_BASE = LLM_URL.split("/v1/")[0] if "/v1/" in LLM_URL else LLM_URL.rstrip("/")
_cands = list(dict.fromkeys([_LLM_BASE, "http://127.0.0.1:11434", "http://127.0.0.1:11436",
                             "http://127.0.0.1:11435", "http://127.0.0.1:8098",
                             "http://127.0.0.1:8080", "http://127.0.0.1:8000"]))
_base, _ids = _probe_servers(_cands)
if _base:
    LLM_URL = _base + "/v1/chat/completions"
    if str(LLM_MODEL) in ("local", "", "None"):
        LLM_MODEL = (next((i for i in _ids if "qwen2.5:3b" in i), None)
                     or next((i for i in _ids if "qwen" in i.lower()), None) or _ids[0])
else:
    print("[model] WARNING: no local model server answered on %s - chat will fail until one runs"
          % ", ".join(_cands), flush=True)
MAX_ROUNDS = None if CLI.max_rounds <= 0 else max(1, CLI.max_rounds)      # None = UNLIMITED
MAX_TOOL_CALLS = None if getattr(CLI, "max_tool_calls", 0) <= 0 else max(1, CLI.max_tool_calls)
# Hosted product has NO host shell and no infra stats. Self-host runs set CHC_SELF_HOST=1.
SELF_HOST = (os.environ.get("CHC_SELF_HOST", "").strip().lower() in ("1", "true", "yes", "on"))
ADMIN_TOKEN = (getattr(CLI, "admin_token", "") or "").strip()
PUBLIC_URL = os.environ.get("CHC_PUBLIC_URL", "")
MAX_TOKENS = max(64, CLI.max_tokens)
UPSTREAM_KEY_FILE = pathlib.Path(CLI.upstream_key)
# the house key can live on a read-only path; fall back to the vault copy rather than
# switching DeepSeek off because one file is in the wrong place.
for _c in (pathlib.Path("/mnt/ledger/vault/keys/deepseek_api.key"), pathlib.Path("/opt/chc-harness/upstream.key")):
    try:
        if not UPSTREAM_KEY_FILE.exists() and _c.is_file() and _c.read_text().strip():
            UPSTREAM_KEY_FILE = _c
            break
    except Exception:
        pass

ADMIN_TOKEN_FILE = pathlib.Path(os.environ.get('CHC_AI_ADMIN_TOKEN_FILE', '/opt/chc-ai/admin.token'))
# the unit starts without --admin-token: take it from the token file the installer wrote,
# otherwise /enter and the admin routes answer 403 on a box that was installed correctly.
if not ADMIN_TOKEN:
    try:
        ADMIN_TOKEN = ADMIN_TOKEN_FILE.read_text().strip()
    except Exception:
        pass


def admin_ok(tok):
    want = ADMIN_TOKEN
    if not want:
        try: want = ADMIN_TOKEN_FILE.read_text().strip()
        except Exception: want = ""
    return bool(want) and hmac.compare_digest((tok or ""), want)
UPSTREAM_DIR = pathlib.Path(os.environ.get("CHC_AI_UPSTREAM_DIR", "/opt/chc-ai/upstream"))

def user_key_path(uid):
    return UPSTREAM_DIR / ("%s.key" % uid)

def upstream_key_for(u):
    """The account's own DeepSeek key if it has one, else the house key (may be empty)."""
    try:
        p = user_key_path(u["id"])
        if p.is_file():
            k = p.read_text().strip()
            if k:
                return k
    except Exception:
        pass
    try:
        return UPSTREAM_KEY_FILE.read_text().strip()
    except Exception:
        return ""

def upstream_state(u):
    own = user_key_path(u["id"]).is_file()
    house = False
    try:
        house = bool(UPSTREAM_KEY_FILE.read_text().strip())
    except Exception:
        house = False
    on = bool(u["upstream_on"]) if "upstream_on" in u.keys() else False
    allows = (u["tier"] or "free") == "big"
    return {"plan_allows": allows, "own_key": own, "house_key": house,
            "on": on and allows and (own or house), "selected": (on and allows)}

SMTP_ENV = pathlib.Path(CLI.smtp_env)
PAY_ENV = pathlib.Path(CLI.pay_env)
FILES_DIR = pathlib.Path(CLI.files)
FREE_DAY = CLI.free_day

# ---- customer workspace: 1 GiB, hard, enforced by the app itself ----
WS_LIMIT = int(os.environ.get("CHC_AI_MAX_WS_BYTES", str(1024 ** 3)))   # 1 GiB
REFUSE_ROOT = os.environ.get("CHC_AI_REFUSE_ROOT", "0") == "1"          # customer boxes
# HOSTED=1: our hardware, sandboxed, quota'd. HOSTED=0: the customer's OWN machine -
# full access to that machine, their hardware, their rules, no quota.
HOSTED = os.environ.get("CHC_AI_HOSTED", "1") == "1"
if not HOSTED:
    WS_LIMIT = 0
    REFUSE_ROOT = False


# ---- S33 / DOLA SEE 7.7.8: data at rest for anything the house keeps ----
S33_ENGINE = os.environ.get("CHC_S33_ENGINE", "/opt/chc-ai/s33/SEE778_DOLA_FINAL.py")
S33_KEY = os.environ.get("CHC_S33_KEY", "/opt/chc-ai/s33/s33_master.key")
_S33 = {"mod": None, "key": None, "tried": False, "err": ""}


def s33_ready():
    if _S33["tried"]:
        return _S33["mod"] is not None
    _S33["tried"] = True
    try:
        import importlib.util as _ilu
        if not (os.path.isfile(S33_ENGINE) and os.path.isfile(S33_KEY)):
            _S33["err"] = "engine or key missing"
            return False
        spec = _ilu.spec_from_file_location("see778", S33_ENGINE)
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        key = open(S33_KEY, "rb").read()
        if len(key) != 32:
            _S33["err"] = "key must be 32 bytes"
            return False
        _S33["mod"], _S33["key"] = mod, key
        return True
    except Exception as e:
        _S33["err"] = str(e)[:120]
        return False


S33_CHUNK = 60000   # engine ceiling is 65479 bytes/packet; 60k keeps headroom


def s33_enc(pt: bytes, ad: bytes = b"chc:at-rest") -> bytes:
    """Multi-packet envelope: MAGIC + header + N packets. Fails closed - raises, never writes plaintext."""
    if not s33_ready():
        raise RuntimeError("S33 unavailable: " + _S33["err"])
    m = _S33["mod"]
    c = m.DualLockCipher(_S33["key"], sender_id=b"chc-harness")
    ph = hashlib.sha256(pt).hexdigest()
    chunks = [pt[i:i + S33_CHUNK] for i in range(0, len(pt), S33_CHUNK)] or [b""]
    hdr = json.dumps({"engine": "sse77.8", "sha256": ph, "bytes": len(pt), "chunks": len(chunks),
                      "ad": ad.decode("utf-8", "replace")}, sort_keys=True).encode()
    out = bytearray(b"S33:" + struct.pack(">I", len(hdr)) + hdr)
    for i, ch in enumerate(chunks):
        pkt = c.encrypt(ch, ad=b"%s|%d|%s" % (ad, i, ph.encode()))
        if isinstance(pkt, tuple):
            pkt = pkt[0]
        out += struct.pack(">I", len(pkt)) + pkt
    return bytes(out)


def s33_dec(env: bytes) -> bytes:
    if not env.startswith(b"S33:"):
        raise ValueError("not an S33 envelope")
    if not s33_ready():
        raise RuntimeError("S33 unavailable: " + _S33["err"])
    hl = struct.unpack(">I", env[4:8])[0]
    hdr = json.loads(env[8:8 + hl])
    off = 8 + hl
    m = _S33["mod"]
    c = m.DualLockCipher(_S33["key"], sender_id=b"chc-harness")
    chunks = []
    for i in range(int(hdr.get("chunks", 1))):
        n = struct.unpack(">I", env[off:off + 4])[0]
        pkt = env[off + 4:off + 4 + n]
        off += 4 + n
        res = c.decrypt(pkt, ad=b"%s|%d|%s" % (hdr["ad"].encode(), i, hdr["sha256"].encode()))
        chunks.append(res[0] if isinstance(res, tuple) else res)
    pt = b"".join(chunks)
    if hashlib.sha256(pt).hexdigest() != hdr["sha256"]:
        raise ValueError("S33 self-check failed (tamper)")
    return pt


def _s33_line(rec) -> bytes:
    """One memory record -> one S33 line (base64 envelope)."""
    import base64
    raw = json.dumps(rec, ensure_ascii=False).encode()
    return b"S33E:" + base64.b64encode(s33_enc(raw, ad=b"chc:memory-turn")) + b"\n"


def _s33_unline(line: bytes):
    import base64
    if line.startswith(b"S33E:"):
        return json.loads(s33_dec(base64.b64decode(line[5:])).decode())
    return json.loads(line.decode())


# ---- SPARKY memory: per-account, on disk, outside the container's disposable files ----
MEM_DIR = pathlib.Path(os.environ.get("CHC_AI_MEMORY", "/data/memory" if not HOSTED else "/opt/chc-ai/memory"))

def _mem_dir(uid):
    d = MEM_DIR / str(uid)
    d.mkdir(parents=True, exist_ok=True)
    return d

def memory_authorised(u):
    try:
        return bool(u["memory_on"]) if "memory_on" in u.keys() else False
    except Exception:
        return False


def _mem_append(uid, rec):
    """append-only turn record - one line per turn, never rewritten"""
    try:
        path = _mem_dir(uid) / "turns.jsonl"
        try:
            line = _s33_line(rec)          # S33 envelope or nothing - never plaintext
        except Exception:
            return                          # engine unavailable: refuse to persist, do not leak
        with open(path, "ab") as f:
            f.write(line)
    except Exception:
        pass

def _mem_facts(uid):
    out = []
    try:
        p = _mem_dir(uid) / "facts.jsonl"
        if p.is_file():
            for line in p.read_text().splitlines()[-400:]:
                try: out.append(_s33_unline(line.encode()))
                except Exception: pass
    except Exception:
        pass
    return out

_FACT_PATTERNS = [
    (r"\bmy name is ([A-Z][\w'-]{0,20}(?:\s[A-Z][\w'-]{0,20})?)", "name"),
    (r"\bcall me ([A-Z][\w'-]{0,20})", "name"),
    (r"\bi (?:prefer|like|want|always use|work with) ([^.!?\n]{3,90})", "preference"),
    (r"\bi (?:hate|never want|do not want|don't want) ([^.!?\n]{3,90})", "avoid"),
    (r"\b(?:remember|note) (?:that )?([^.!?\n]{5,140})", "remember"),
    (r"\bwe (?:decided|agreed) (?:to )?([^.!?\n]{5,140})", "decision"),
]

def _learn(uid, text):
    """distil durable facts from what the user said. Deduped, longest wins, reversible."""
    try:
        import re as _re
        low = (text or "")
        cand = []
        for pat, kind in _FACT_PATTERNS:
            for m in _re.finditer(pat, low, _re.I):
                fact = " ".join(m.group(1).split())[:180]
                if len(fact) >= 3:
                    cand.append((fact, kind))
        have = [f.get("fact","") for f in _mem_facts(uid)]
        added = []
        for fact, kind in sorted(cand, key=lambda c: -len(c[0])):
            fl = fact.lower()
            # skip if it is contained in something we already know, or contains it (keep the fuller one)
            if any(fl in h.lower() or h.lower() in fl for h in have + added):
                continue
            rec = {"ts": now(), "kind": kind, "fact": fact}
            with open(_mem_dir(uid) / "facts.jsonl", "a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            added.append(fact)
        return added
    except Exception:
        return []

def _recall(uid, query, k=8):
    """what SPARKY knows about this account, ranked against what is being asked"""
    try:
        q = set(w.lower() for w in (query or "").split() if len(w) > 2)
        facts = _mem_facts(uid)
        def score(f):
            t = set(w.lower().strip(".,!?") for w in f.get("fact","").split())
            return len(q & t) if q else 1
        facts = sorted(facts, key=score, reverse=True)[:k]
        return [f.get("fact","") for f in facts if f.get("fact")]
    except Exception:
        return []

def _report(uid, model, ok=True, note=""):
    """daily field report - what SPARKY did, so the house can read progress"""
    try:
        day = today()
        d = _mem_dir(uid)
        f = d / ("report-%s.json" % day)
        rep = {"day": day, "uid": uid, "model": model, "turns": 0, "facts": 0, "errors": 0, "notes": []}
        if f.is_file():
            try: rep = json.loads(f.read_text())
            except Exception: pass
        rep["turns"] = rep.get("turns", 0) + 1
        rep["facts"] = len(_mem_facts(uid))
        if not ok: rep["errors"] = rep.get("errors", 0) + 1
        if note: rep["notes"] = (rep.get("notes", []) + [note])[-20:]
        rep["updated"] = now()
        rep["models"] = rep.get("models", {})
        rep["models"][model] = rep["models"].get(model, 0) + 1
        f.write_text(json.dumps(rep, indent=1))
        return rep
    except Exception:
        return {}

def _ws_used(uid):
    """bytes used by this account's workspace (lstat, no symlink following)"""
    try:
        total = 0
        for root, dirs, files in os.walk(_workspace(uid), followlinks=False):
            for f in files:
                try: total += os.lstat(os.path.join(root, f)).st_size
                except OSError: pass
        return total
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# PLANS - the price list, in code, one source of truth.
# free      : 60 calls per day on the local Qwen, no card needed
# qwen6     : $5 per month - the upscaled Qwen, own slot, 1200 calls/day
# deepseek3 : $5 top-up    - $2.50 of DeepSeek upstream usage (~2,500 calls)
# ---------------------------------------------------------------------------
PLANS = {
    # price   : what we charge
    # cap     : calls included
    # unit_cost : internal only - what a call costs us. never printed to customers.
    "free":      {"label": "FREE",     "price": "$0", "period": "forever",
                  "price_usd": 0.0,    "days": 0,    "cap": 60,
                  "unit_cost": 0.00006,
                  "model": "Qwen 3-4B (local, on our box)", "tier": "free",
                  "calls": "60 calls / day"},
    "qwen6":     {"label": "QWEN+",    "price": "$5", "period": "per month",
                  "price_usd": 5.0,    "days": 30,   "cap": 1200,
                  "unit_cost": 0.00006,
                  "model": "Upscaled Qwen, own inference slot", "tier": "shell",
                  "calls": "1,200 calls / day"},
    "deepseek3": {"label": "DEEPSEEK", "price": "$5", "period": "top-up",
                  "price_usd": 5.0,    "days": 1,    "cap": 2500,   "credit_usd": 2.50,
                  "unit_cost": 0.000981,
                  "model": "DeepSeek upstream (house key) + API key access", "tier": "big",
                  "calls": "DeepSeek upstream included, valid 30 days"},
}

def plan_cost(key):
    """Internal only: what a plan's full daily cap costs us. Never shown to a customer."""
    pl = PLANS[key]
    if not pl["price_usd"] or not pl["days"]:
        return None
    cost = pl["unit_cost"] * pl["cap"] * pl["days"]
    return {"revenue": pl["price_usd"], "cost": round(cost, 4),
            "net": round(pl["price_usd"] - cost, 4)}


def _cost_check():
    """Boot-time sanity check: we must never sell a plan for less than it costs us."""
    rows, bad = [], []
    for k in PLANS:
        c = plan_cost(k)
        if not c:
            continue
        rows.append("%s %s/%s cap=%d rev=$%.2f cost=$%.2f net=$%.2f"
                    % (k, PLANS[k]["price"], PLANS[k]["period"], PLANS[k]["cap"],
                       c["revenue"], c["cost"], c["net"]))
        if c["net"] < 0:
            bad.append(k)
    print("[costs] " + " | ".join(rows), flush=True)
    if bad:
        print("[costs] WARNING: priced below cost: %s" % ", ".join(bad), flush=True)
    return bad


def plan_of(u):
    pl = (u["plan"] if "plan" in u.keys() else "") or "free"
    if pl in PLANS: return pl
    t = (u["tier"] if "tier" in u.keys() else "") or "free"
    if t == "big": return "deepseek3"
    if t == "shell": return "qwen6"
    return "free"

COOKIE = "chc_sess"
BASE = CLI.base

# ----------------------------------------------------------------------------- db
def db():
    c = sqlite3.connect(DBP)
    c.row_factory = sqlite3.Row
    c.execute("""create table if not exists users(
        id integer primary key autoincrement, email text unique, handle text, pw text, salt text,
        totp text, plan text default 'free', created text, verified integer default 0, paid_until text,
        tier text default 'free')""")
    try:
        c.execute("alter table users add column tier text default 'free'")
    except Exception:
        pass
    try:
        c.execute("alter table users add column tool_uid integer")
    except Exception:
        pass
    try:
        c.execute("alter table users add column remember_all integer default 0")
    except Exception:
        pass
    c.execute("""create table if not exists chats(
        id text primary key, uid integer, title text, created text, updated text, perms text default 'read-write')""")
    c.execute("""create table if not exists msgs(
        id integer primary key autoincrement, chat text, ts text, role text, content text)""")
    c.execute("""create table if not exists plugins(
        id integer primary key autoincrement, uid integer, name text, desc text, kind text,
        custom integer default 0, created text)""")
    c.execute("""create table if not exists tasks(
        id integer primary key autoincrement, uid integer, kind text, spec text, status text,
        created text, last_run text)""")
    c.execute("""create table if not exists usage(id integer primary key autoincrement, uid integer, ts text, day text, tok integer)""")
    c.execute("""create table if not exists magic(token text primary key, uid integer, exp integer, used integer default 0)""")
    c.execute("""create table if not exists api_keys(
        id integer primary key autoincrement, uid integer, label text, prefix text unique,
        key_hash text, created text, revoked integer default 0, last_used text,
        quota_tokens integer default 0)""")
    c.execute("""create table if not exists key_usage(
        id integer primary key autoincrement, key_id integer, day text,
        requests integer default 0, tokens integer default 0)""")
    c.execute("""create table if not exists email_codes(id integer primary key autoincrement, uid integer, code text,
                 exp integer, tries integer default 0)""")
    c.execute("""create table if not exists mail_queue(id integer primary key autoincrement, to_addr text,
                 subject text, body text, created text, sent integer default 0)""")
    c.execute("""create table if not exists claims(uid integer, token text, exp integer, used integer default 0)""")
    c.execute("""create table if not exists codes(code text primary key, plan text, days integer,
                 used integer default 0, uid integer default 0, created text)""")
    c.execute("""create table if not exists invoices(
        ref text primary key, uid integer, plan text, asset text, units integer, quote text,
        address text, status text default 'open', created text, paid_at text, txid text,
        code text, last_check integer default 0)""")
    c.execute("""create table if not exists assist_threads(
        id integer primary key autoincrement, uid integer, email text, subject text,
        created text, updated text, status text default 'open')""")
    c.execute("""create table if not exists assist_msgs(
        id integer primary key autoincrement, thread integer, uid integer, role text,
        body text, created text)""")
    c.execute("""create table if not exists tool_runs(
        id integer primary key autoincrement, chat text, ts text, name text, args text, result text)""")
    c.execute("""create table if not exists files(
        id integer primary key autoincrement, uid integer, name text, kind text, size integer,
        path text, ftext text, created text)""")
    try:
        c.execute("alter table users add column memory_on integer default 0")
    except Exception:
        pass
    try:
        c.execute("alter table users add column upstream_on integer default 0")
    except Exception:
        pass
    try:
        c.execute("alter table users add column model text default 'auto'")
    except Exception:
        pass
    c.execute("""create table if not exists feedback(
        id integer primary key autoincrement, uid integer, email text, kind text,
        body text, page text, created text, status text default 'new')""")
    c.execute("""create table if not exists publish(
        token text primary key, uid integer, fid integer, name text, sha256 text,
        size integer, created text)""")
    c.commit()
    return c

def now(): return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def today(): return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

# ------------------------------------------------------------------- auth primitives
def hash_key(k):
    return hashlib.sha256(k.encode()).hexdigest()

# ---- API keys (billing). Keys are stored HASHED; the plaintext is shown once at creation.
def new_api_key(uid, label="default"):
    raw = "chc_" + secrets.token_urlsafe(30)
    prefix = raw[4:12]
    c = db()
    c.execute("insert into api_keys(uid,label,prefix,key_hash,created) values(?,?,?,?,?)",
              (uid, (label or "default")[:60], prefix, hash_key(raw), now()))
    c.commit(); c.close()
    return raw, prefix

def user_from_key(request):
    hdr = request.headers.get("Authorization", "")
    if not hdr.startswith("Bearer "): return None, None
    raw = hdr[7:].strip()
    if not raw.startswith("chc_"): return None, None
    c = db()
    row = c.execute("""select k.id kid, k.uid uid, k.revoked rev, u.email em, u.plan pl
                       from api_keys k join users u on u.id=k.uid where k.key_hash=?""", (hash_key(raw),)).fetchone()
    if not row or row["rev"]:
        c.close(); return None, None
    c.execute("update api_keys set last_used=? where id=?", (now(), row["kid"])); c.commit(); c.close()
    return dict(id=row["uid"], email=row["em"], plan=row["pl"]), row["kid"]

def auth_user(request):
    """Session cookie first, then a billing API key in Authorization: Bearer."""
    u = current_user(request)
    if u: return u, None
    return user_from_key(request)

def meter(uid, key_id, tokens):
    c = db()
    c.execute("insert into usage(uid,ts,day,tok) values(?,?,?,?)", (uid, now(), today(), 1))
    if key_id:
        r = c.execute("select id from key_usage where key_id=? and day=?", (key_id, today())).fetchone()
        if r: c.execute("update key_usage set requests=requests+1, tokens=tokens+? where id=?", (int(tokens), r["id"]))
        else: c.execute("insert into key_usage(key_id,day,requests,tokens) values(?,?,1,?)", (key_id, today(), int(tokens)))
    c.commit(); c.close()

def pw_hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()

def new_salt(): return secrets.token_hex(16)

def gen_password(n: int = 16) -> str:
    """Human-typable strong password: no 0/O, 1/l/I, and always one of each class."""
    letters = "abcdefghijkmnopqrstuvwxyz"
    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    digits = "23456789"
    symbols = "!@#$%^&*-_=+"
    pool = letters + upper + digits + symbols
    while True:
        pw = "".join(secrets.choice(pool) for _ in range(n))
        if (any(c in letters for c in pw) and any(c in upper for c in pw)
                and any(c in digits for c in pw) and any(c in symbols for c in pw)):
            return pw

def set_user_password(c, email: str, pw: str = "") -> tuple:
    """Set (or generate) the login password for an account. Returns (email, password)."""
    email = (email or "").strip().lower()
    row = c.execute("select id from users where lower(email)=?", (email,)).fetchone()
    if not row:
        salt0 = new_salt()
        handle = email.split("@")[0][:24] or "owner"
        c.execute("insert into users(email,handle,pw,salt,totp,plan,created,verified) values(?,?,?,?,?,?,?,1)",
                  (email, handle, pw_hash(secrets.token_hex(16), salt0), salt0, secrets.token_hex(10), "free", now()))
        c.commit()
        row = c.execute("select id from users where lower(email)=?", (email,)).fetchone()
    pw = pw or gen_password()
    salt = new_salt()
    c.execute("update users set pw=?, salt=?, verified=1 where id=?", (pw_hash(pw, salt), salt, row["id"]))
    c.commit()
    return email, pw

def sign(payload: str) -> str:
    mac = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{mac}".encode()).decode()

def unsign(tok: str):
    try:
        raw = base64.urlsafe_b64decode(tok.encode()).decode()
    except Exception:
        return None
    payload, _, mac = raw.rpartition("|")
    if not payload: return None
    if hmac.compare_digest(mac, hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()):
        return payload
    return None

def b32(secret_bytes: bytes) -> str:
    return base64.b32encode(secret_bytes).decode().rstrip("=")

def totp(secret_b32: str, at: float = None, step: int = 30, digits: int = 6) -> str:
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    counter = int((at or time.time()) // step)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    off = h[-1] & 0x0F
    code = (struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f"{code:0{digits}d}"

def totp_ok(secret_b32: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not re.fullmatch(r"\d{6}", code): return False
    t = time.time()
    return any(hmac.compare_digest(totp(secret_b32, t + d * 30), code) for d in (-1, 0, 1))

def totp_uri(secret_b32: str, acct: str, issuer="CHC HARNESS") -> str:
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(issuer)}:{quote(acct)}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&period=30&digits=6&algorithm=SHA1")

def current_user(request):
    tok = request.cookies.get(COOKIE)
    if not tok: return None
    uid = unsign(tok)
    if not uid or not uid.startswith("u:"): return None
    c = db()
    try:
        c.execute("alter table users add column upstream_on integer default 0")
    except Exception:
        pass
    try:
        c.execute("alter table users add column model text default 'auto'")
    except Exception:
        pass
    row = c.execute("select id,email,handle,plan,paid_until,tier,upstream_on,memory_on from users where id=?", (int(uid[2:]),)).fetchone()
    c.close()
    return dict(row) if row else None

def set_session(resp, uid, method="unknown", request=None):
    """Issue a session AND write an audit row: who, how, from where. If a session is ever handed
    out on a path we did not intend, /admin/logins names the method instead of us guessing."""
    resp.set_cookie(COOKIE, sign(f"u:{uid}"), httponly=True, samesite="Lax", max_age=60 * 60 * 24 * 30,
                    path="/", secure=False)
    try:
        c = db()
        c.execute("""create table if not exists login_audit(id integer primary key autoincrement,
                     ts integer, uid integer, method text, ip text, ua text)""")
        c.execute("insert into login_audit(ts,uid,method,ip,ua) values(?,?,?,?,?)",
                  (int(time.time()), int(uid), str(method)[:40],
                   (request.remote if request is not None else "")[:60],
                   ((request.headers.get("User-Agent") if request is not None else "") or "")[:160]))
        c.commit(); c.close()
    except Exception:
        pass

# ----------------------------------------------------------------------------- LLM
def _stream_llm(messages, max_tokens, on_delta, on_done, on_error, upstream=False, stop_when=None,
                result=None, up_key=None):
    if upstream and ((up_key or '').strip() or (UPSTREAM_KEY_FILE.exists() and UPSTREAM_KEY_FILE.read_text().strip())):
        url = "https://api.deepseek.com/chat/completions"
        headers = {"Content-Type": "application/json",
                   "Authorization": "Bearer " + (up_key or UPSTREAM_KEY_FILE.read_text().strip())}
        body = {"model": "deepseek-chat", "messages": messages, "max_tokens": max_tokens,
                "temperature": 0.5, "frequency_penalty": 0.25, "presence_penalty": 0.25, "stream": True}
    else:
        url = LLM_URL
        headers = {"Content-Type": "application/json"}
        msgs = [dict(m) for m in messages]
        if msgs and msgs[0].get("role") == "system":
            msgs[0]["content"] = msgs[0]["content"] + "\n/no_think"
        body = {"model": LLM_MODEL, "messages": msgs, "max_tokens": max_tokens, "temperature": 0.45,
                "top_p": 0.9, "stream": True, "chat_template_kwargs": {"enable_thinking": False}}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    CLOSERS = ("</think", "</think>", "<｜end▁of▁thinking｜>", "<｜end▁of▁thinking｜>")
    inside = False
    held = ""
    def flush_after(marker):
        nonlocal inside, held
        i = -1; used = ""
        for m in CLOSERS:
            j = held.find(m)
            if j >= 0 and (i < 0 or j < i): i, used = j, m
        if i < 0: return False
        tail = held[i + len(used):]
        if used.endswith(">") and not tail.startswith(">"): pass
        tail = tail.lstrip(">").lstrip("\n")
        inside = False; held = ""
        if tail: on_delta(tail)
        return True
    def emit_clean(piece):
        nonlocal inside, held
        if not inside and ("<think" in piece or "<思考" in piece):
            inside = True
            held = piece[piece.find("<think") + len("<think"):] if "<think" in piece else piece
            if held.startswith(">"): held = held[1:]
            flush_after(None)
            return
        if inside:
            held += piece
            if not flush_after(None) and len(held) > 4000:
                # runaway: model never closed thinking — drop it, start fresh
                held = ""; inside = False
            return
        if "</think" in piece:
            on_delta(piece.split("</think", 1)[0]); return
        on_delta(piece)
    try:
        with urllib.request.urlopen(req, timeout=900) as r:
            for raw in r:
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("data:"): continue
                d = line[5:].strip()
                if d == "[DONE]": break
                try: j = json.loads(d)
                except Exception: continue
                ch = (j.get("choices") or [{}])[0]
                _d = ch.get("delta") or {}
                # Qwen3 thinking builds stream the answer in reasoning_content
                piece = _d.get("content") or _d.get("reasoning_content") or ""
                if piece: emit_clean(piece)
                fr = ch.get("finish_reason")
                if fr and result is not None: result["finish"] = fr
                if stop_when and stop_when(): break
    except Exception as e:
        on_error(f"{type(e).__name__}: {e}")
        return
    on_done()

# -------------------------------------------------------------------------- templates
def _stream_turn(messages, max_tokens, on_delta, on_done, on_error, upstream=False,
                 stop_when=None, on_note=None, max_rounds=None, up_key=None):
    """Run ONE turn to completion, the way an agent should.

    Small local models stop early: they hit the token cap, the stream drops, or they
    answer nothing at all. Instead of handing the user a half sentence, the turn is
    re-opened — the model is told to continue exactly where it stopped — until it
    finishes cleanly or the round budget runs out. Rounds, cap and URL are all CLI flags.
    """
    _rlim = max_rounds if max_rounds is not None else MAX_ROUNDS
    rounds = 10 ** 9 if _rlim is None else max(1, _rlim)
    convo = [dict(m) for m in messages]
    written = ""
    for rnd in range(1, rounds + 1):
        seen = {"n": 0}
        result = {"finish": None}
        err = {"v": None}

        def delta(piece):
            if not piece:
                return
            seen["n"] += len(piece)
            on_delta(piece)

        def failed(msg):
            err["v"] = msg

        _stream_llm(convo, max_tokens, delta, lambda: None, failed, upstream, stop_when, result, up_key)
        finish = result.get("finish")
        if err["v"]:
            low = err["v"].lower()
            transient = ("timeout" in low or "timed out" in low or "connection" in low
                         or "temporar" in low or "reset" in low)
            if transient and rnd < rounds:
                if on_note: on_note("upstream hiccup (%s) — retrying (round %d/%d)" % (str(err["v"])[:120], rnd + 1, rounds))
                continue
            on_error(err["v"]); return
        if stop_when and stop_when():
            break
        cut_short = finish in ("length", "max_tokens", "max_output")
        if cut_short and rnd < rounds:
            if on_note: on_note("output cut short — continuing (round %d/%d)" % (rnd + 1, rounds))
            convo.append({"role": "assistant", "content": "(answer continued above)"})
            convo.append({"role": "user",
                          "content": "Continue exactly where you stopped. Do not repeat anything you already "
                                     "wrote. Finish the answer completely, then stop."})
            continue
        if seen["n"] == 0 and rnd < rounds:
            if on_note: on_note("no output — asking again (round %d/%d)" % (rnd + 1, rounds))
            convo.append({"role": "user", "content": "Answer the previous request now, directly."})
            continue
        break
    on_done()

SITE = "https://ai.94-237-56-140.sslip.io"
SITE_FOOT = """
<footer style="margin-top:60px;border-top:1px solid #1d2230;padding:26px 20px 40px">
<div class="wrap" style="display:flex;flex-wrap:wrap;gap:10px 22px;font-size:13px;color:#8892a6">
<a href="/">HOME</a><a href="/free">FREE</a><a href="/self-host">SELF-HOST</a>
<a href="/compare">COMPARE</a><a href="/security">SECURITY</a><a href="/blog">NOTES</a><a href="/plan">PLANS</a>
<a href="/get">DOWNLOAD</a><a href="/signup">SIGN UP</a><a href="/assist">ASSIST</a>
<a href="/sitemap.xml">SITEMAP</a>
<div style="flex-basis:100%;color:#5d6779;font-size:11px;margin-top:6px">
CHC HARNESS — your own AI workspace. Free tier: 60 calls a day, no card.</div>
</div></footer>"""


SITE_DESC = ("Your own AI workspace: 60 free calls a day, no card. Chat, code, files and tools in a "
             "1 GB private space. Run it hosted, or self-host on your own machine with full access.")

def page(title, body, script="", css="", cls="", desc="", path=""):
    _d = (desc or SITE_DESC).replace('"', "'")
    _u = SITE + (path or "")
    # structured data: gives Google a machine-readable description of the product and, on /free,
    # of the actual FAQ. Cheap, no account, and it is the part of "marketing" a crawler can use.
    import json as _json
    _app_ld = {"@context": "https://schema.org", "@type": "SoftwareApplication",
               "name": "CHC HARNESS", "applicationCategory": "BusinessApplication",
               "operatingSystem": "Web, Linux, macOS, Android", "url": SITE,
               "description": SITE_DESC,
               "offers": [{"@type": "Offer", "price": "0", "priceCurrency": "EUR",
                           "name": "Free tier — 60 calls a day, no card"},
                          {"@type": "Offer", "price": "5", "priceCurrency": "EUR",
                           "name": "QWEN+ hosted, per month"}]}
    _faq_ld = {"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": [
        {"@type": "Question", "name": "Is there a free tier with no credit card?",
         "acceptedAnswer": {"@type": "Answer", "text": "Yes. 60 calls a day and 1 GB of private workspace, email sign-up only, no card."}},
        {"@type": "Question", "name": "Can I self-host it?",
         "acceptedAnswer": {"@type": "Answer", "text": "Yes. Same harness runs on your own machine with full access and no call cap; you own the hardware and the data."}},
        {"@type": "Question", "name": "Where do my chats and files live?",
         "acceptedAnswer": {"@type": "Answer", "text": "In your own workspace. Hosted customers are sandboxed to their own area and have no access to the house audit chain or the host shell."}}]}
    _ld = _app_ld if (path or "") != "/free" else _faq_ld
    _ld_tag = '<script type="application/ld+json">' + _json.dumps(_ld, separators=(",", ":")) + '</script>' 
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>{title}</title>
<meta name=description content="{_d}">
<meta name=robots content="index,follow">
<meta name="google-site-verification" content="eOVV0zf_XCTLB5q9rASMDIzoVMfFVc6-4Y5vk67BfXs">
<link rel=canonical href="{_u}">{_ld_tag}
<meta property="og:type" content="website"><meta property="og:title" content="{title}">
<meta property="og:description" content="{_d}"><meta property="og:url" content="{_u}">
<meta property="og:site_name" content="CHC HARNESS">
<meta name=twitter:card content="summary_large_image"><meta name=twitter:title content="{title}">
<meta name=twitter:description content="{_d}">
<style>
:root{{--bg:#05060a;--panel:#0d1017;--line:#1d2230;--ink:#e8edf7;--dim:#8892a6;--neo:#39ff9e;--blue:#4f8cff;--purple:#a855f7;--red:#ff3b30;--amber:#f59e0b}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,"DejaVu Sans",sans-serif}}
a{{color:var(--neo);text-decoration:none}}
.wrap{{max-width:1080px;margin:0 auto;padding:0 20px}}
.btn{{display:inline-block;padding:12px 22px;border-radius:12px;background:linear-gradient(135deg,var(--neo),#14c47a);color:#04110a;font-weight:800;border:0;cursor:pointer;letter-spacing:.02em}}
.btn.ghost{{background:transparent;border:1px solid var(--line);color:var(--ink);font-weight:600}}
.btn.small{{padding:8px 14px;border-radius:10px;font-size:13px}}
input,textarea,select{{background:#0b0f16;border:1px solid var(--line);border-radius:10px;color:var(--ink);padding:11px 12px;font:14px/1.5 inherit;width:100%}}
input:focus,textarea:focus{{outline:none;border-color:var(--neo)}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px}}
.err{{color:#ff7b72;font-size:13px}}
.mono{{font-family:ui-monospace,"DejaVu Sans Mono",monospace}}
{css}
</style></head><body class="{cls}">{body}
{SITE_FOOT}
<script>{script}</script></body></html>"""

FIRE_CSS = """
/* ---- the fire backdrop: red base, electric neo-blue + purple clash ---- */
body.landing{background:#05060a;overflow-x:hidden}
.fire{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden;
  background:
    radial-gradient(60% 70% at 70% 20%, rgba(79,140,255,.35), transparent 60%),
    radial-gradient(55% 65% at 25% 35%, rgba(168,85,247,.32), transparent 60%),
    radial-gradient(70% 80% at 50% 100%, rgba(255,59,48,.55), transparent 65%),
    radial-gradient(40% 40% at 85% 85%, rgba(255,140,0,.35), transparent 60%),
    #05060a;}
.flame{position:absolute;bottom:-18vh;width:46vw;height:80vh;filter:blur(60px);opacity:.55;
  background:radial-gradient(closest-side, rgba(255,90,0,.95), rgba(255,59,48,.35) 55%, transparent 70%);
  animation:lick 7s ease-in-out infinite alternate}
.flame.b{left:18vw;animation-delay:-2s;background:radial-gradient(closest-side, rgba(79,140,255,.85), rgba(168,85,247,.35) 60%, transparent 72%)}
.flame.c{left:-8vw;width:38vw}
.flame.d{left:62vw;width:40vw;animation-delay:-4s;background:radial-gradient(closest-side, rgba(168,85,247,.8), rgba(255,59,48,.28) 62%, transparent 74%)}
@keyframes lick{0%{transform:translateY(0) scale(1)}50%{transform:translateY(-4vh) scale(1.06)}100%{transform:translateY(-1vh) scale(.98)}}
.spark{position:absolute;width:2px;height:2px;border-radius:50%;background:#ffd08a;opacity:.7;animation:rise linear infinite}
@keyframes rise{from{transform:translateY(0);opacity:.9}to{transform:translateY(-110vh);opacity:0}}
.stage{position:relative;z-index:2}
/* ---- CHC HARNESS wordmark: neo green, black outline, big ---- */
.wordmark{font:900 clamp(46px,11vw,150px)/0.9 system-ui,"DejaVu Sans",sans-serif;letter-spacing:-.03em;
  color:var(--neo);
  -webkit-text-stroke:6px #000;
  paint-order:stroke fill;
  text-shadow:0 0 1px #000, 0 0 26px rgba(57,255,158,.55), 0 14px 40px rgba(0,0,0,.85);
  margin:0}
.wordmark .see{display:block;font-size:.30em;-webkit-text-stroke:3px #000;color:#fff;
  text-shadow:0 0 18px rgba(79,140,255,.8);letter-spacing:.22em}
.emblem{display:inline-flex;align-items:center;gap:10px;padding:8px 14px;border-radius:999px;
  background:radial-gradient(120% 120% at 20% 0%, #ff5a00, #ff3b30 55%, #7a0000);
  border:1px solid #ff8a5c;box-shadow:0 0 24px rgba(255,59,48,.55);color:#fff;font:900 12px/1 system-ui;letter-spacing:.16em}
.emblem b{color:#bdf7d6}
.top-actions{position:fixed;top:18px;right:18px;display:flex;gap:10px;align-items:center;z-index:5}
.tagchip{padding:7px 12px;border-radius:999px;border:1px solid var(--line);background:rgba(5,6,10,.6);color:var(--dim);font:700 11px/1 system-ui;letter-spacing:.12em}
.hero{min-height:92vh;display:flex;flex-direction:column;justify-content:center;padding:110px 0 60px}
.sub{color:#cfd8e8;font-size:clamp(15px,1.6vw,19px);max-width:600px;margin:18px 0 26px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-top:36px}
.feat{background:rgba(13,16,23,.82);border:1px solid var(--line);border-radius:14px;padding:16px}
.feat h4{margin:0 0 6px;font:700 13px/1.2 system-ui;letter-spacing:.1em;color:var(--neo)}
.feat p{margin:0;color:var(--dim);font-size:13px}
.authshell{display:grid;grid-template-columns:1.1fr .9fr;gap:34px;align-items:start;margin:40px 0 60px}
@media(max-width:860px){.authshell{grid-template-columns:1fr}}
.tabs{display:flex;gap:8px;margin-bottom:14px}
.tab{flex:1;text-align:center;padding:10px;border-radius:10px;border:1px solid var(--line);cursor:pointer;font:700 12px/1 system-ui;letter-spacing:.12em;color:var(--dim)}
.tab.on{background:rgba(57,255,158,.12);border-color:var(--neo);color:var(--neo)}
.field{margin:10px 0}
.field label{display:block;font:700 11px/1 system-ui;letter-spacing:.12em;color:var(--dim);margin-bottom:6px}
.badge{display:inline-block;padding:3px 9px;border-radius:999px;background:rgba(57,255,158,.12);border:1px solid rgba(57,255,158,.35);color:var(--neo);font:800 10px/1.6 system-ui;letter-spacing:.12em}
"""

APPLET_CSS = """
.app{display:grid;grid-template-columns:288px 1fr;height:100vh;overflow:hidden}
.side{background:#080b11;border-right:1px solid var(--line);display:flex;flex-direction:column;min-height:0;transition:opacity .12s ease}
.app.sbcol{grid-template-columns:0 1fr}
.app.sbcol .side{width:0;padding:0;border-right:0;overflow:hidden;visibility:hidden}
#sbtog{margin-left:auto;background:#0f141d;border:1px solid #1b2230;color:#8892a6;border-radius:8px;padding:5px 9px;font:900 13px/1 system-ui;cursor:pointer}
#sbtog:hover{color:var(--neo);border-color:rgba(57,255,158,.35)}
#chtog{margin-left:auto;background:#0f141d;border:1px solid #1b2230;color:#8892a6;border-radius:6px;padding:1px 7px;font:900 11px/1.5 system-ui;cursor:pointer}
#chtog:hover{color:var(--neo);border-color:rgba(57,255,158,.35)}
#chatlist.off{display:none}
#chatlist.off + #chatmore{display:none}
#sbopen{position:fixed;left:0;top:50%;transform:translateY(-50%);z-index:99999;display:block;background:#101a16;border:1px solid rgba(57,255,158,.45);border-left:0;color:var(--neo);border-radius:0 10px 10px 0;padding:16px 5px;font:900 11px/1 system-ui;letter-spacing:.16em;cursor:pointer;box-shadow:2px 0 14px rgba(0,0,0,.7);writing-mode:vertical-rl;text-orientation:mixed}
#sbopen:hover{background:#16241d;color:#fff}
.app:not(.sbcol) #sbopen{background:#0b1017;border-color:#1b2230;color:#8892a6}
.brand{display:flex;align-items:center;gap:10px;padding:16px 14px;border-bottom:1px solid var(--line)}
.brand b{font:900 15px/1 system-ui;letter-spacing:.06em;color:var(--neo);-webkit-text-stroke:1px #000}
.brand small{color:var(--dim);font-size:10px;letter-spacing:.18em}
.newchat{margin:12px 14px;padding:11px;border-radius:11px;background:linear-gradient(135deg,rgba(57,255,158,.16),rgba(79,140,255,.10));border:1px solid rgba(57,255,158,.35);color:var(--neo);font:800 12px/1 system-ui;letter-spacing:.1em;cursor:pointer;text-align:center}
.nav{padding:6px 8px;overflow:auto;flex:1;min-height:0}
.nav .item{display:flex;gap:10px;align-items:center;padding:9px 10px;border-radius:9px;color:#c6cedd;font-size:13.5px;cursor:pointer;border:1px solid transparent}
.nav .item:hover{background:#0f141d;border-color:#1b2230}
.nav .item.on{background:#101a16;border-color:rgba(57,255,158,.3);color:var(--neo)}
.nav h5{margin:14px 10px 6px;font:700 10px/1 system-ui;letter-spacing:.16em;color:#5d6779}
.chatrow{display:block;padding:7px 10px;border-radius:8px;color:#aab4c6;font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer}
.chatrow:hover{background:#0f141d;color:var(--ink)}
.sidefoot{border-top:1px solid var(--line);padding:10px 12px;font-size:12px;color:var(--dim)}
.main{display:flex;flex-direction:column;min-height:0;background:radial-gradient(120% 90% at 80% -10%, rgba(79,140,255,.10), transparent 55%),#05060a}
.topbar{display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.chip{padding:6px 11px;border-radius:999px;border:1px solid var(--line);color:var(--dim);font:700 11px/1 system-ui;letter-spacing:.1em;background:#0b0f16;cursor:pointer}
.chip.on{background:rgba(57,255,158,.14);border-color:rgba(57,255,158,.5);color:var(--neo)}
.chip.perm.on{background:rgba(79,140,255,.14);border-color:rgba(79,140,255,.5);color:#9cc3ff}
.grow{flex:1}
#dot{width:10px;height:10px;border-radius:50%;background:#4a5263}
#dot.s{background:var(--neo);animation:pulse 1s infinite}
#dot.e{background:var(--red);box-shadow:0 0 12px 2px var(--red)}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(57,255,158,.5)}70%{box-shadow:0 0 0 8px rgba(57,255,158,0)}100%{box-shadow:0 0 0 0 rgba(57,255,158,0)}}
.msgs{flex:1;overflow:auto;padding:22px 16px 8px}
.msg{max-width:820px;margin:0 auto 16px;display:flex;gap:12px}
.who{width:28px;height:28px;border-radius:8px;flex:0 0 28px;display:grid;place-items:center;font:900 12px/1 system-ui}
.who.u{background:#1b2230;color:#cfd8e8}
.who.a{background:linear-gradient(135deg,var(--neo),#14c47a);color:#04110a}
.bub{background:#0d1119;border:1px solid var(--line);border-radius:12px;padding:11px 14px;white-space:pre-wrap;word-wrap:break-word;font-size:14.5px;min-width:0}
.composer{border-top:1px solid var(--line);padding:12px 16px 16px;background:rgba(8,11,17,.85)}
.composer .inner{max-width:820px;margin:0 auto}
.composer textarea{min-height:64px;max-height:34vh;resize:none}
.sendrow{display:flex;align-items:center;gap:10px;margin-top:8px}
.modal{position:fixed;inset:0;background:rgba(3,4,8,.72);display:none;place-items:center;z-index:50;padding:20px}
.modal.on{display:grid}
.modal .card{width:min(680px,96vw);max-height:86vh;overflow:auto}
.panel{display:none;padding:22px 16px;overflow:auto;flex:1}
.panel.on{display:block}
.panel .wrap2{max-width:820px;margin:0 auto}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:10px 0}
.plugin{display:flex;gap:12px;align-items:flex-start;padding:14px;border:1px solid var(--line);border-radius:12px;background:#0b0f16;margin:10px 0}
.plugin h4{margin:0 0 4px;font:800 13px/1.3 system-ui;color:var(--ink)}
.plugin p{margin:0;color:var(--dim);font-size:12.5px}
.kv{display:grid;grid-template-columns:170px 1fr;gap:8px 14px;font-size:13.5px}
.kv b{color:var(--dim);font-weight:600}

.toolnote{font:12px/1.5 ui-monospace,monospace;color:#7f8ba0;background:#0b0f16;border-left:2px solid #2b3446;padding:6px 10px;margin:4px 0;white-space:pre-wrap;word-break:break-word}
.toolblock{border:1px solid #223047;border-radius:10px;margin:8px 0;padding:8px 10px;background:#080c13}
.toolhead{font:11px/1.4 ui-monospace,monospace;letter-spacing:.12em;color:#39ff9e;margin:2px 0 4px}
.toolblock pre{margin:0 0 8px;font:12px/1.45 ui-monospace,monospace;color:#c7d2e5;white-space:pre-wrap;word-break:break-word;max-height:340px;overflow:auto}
"""

def landing():
    sparks = "".join(
        f'<div class="spark" style="left:{(i*7)%100}px;bottom:-10px;animation-duration:{6+i%5}s;animation-delay:-{i%7}s"></div>'
        for i in range(26))
    return page("CHC HARNESS — AI that answers to you", f"""
<div class=fire><div class="flame"></div><div class="flame b"></div><div class="flame c"></div><div class="flame d"></div>{sparks}</div>
<div class="top-actions">
  <span class="emblem"><b>SEE 7.7.8</b> · QWEN3-4B · YOUR OWN 1 GB WORKSPACE · $5/MO</span>
  <a class="btn ghost small" href="{BASE}/download">DOWNLOAD</a>
</div>
<div class="stage wrap">
 <div class=hero>
  <h1 class=wordmark>CHC HARNESS<span class=see>SEE 7.7.8</span></h1>
  <p class=sub>Your own AI workspace — <b>streamed token by token</b>, running Qwen on hardware we own.
  Chat, code, write, automate, with a private 1 GB workspace that is yours alone. <b>$5 a month, one price, nothing to install.</b></p>
  <div class=row>
    <a class="btn" href="{BASE}/signup">CREATE ACCOUNT</a>
    <a class="btn ghost" href="{BASE}/login">LOG IN</a>
    <a class="btn ghost" href="{BASE}/download">SPEC &amp; DESIGN</a>
  </div>
  <div class=grid>
    <div class=feat><h4>STREAMS EVERY TOKEN</h4><p>Green when it is streaming, red when it errors — you always know what the model is doing.</p></div>
    <div class=feat><h4>YOUR WORKSPACE</h4><p>Read-only, read-write or full access. Files, plugins and automations in one place.</p></div>
    <div class=feat><h4>PLUGIN STORE</h4><p>Websites, documents, images, video. Add from the store — or let the agent build its own.</p></div>
    <div class=feat><h4>2FA BY DEFAULT</h4><p>Password plus a TOTP code. No SMS, no phone numbers, no excuses.</p></div>
  </div>
 </div>
</div>""", css=FIRE_CSS, cls="landing")

def auth_page(mode):
    title = "Create your account" if mode == "signup" else "Log in"
    return page(f"{title} · CHC HARNESS", f"""
<div class=fire><div class="flame"></div><div class="flame b"></div><div class="flame c"></div></div>
<div class="top-actions"><span class="emblem"><b>SEE 7.7.8</b> · S33</span><a class="btn ghost small" href="{BASE}/download">DOWNLOAD</a></div>
<div class="stage wrap">
 <div class=authshell>
  <div>
    <h1 class=wordmark style="font-size:clamp(34px,7vw,84px)">CHC HARNESS<span class=see>SEE 7.7.8</span></h1>
    <p class=sub>Email in, 6-digit code out. No passwords to remember.</p>
    <div class=grid>
      <div class=feat><h4>FREE TIER</h4><p>60 calls a day, no card.</p></div>
      <div class=feat><h4>$5 / MONTH</h4><p>Hosted by us, or self-hosted on your own machine — same price, same harness. Qwen engine either way.</p></div>
      <div class=feat><h4>TWO WAYS TO RUN IT</h4><p>Click a link and use ours, or download it and run it yourself. Same $5.</p></div>
      <div class=feat><h4>RUN IT YOURSELF</h4><p>One command on your own machine, your own vault and key:<br><code class=mono>curl -fsSL {BASE}/install.sh | bash</code><br>or <code class=mono>docker run -p 8895:8895 chc-harness</code></p></div>
    </div>
  </div>
  <div class=card>
    <div class=tabs>
      <div class="tab {'on' if mode=='signup' else ''}" onclick="location='{BASE}/signup'">CREATE</div>
      <div class="tab {'on' if mode=='login' else ''}" onclick="location='{BASE}/login'">LOG IN</div>
    </div>
    <div class=field><label>EMAIL</label><input id=email type=email autocomplete=username placeholder="you@example.com"></div>
    <div class=row style="margin-top:4px"><button class=btn id=send style="width:100%">EMAIL ME A 2FA CODE</button></div>
    <div class=row style="margin-top:8px"><button class="btn ghost" id=magicbtn style="width:100%">EMAIL ME A ONE-CLICK LINK</button></div>
    <div id=step2 style="display:none;margin-top:14px">
      <div class=field><label>6-DIGIT CODE</label><input id=code inputmode=numeric autocomplete=one-time-code placeholder="123456"></div>
      <div class=row><button class=btn id=go style="width:100%">VERIFY &amp; ENTER</button></div>
    </div>
    <div id=pwbox style="margin-top:14px">
      <div class=field><label>PASSWORD — no code needed if you set one</label><input id=pw type=password autocomplete=current-password placeholder="your password"></div>
      <div class=row><button class=btn id=loginpw style="width:100%">LOG IN WITH PASSWORD</button></div>
    </div>
    <div id=msg class=err style="margin-top:10px"></div>
    <p style="color:#8892a6;font-size:12px;margin:14px 0 0;line-height:1.7">
    <b>Don't take our word for it.</b> The source is public — read the code, run it yourself, check the
    signed receipt chain: <a href="https://github.com/CHCDOLADEEPSEEKMKSEC/chc-harness" style="color:var(--neo)">github.com/CHCDOLADEEPSEEKMKSEC/chc-harness</a></p>
    <p style="color:#5d6779;font-size:12px;margin:12px 0 0" id=hint>Password or a one-time email code — your choice.
    <a href="{BASE}/claim" style="color:#8892a6">Have a claim link?</a></p>
  </div>
 </div>
</div>""", script=f"""
const mode={json.dumps(mode)};
const msg=document.querySelector('#msg');
let sentTo=null;
document.querySelector('#magicbtn').onclick=async()=>{{
  msg.textContent='sending…';
  const acct=(document.querySelector('#email').value||'').trim();
  if(!acct){{ msg.textContent='enter your email first'; return; }}
  const r=await fetch('{BASE}/api/magic-request',{{method:'POST',headers:{{'content-type':'application/json'}},
    body:JSON.stringify({{acct:acct}})}});
  const j=await r.json();
  if(j.link){{ msg.innerHTML='one-click link: <a href="'+j.link+'">'+j.link+'</a>'; return; }}
  msg.textContent=j.emailed?'link emailed - check your inbox':'if that account exists, a link is on its way';
}};
document.querySelector('#send').onclick=async()=>{{
  const email=document.querySelector('#email').value.trim();
  if(!email){{msg.textContent='type your email first';return;}}
  const r=await fetch('{BASE}/api/'+(mode==='signup'?'signup_email':'email_code'),{{method:'POST',
    headers:{{'content-type':'application/json'}},body:JSON.stringify({{email:email,acct:email}})}});
  const j=await r.json();
  if(j.error){{msg.textContent=j.error;return;}}
  sentTo=email;
  if(mode==='signup'){{document.querySelector('#hint').textContent='If an account already exists we email a login code instead.';}}
  document.querySelector('#step2').style.display='block';
  msg.textContent=j.sent?('code sent to '+email+' — check your inbox'):(j.msg||'code queued — delivery not configured yet');
}};
document.querySelector('#go').onclick=async()=>{{
  const r=await fetch('{BASE}/api/verify_code',{{method:'POST',headers:{{'content-type':'application/json'}},
    body:JSON.stringify({{email:sentTo||document.querySelector('#email').value.trim(),
                          code:document.querySelector('#code').value.trim()}})}});
  const j=await r.json();
  if(!j.ok){{msg.textContent=j.error||'bad code';return;}}
  location='{BASE}/app';
}};
document.addEventListener('keydown',e=>{{if(e.key==='Enter')document.querySelector('#go').click();}});
document.querySelector('#loginpw').onclick=async()=>{{
  const email=document.querySelector('#email').value.trim();
  const pw=document.querySelector('#pw').value;
  if(!email||!pw){{msg.textContent='email and password, please';return;}}
  const r=await fetch('{BASE}/api/login',{{method:'POST',headers:{{'content-type':'application/json'}},
    body:JSON.stringify({{email:email,pw:pw}})}});
  const j=await r.json();
  if(!j.ok){{msg.textContent=j.error||'login failed';return;}}
  location='{BASE}/app';
}};
""", css=FIRE_CSS, cls="landing")

def totp_page():
    return page("Set up 2FA · CHC HARNESS", f"""
<div class="wrap" style="max-width:640px;padding-top:60px">
 <h1 class=wordmark style="font-size:clamp(28px,6vw,54px);color:var(--neo)">2FA</h1>
 <p style="color:var(--dim)">Add this account to your authenticator app (Aegis, Raivo, Google Authenticator, 1Password). Then enter the 6-digit code to finish.</p>
 <div class=card style="margin:16px 0;display:flex;gap:18px;align-items:center;flex-wrap:wrap">
   <div id=qrw style="background:#05060a;border:1px solid #1d2230;border-radius:12px;padding:8px"><img id=qr width=190 height=190 alt=QR></div>
   <div class=kv style="flex:1;min-width:240px">
     <b>ACCOUNT</b><span id=acct class=mono>—</span>
     <b>SECRET</b><span id=sec class=mono style="word-break:break-all">—</span>
     <b>OTPAUTH</b><span class=mono style="word-break:break-all;color:var(--dim)" id=uri>—</span>
   </div>
 </div>
 <div class=field><label>6-DIGIT CODE</label><input id=code inputmode=numeric placeholder="123456"></div>
 <div id=msg class=err></div>
 <div class=row><button class=btn id=go>VERIFY &amp; ENTER</button></div>
</div>""", script=f"""
const q=new URLSearchParams(location.search);
const secret=q.get('secret')||'';
const acct=q.get('acct')||'';
document.querySelector('#sec').textContent=secret;
document.querySelector('#uri').textContent='otpauth://totp/CHC%20HARNESS:'+encodeURIComponent(acct)+'?secret='+secret+'&issuer=CHC%20HARNESS';
document.querySelector('#acct').textContent=acct;
const uri='otpauth://totp/CHC%20HARNESS:'+encodeURIComponent(acct)+'?secret='+secret+'&issuer=CHC%20HARNESS';
document.querySelector('#qr').src='{BASE}/api/qr?d='+encodeURIComponent(uri);
document.querySelector('#qrw').style.display='block';
async function go(){{
  const r=await fetch('{BASE}/api/totp_confirm',{{method:'POST',headers:{{'content-type':'application/json'}},
    body:JSON.stringify({{secret:secret,code:document.querySelector('#code').value.trim(),acct:acct}})}});
  const j=await r.json(); if(!j.ok){{document.querySelector('#msg').textContent=j.error||'bad code';return;}}
  location='{BASE}/app';
}}
document.querySelector('#go').onclick=go;
document.querySelector('#code').addEventListener('keydown',e=>{{if(e.key==='Enter')go();}});
""")

def app_page(user, switched=""):
    _m = "DEEPSEEK (UPSTREAM)" if user["upstream_on"] else "QWEN 3-4B (LOCAL)"
    _plan = (user["plan"] if "plan" in user.keys() else "free") or "free"
    _price = {"free": "FREE $0", "qwen6": "QWEN+ $5/MO", "deepseek3": "DEEPSEEK $5 TOP-UP", "big": "BIG (HOUSE)"}.get(_plan, _plan.upper())
    model_line = "MODEL: %s · %s · 1 GB WORKSPACE" % (_m, _price)
    banner = ""
    if switched in ("deepseek", "local"):
        _t = ("SWITCHED — now answering on DEEPSEEK (upstream)" if switched == "deepseek"
              else "SWITCHED — back on QWEN (local)")
        banner = ("<div id=modelbanner style=\"padding:8px 14px;background:rgba(57,255,158,.12);"
                   "border-bottom:1px solid var(--neo);color:var(--neo);font-size:12px;letter-spacing:.08em\">"
                   + _t + "</div>")
    return page("CHC HARNESS", f"""
<button id=sbopen title="Toggle sidebar (Ctrl+B)" aria-label="Toggle sidebar">MENU  «</button>
<div class=app>
 <aside class=side>
  <div class=brand><b>CHC HARNESS</b><small>SEE 7.7.8</small><button id=sbtog title="Collapse sidebar (Ctrl+B)" aria-label="Collapse sidebar">« HIDE</button></div>
  <div class=newchat id=newchat>+ NEW CHAT</div>
  <div class=nav id=nav>
   <h5>WORKSPACE</h5>
   <div class=item data-panel=chat on>◈ Chat</div>
   <div class=item data-panel=files>▤ Files &amp; workspace</div>
   <div class=item data-panel=plugins>✚ Plugins store</div>
   <div class=item data-panel=automation>⟳ Automation</div>
   <div class=item data-panel=search>⌕ Search</div>
   <h5 style="display:flex;align-items:center;gap:8px">CHATS <button id=chtog title="Hide the chat list">HIDE</button></h5>
   <div id=chatlist></div>
  </div>
  <div class=sidefoot>
    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
      <span id=who>{user['handle'] or user['email']}</span>
      <span class=badge id=planbadge>{user['plan'].upper()}</span>
    </div>
    <div class=row style="margin:8px 0 0">
      <a class=chip id=autoscroll title="Keep the chat pinned to the newest message" onclick="toggleScroll();return false" style="cursor:pointer">AUTO-SCROLL</a>
    <a class=chip href="{BASE}/authorise" title="Control what SPARKY may remember">{'MEMORY ON' if user['memory_on'] else 'AUTHORISE MEMORY'}</a>
      <button class="chip" id=settings>SETTINGS</button>
      <a class=chip href="{BASE}/assist">HELP</a>
      <a class=chip href="{BASE}/feedback">FEEDBACK</a>
      <a class=chip href="{BASE}/get">INSTALL</a>
      <a class=chip href="{BASE}/logout">LOG OUT</a>
    </div>
  </div>
 </aside>
 <main class=main>
  <div class=topbar>
    <a class="chip{' on' if not user['upstream_on'] else ''}" id="modelswitch_local" href="{BASE}/upstream/off" title="Run on the local Qwen">LOCAL</a>
    <a class="chip{' on' if user['upstream_on'] else ''}" id="modelswitch_deepseek" href="{BASE}/upstream/on" title="Run on DeepSeek (upstream)">DEEPSEEK</a>
    <span class=chip on data-mode=coding>CODER</span>
    <span class=chip data-mode=reasoning>REASONING</span>
    <span class=chip data-mode=chat>CHAT</span>
    <span class=grow></span>
    <span class=chip perm on data-perm=read-write>READ-WRITE</span>
    <span class="mono" style="color:#5d6779;font-size:11px;margin-right:8px">{model_line}</span>
    <span class=chip perm data-perm=read-only>READ-ONLY</span>
    <span class=chip perm data-perm=full>FULL ACCESS</span>
    <span class="chip" id=rememberbtn title="Remember everything across all your chats">REMEMBER</span>
    <span class="chip" id=verifybtn title="Verify the signed record">VERIFY RECORD</span>
    <span class="chip" id=shellbtn style="border-color:var(--neo);color:var(--neo)">SHELL ⌘</span>
    <span id=dot title="idle"></span>
  </div>
  {banner}
  <div id=uppanel style="display:none;border-bottom:1px solid var(--line);background:#0a0d13;padding:12px 14px">
    <div class=row style="gap:10px;align-items:center;flex-wrap:wrap">
      <b style="color:var(--neo)">UPSTREAM MODEL</b>
      <span id=upstate style="color:var(--dim);font-size:12px">checking…</span>
      <input id=upkey type=password placeholder="sk-... your DeepSeek key (stored on your account, never shown again)"
             style="flex:1;min-width:280px;padding:8px;background:#0b0e14;color:var(--ink);border:1px solid var(--line);border-radius:6px">
      <button class=chip id=upsave>SAVE KEY + TEST</button>
      <button class=chip id=upon>USE UPSTREAM</button>
      <button class=chip id=upoff>USE LOCAL</button>
      <button class=chip id=upforget>FORGET KEY</button>
      <a class=chip href="{BASE}/plan">NEEDS DEEPSEEK TOP-UP</a>
    </div>
    <p style="color:#5d6779;font-size:11px;margin:6px 0 0">Your key is stored in a 0600 file on the box for your account only. It is used for your calls and never displayed.</p>
  </div>
  <div id=shellpanel style="display:none;border-bottom:1px solid var(--line);background:#0a0d13;padding:10px 14px">
    <div class=row style="gap:8px;align-items:center">
      <span class=mono style="color:var(--neo);font-size:12px">FULL ACCESS</span>
      <input id=shellcmd class=mono placeholder="command on this box… e.g. whoami  ·  ls -la  ·  df -h" style="flex:1;background:#05060a;border:1px solid var(--line);border-radius:8px;color:var(--ink);padding:8px 10px">
      <button class="chip" id=shellrun style="border-color:var(--neo);color:var(--neo)">RUN</button>
      <button class=chip id=shellclose>CLOSE</button>
    </div>
    <pre id=shellout class=mono style="margin:8px 0 0;max-height:220px;overflow:auto;background:#05060a;border:1px solid var(--line);border-radius:8px;padding:10px;color:#cfd6e4;white-space:pre-wrap"></pre>
  </div>
  <style>@keyframes chcspin{{to{{transform:rotate(360deg)}}}} .chcspin{{width:34px;height:34px;border:3px solid rgba(57,255,158,.25);border-top-color:var(--neo);border-radius:50%;animation:chcspin .8s linear infinite;margin:0 auto}}</style>
  <div id=loadingbox style="display:none;position:absolute;inset:0;background:rgba(5,6,10,.72);z-index:40;align-items:center;justify-content:center">
    <div style="text-align:center"><div class=chcspin></div><div class=mono style="margin-top:10px;color:var(--neo);font-size:13px" id=loadingtext>LOADING CHAT…</div></div>
  </div>
  <pre id=verifyout class=mono style="display:none;margin:0;padding:10px 14px;border-bottom:1px solid var(--line);background:#05060a;color:#cfd6e4;white-space:pre-wrap;font-size:12px"></pre>
  <section class="panel on" id=panel-chat>
    <div class=msgs id=msgs></div>
    <div class=composer><div class=inner>
      <div id=attachrow class=row style="display:none;gap:6px;flex-wrap:wrap;margin-bottom:8px"></div>
      <textarea id=q placeholder="Message CHC HARNESS…  (Ctrl+Enter to send)"></textarea>
      <div class=sendrow><button class=btn id=send>STREAM</button><span style="color:#5d6779;font-size:12px" id=hint>coder mode · read-write</span><span class=grow></span><button class="chip" id=stop style="display:none">STOP</button></div>
    </div></div>
  </section>
  <section class=panel id=panel-files><div class=wrap2>
    <h3>FILES &amp; WORKSPACE</h3>
    <p style="color:var(--dim)">Upload text, PDF, documents, images or video. Text and PDF content is read into the chat when you attach it. Images and video are stored and openable, but the local model cannot see pixels or watch frames.</p>
    <div class=row style="gap:8px;flex-wrap:wrap;align-items:center">
      <label class=btn style="margin:0;cursor:pointer;display:inline-block">UPLOAD FILES<input id=fileinput type=file multiple style="display:none"></label>
      <label class="btn ghost" style="margin:0;cursor:pointer;display:inline-block">IMAGE<input id=imginput type=file accept="image/*" multiple style="display:none"></label>
      <label class="btn ghost" style="margin:0;cursor:pointer;display:inline-block">VIDEO<input id=vidinput type=file accept="video/*" multiple style="display:none"></label>
      <button class=chip id=refreshfiles>REFRESH</button>
      <span style="color:#5d6779;font-size:12px" id=upstatus></span>
    </div>
    <div id=filelist><p style="color:#5d6779">No files yet.</p></div>
    <h4 style="margin-top:22px">AGENT WORKSPACE <span style="color:#5d6779;font-weight:400;font-size:12px">— files {AGENT_NAME} made with FULL ACCESS</span></h4>
    <div id=worklist><p style="color:#5d6779">Nothing yet. Switch the top bar to FULL ACCESS and ask him to make something.</p></div>
  </div></section>
  <section class=panel id=panel-plugins><div class=wrap2>
    <h3>PLUGINS STORE</h3>
    <p style="color:var(--dim)">Website generator, documents, images, video, automation. Add one, or let the agent build a custom plugin from a prompt.</p>
    <div id=pluginlist></div>
    <div class=card style="margin-top:14px">
      <h4 style="margin:0 0 8px">CUSTOM PLUGIN (agent builds its own)</h4>
      <textarea id=customdesc placeholder="Describe the plugin, e.g. 'generate a landing page from a spec and save it to the workspace'"></textarea>
      <div class=row><button class=btn id=addcustom>BUILD CUSTOM PLUGIN</button></div>
    </div>
  </div></section>
  <section class=panel id=panel-automation><div class=wrap2>
    <h3>AUTOMATION</h3>
    <p style="color:var(--dim)">Tasks you can queue: research, scrape a page, draft a document, publish a page. They run from the workspace.</p>
    <div class=row><input id=taskkind placeholder="task name"><button class=btn id=addtask>ADD TASK</button></div>
    <div id=tasklist></div>
  </div></section>
  <section class=panel id=panel-search><div class=wrap2>
    <h3>SEARCH</h3>
    <div class=row><input id=qs placeholder="search chats and messages"><button class=btn id=doq>SEARCH</button></div>
    <div id=results></div>
  </div></section>
 </main>
</div>
<div class=modal id=modal><div class=card>
  <div class=row style="justify-content:space-between"><h3 style="margin:0">SETTINGS</h3><button class="chip" id=closeM>CLOSE</button></div>
  <div class=kv style="margin-top:14px">
    <b>ACCOUNT</b><span id=setacct>—</span>
    <b>PLAN</b><span id=setplan>—</span>
    <b>2FA</b><span>TOTP enabled</span>
    <b>THEME</b><span>neo green on black (fixed)</span>
    <b>MODEL</b><span>house model (local) · paid plan can bring a key</span>
    <b>SESSION</b><span>stays signed in for 30 days</span>
  </div>
  <div class=row style="margin-top:16px"><a class=btn href="{BASE}/plan">PLANS &amp; PRICING</a><a class="btn ghost" href="{BASE}/get">INSTALL</a><a class="btn ghost" href="{BASE}/logout">LOG OUT</a></div>
</div></div>""", script=f"""
const BASE={json.dumps(BASE)};
let mode='coding', perm='read-write', chat=null, key='', abort=null;
const dot=document.querySelector('#dot'), msgs=document.querySelector('#msgs'), q=document.querySelector('#q');
const hint=document.querySelector('#hint');
function lit(s,t){{dot.className=s; dot.title=t||'';}}
function esc(t){{return (t||'').replace(/[&<>]/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]));}}
function bubble(role,text){{
  const d=document.createElement('div'); d.className='msg';
  d.innerHTML='<div class="who '+(role==='user'?'u':'a')+'">'+(role==='user'?'U':'C')+'</div><div class=bub></div>';
  const bub=d.querySelector('.bub');
  const imgs=[], vids=[];
  const plain=(text||'').replace(/\[\[img:(\d+)\]\]/g,(m,id)=>{{imgs.push(id);return '';}}).replace(/\[\[vid:(\d+)\]\]/g,(m,id)=>{{vids.push(id);return '';}});
  bub.innerHTML=esc(plain).replace(/\\n/g,'<br>');
  imgs.forEach(id=>{{
    const im=document.createElement('img');
    im.src=BASE+'/files/'+id; im.loading='lazy';
    im.style.cssText='display:block;max-width:min(420px,100%);max-height:320px;border:1px solid var(--line);border-radius:10px;margin-top:8px;cursor:zoom-in';
    im.onclick=()=>window.open(im.src,'_blank');
    bub.appendChild(im);
  }});
  vids.forEach(id=>{{
    const v=document.createElement('video');
    v.src=BASE+'/files/'+id; v.controls=true; v.preload='metadata';
    v.style.cssText='display:block;max-width:min(520px,100%);max-height:340px;border:1px solid var(--line);border-radius:10px;margin-top:8px;background:#000';
    bub.appendChild(v);
  }});
  msgs.appendChild(d); stick();
  return bub;
}}
function hintText(){{return mode+' mode · '+perm+(perm==='full'?' · shell on':(perm==='read-write'?' · file tools only':' · no tools'));}}
document.querySelectorAll('[data-mode]').forEach(c=>c.onclick=()=>{{mode=c.dataset.mode;
  document.querySelectorAll('[data-mode]').forEach(x=>x.classList.toggle('on',x===c)); hint.textContent=hintText();}});
document.querySelectorAll('[data-perm]').forEach(c=>c.onclick=()=>{{perm=c.dataset.perm;
  fetch(BASE+'/api/perms',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{chat:chat,perms:perm}})}}).catch(()=>{{}});
  document.querySelectorAll('[data-perm]').forEach(x=>x.classList.toggle('on',x===c)); hint.textContent=hintText();}});


// ---- UPSTREAM MODEL button: real key, real switch, real state ----
const _up={{on:false,plan_allows:false,own_key:false,house_key:false}};
async function upLoad(){{
  try{{
    const j=await (await fetch(BASE+'/api/upstream')).json();
    Object.assign(_up,j);
    const chip=document.querySelector('#modelchip');
    chip.classList.toggle('on',!!j.on);
    chip.textContent = j.on ? 'UPSTREAM ON' : (j.plan_allows ? 'UPSTREAM MODEL' : 'LOCAL MODEL');
    const st=document.querySelector('#upstate');
    if(st) st.textContent = !j.plan_allows
      ? 'LOCKED - upstream needs the DeepSeek top-up'
      : (j.on ? 'active - your calls go to DeepSeek' : 'ready - add a key and press USE UPSTREAM');
  }}catch(e){{}}
}}
var _mc=document.querySelector('#modelchip'); if(_mc) _mc.onclick=function(){{
  var pn=document.querySelector('#uppanel');
  pn.style.display=(pn.style.display==='none'||!pn.style.display)?'block':'none';
  upLoad();
}};
var _us=document.querySelector('#upsave'); if(_us) _us.onclick=async function(){{
  var k=document.querySelector('#upkey').value.trim();
  var st=document.querySelector('#upstate'); st.textContent='testing key with DeepSeek...';
  var j=await (await fetch(BASE+'/api/upstream',{{method:'POST',headers:{{'content-type':'application/json'}},
      body:JSON.stringify({{action:'set',key:k}})}})).json();
  st.textContent = j.ok ? 'key saved and verified - now press USE UPSTREAM' : ('rejected: '+(j.error||'no'));
  document.querySelector('#upkey').value=''; upLoad();
}};
var _uo=document.querySelector('#upon'); if(_uo) _uo.onclick=async function(){{
  await fetch(BASE+'/api/upstream',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{action:'on'}})}}); upLoad();}};
var _uf=document.querySelector('#upoff'); if(_uf) _uf.onclick=async function(){{
  await fetch(BASE+'/api/upstream',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{action:'off'}})}}); upLoad();}};
var _ug=document.querySelector('#upforget'); if(_ug) _ug.onclick=async function(){{
  await fetch(BASE+'/api/upstream',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{action:'forget'}})}}); upLoad();}};
upLoad();
document.querySelectorAll('[data-panel]').forEach(it=>it.onclick=()=>{{
  document.querySelectorAll('[data-panel]').forEach(x=>x.classList.toggle('on',x===it));
  document.querySelectorAll('.panel').forEach(p=>p.classList.toggle('on',p.id==='panel-'+it.dataset.panel));
}});
document.querySelector('#settings').onclick=async()=>{{
  const r=await fetch(BASE+'/api/me'); const j=await r.json();
  document.querySelector('#setacct').textContent=j.email||'—';
  document.querySelector('#setplan').textContent=(j.plan||'free').toUpperCase();
  document.querySelector('#modal').classList.add('on');
}};
document.querySelector('#closeM').onclick=()=>document.querySelector('#modal').classList.remove('on');
async function newChat(){{
  const r=await fetch(BASE+'/api/chats',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{title:'new chat'}})}});
  const j=await r.json(); msgs.innerHTML=''; await openChat(j.id); return j.id;
}}
document.querySelector('#newchat').onclick=newChat;
const shellpanel=document.querySelector('#shellpanel');
document.querySelector('#shellbtn').onclick=()=>{{shellpanel.style.display=shellpanel.style.display==='none'?'block':'none';
  if(shellpanel.style.display==='block') document.querySelector('#shellcmd').focus();}};
document.querySelector('#shellclose').onclick=()=>{{shellpanel.style.display='none';}};
async function runShell(){{
  const el=document.querySelector('#shellcmd'), out=document.querySelector('#shellout');
  const cmd=el.value.trim(); if(!cmd) return;
  out.textContent='… running: '+cmd;
  try{{
    const r=await fetch(BASE+'/api/shell',{{method:'POST',headers:{{'content-type':'application/json'}},
      body:JSON.stringify({{chat:chat,cmd:cmd}})}});
    const j=await r.json();
    if(!r.ok){{ out.textContent='BLOCKED — '+(j.error||r.status); return; }}
    out.textContent=j.out||'(no output)';
  }}catch(e){{ out.textContent='error: '+e; }}
}}
document.querySelector('#shellrun').onclick=runShell;
document.querySelector('#shellcmd').addEventListener('keydown',e=>{{if(e.key==='Enter') runShell();}});
let chatList=[];
async function refreshChats(){{
  const r=await fetch(BASE+'/api/chats'); const j=await r.json();
  chatList=j.chats||[];
  const box=document.querySelector('#chatlist'); box.innerHTML='';
  chatList.forEach(c=>{{
    const el=document.createElement('div'); el.className='chatrow'; el.textContent=c.title||'chat';
    if(c.id===chat) el.style.background='rgba(57,255,158,.12)';
    el.onclick=()=>openChat(c.id);
    box.appendChild(el);
  }});
}}
function toolBlock(name,args,result){{
  const d=document.createElement('div'); d.className='toolblock';
  const h=document.createElement('div'); h.className='toolhead'; h.textContent='TOOL CALL · '+name; d.appendChild(h);
  const a=document.createElement('pre'); a.textContent=args; d.appendChild(a);
  const r=document.createElement('div'); r.className='toolhead'; r.textContent='RESULT'; d.appendChild(r);
  const o=document.createElement('pre'); o.textContent=result; d.appendChild(o);
  msgs.appendChild(d); msgs.scrollTop=msgs.scrollHeight; return d;
}}
function showLoading(msg){{const b=document.querySelector('#loadingbox');document.querySelector('#loadingtext').textContent=msg||'LOADING CHAT…';b.style.display='flex';}}
function hideLoading(){{document.querySelector('#loadingbox').style.display='none';}}
async function openChat(id){{
  chat=id; try{{localStorage.setItem('chc_chat',id);}}catch(_){{}}
  showLoading('LOADING CHAT…');
  try{{
    const rr=await fetch(BASE+'/api/chats/'+id); const jj=await rr.json();
    msgs.innerHTML='';
    const list=jj.messages||[];
    (list.length>400?list.slice(list.length-400):list).forEach(m=>bubble(m.role,m.content));
    if(list.length>400){{const n=document.createElement('div');n.className='msg';n.innerHTML='<div class=bub style="color:#8b93a3">showing the last 400 messages — the rest are safe on the server</div>';msgs.insertBefore(n,msgs.firstChild);}}
    (jj.tools||[]).forEach(t=>toolBlock(t.name,t.args,t.result));
    lastSeen = list.length ? (list[list.length-1].id||0) : 0;
    startSync();
  }}catch(e){{bubble('assistant','could not load this chat: '+e);}}
  hideLoading();
  await refreshChats();
}}
async function restore(){{
  await refreshChats();
  if(!chatList.length) return;
  let last=null; try{{last=localStorage.getItem('chc_chat');}}catch(_){{}}
  const pick=chatList.find(c=>c.id===last)||chatList[0];
  if(pick) await openChat(pick.id);
}}
// ---- AUTO-SCROLL + INLINE CHAT SYNC ---------------------------------------------
let autoscroll=true, lastSeen=0, syncTimer=null;
function stick(){{ if(autoscroll) msgs.scrollTop=msgs.scrollHeight; }}
function paintScroll(){{ const c=document.getElementById('autoscroll'); if(c) c.classList.toggle('on',autoscroll); }}
function toggleScroll(){{ autoscroll=!autoscroll; paintScroll(); if(autoscroll) stick(); }}
msgs.addEventListener('scroll',()=>{{
  const atBottom = msgs.scrollHeight-msgs.scrollTop-msgs.clientHeight < 60;
  if(!atBottom && autoscroll){{ autoscroll=false; paintScroll(); }}
  if(atBottom && !autoscroll){{ autoscroll=true; paintScroll(); }}
}});
paintScroll();
async function syncOnce(){{
  if(!chat) return;
  try{{
    const r=await fetch(BASE+'/api/chats/'+chat+'/since?after='+lastSeen); if(!r.ok) return;
    const j=await r.json();
    for(const m of (j.messages||[])){{
      if(!m || !m.id || m.id<=lastSeen) continue;
      lastSeen=m.id;
      if(m.role==='user' || m.role==='assistant'){{
        // skip a duplicate of the bubble we are currently streaming into
        const last=msgs.lastElementChild;
        if(last && last.dataset && last.dataset.sid===String(m.id)) continue;
        const b=bubble(m.role,m.content); if(b){{
          const wrap=b.closest('.msg'); if(wrap) wrap.dataset.sid=String(m.id);
        }}
      }}
    }}
    stick();
  }}catch(_){{}}
}}
function startSync(){{
  if(syncTimer) clearInterval(syncTimer);
  lastSeen=lastSeen||0;
  syncOnce();
  syncTimer=setInterval(syncOnce, 6000);
}}
async function cursorToEnd(){{
  if(!chat) return;
  try{{
    const r=await fetch(BASE+'/api/chats/'+chat); const j=await r.json();
    const ms=j.messages||[]; if(ms.length) lastSeen=ms[ms.length-1].id||0;
  }}catch(_){{}}
}}
document.querySelector('#send').onclick=async()=>{{
  const text=q.value.trim(); if(!text)return;
  if(!chat) await newChat();
  bubble('user',text+(attached.size?'\\n[attached: '+Array.from(attached).map(i=>(filesIndex[i]||{{name:'file '+i}}).name).join(', ')+']':'')); q.value='';
  const b=bubble('assistant',''); let buf='';
  lit('s','streaming');
  abort=new AbortController();
  document.querySelector('#stop').style.display='inline-block';
  try{{
    const r=await fetch(BASE+'/api/chat',{{method:'POST',headers:{{'content-type':'application/json'}},signal:abort.signal,
      body:JSON.stringify({{chat:chat,mode:mode,perms:perm,message:text,attach:Array.from(attached)}})}});
    if(!r.ok) throw new Error('HTTP '+r.status+' '+await r.text());
    const rd=r.body.getReader(), dec=new TextDecoder(); let raw='';
    while(true){{const {{done,value}}=await rd.read(); if(done)break;
      raw+=dec.decode(value,{{stream:true}});
      let i; while((i=raw.indexOf('\\n'))>=0){{const line=raw.slice(0,i); raw=raw.slice(i+1);
        if(!line.startsWith('data:'))continue; const d=line.slice(5).trim(); if(d==='[DONE]')continue;
        try{{const j=JSON.parse(d); if(j.tool){{toolBlock(j.tool.name,j.tool.args,j.tool.result);}} if(j.note){{const n=document.createElement('div'); n.className='toolnote'; n.textContent=j.note; msgs.appendChild(n); msgs.scrollTop=msgs.scrollHeight;}} if(j.delta){{b.textContent+=j.delta; msgs.scrollTop=msgs.scrollHeight;}}
          if(j.error){{lit('e','error'); b.textContent+='\\n[error] '+j.error;}}}}catch(_){{}}
      }}
    }}
    lit('','done');
  }}catch(e){{ if(e.name!=='AbortError'){{lit('e','error'); b.textContent+='\\n[error] '+e.message;}} else lit('','stopped'); }}
  finally{{document.querySelector('#stop').style.display='none'; attached.clear(); renderAttached(); refreshChats();}}
}};
document.querySelector('#stop').onclick=()=>{{ if(abort) abort.abort(); }};
q.addEventListener('keydown',e=>{{if(e.key==='Enter'&&e.ctrlKey)document.querySelector('#send').click();}});
async function loadPlugins(){{
  const r=await fetch(BASE+'/api/plugins'); const j=await r.json();
  const box=document.querySelector('#pluginlist'); box.innerHTML='';
  (j.plugins||[]).forEach(p=>{{
    const d=document.createElement('div'); d.className='plugin';
    d.innerHTML='<div style="flex:1"><h4></h4><p></p></div><div></div>';
    d.querySelector('h4').textContent=p.name; d.querySelector('p').textContent=p.desc;
    const b=document.createElement('button'); b.className='chip'; b.textContent=p.custom?'CUSTOM':'ADDED';
    d.lastElementChild.appendChild(b); box.appendChild(d);
  }});
}}
document.querySelector('#addcustom').onclick=async()=>{{
  const desc=document.querySelector('#customdesc').value.trim(); if(!desc)return;
  await fetch(BASE+'/api/plugins',{{method:'POST',headers:{{'content-type':'application/json'}},
    body:JSON.stringify({{name:'custom plugin',desc:desc,custom:1}})}});
  document.querySelector('#customdesc').value=''; loadPlugins();
}};
async function loadTasks(){{
  const r=await fetch(BASE+'/api/tasks'); const j=await r.json();
  const box=document.querySelector('#tasklist'); box.innerHTML='';
  (j.tasks||[]).forEach(t=>{{const d=document.createElement('div'); d.className='chatrow';
    d.textContent=t.kind+' · '+t.status; box.appendChild(d);}});
}}
document.querySelector('#addtask').onclick=async()=>{{
  const k=document.querySelector('#taskkind').value.trim(); if(!k)return;
  await fetch(BASE+'/api/tasks',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{kind:k}})}});
  document.querySelector('#taskkind').value=''; loadTasks();
}};
document.querySelector('#doq').onclick=async()=>{{
  const s=document.querySelector('#qs').value.trim(); if(!s)return;
  const r=await fetch(BASE+'/api/search?q='+encodeURIComponent(s)); const j=await r.json();
  const box=document.querySelector('#results'); box.innerHTML='';
  (j.hits||[]).forEach(h=>{{const d=document.createElement('div'); d.className='plugin';
    d.innerHTML='<div style="flex:1"><h4></h4><p></p></div>';
    d.querySelector('h4').textContent=h.title; d.querySelector('p').textContent=h.content.slice(0,220); box.appendChild(d);}});
}};
const attached=new Set(); let filesIndex={{}};
function fmtSize(n){{return n>1048576?(n/1048576).toFixed(1)+' MB':n>1024?(n/1024).toFixed(0)+' KB':n+' B';}}
function renderAttached(){{
  const row=document.querySelector('#attachrow'); row.innerHTML='';
  if(!attached.size){{row.style.display='none';return;}}
  row.style.display='flex';
  attached.forEach(id=>{{
    const f=filesIndex[id]||{{name:'file '+id}};
    const chip=document.createElement('span'); chip.className='chip on'; chip.textContent=f.name+' ×';
    chip.onclick=()=>{{attached.delete(id);renderAttached();loadFiles();}};
    if(/\.(png|jpe?g|webp|gif)$/i.test(f.name||'')||(f.kind||'')==='image'){{
      const th=document.createElement('img'); th.src=BASE+'/files/'+id;
      th.style.cssText='width:34px;height:34px;object-fit:cover;border-radius:6px;border:1px solid var(--line)';
      row.appendChild(th);
    }}
    row.appendChild(chip);
  }});
}}
async function loadFiles(){{
  const r=await fetch(BASE+'/api/files'); const j=await r.json();
  loadWork();
  const box=document.querySelector('#filelist'); box.innerHTML=''; filesIndex={{}};
  if(!(j.files||[]).length){{box.innerHTML='<p style="color:#5d6779">No files yet — upload a PDF, doc, image or video.</p>';return;}}
  (j.files||[]).forEach(f=>{{
    filesIndex[f.id]=f;
    const d=document.createElement('div'); d.className='plugin';
    d.innerHTML='<div style="flex:1"><h4></h4><p></p></div><div class=row style="gap:6px"></div>';
    d.querySelector('h4').textContent=f.name;
    d.querySelector('p').textContent=f.kind+' · '+fmtSize(f.size)+' · '+f.created;
    const act=d.lastElementChild;
    const o=document.createElement('button'); o.className='chip'; o.textContent='OPEN';
    o.onclick=()=>window.open(BASE+'/files/'+f.id,'_blank');
    const a=document.createElement('button'); a.className='chip'+(attached.has(f.id)?' on':''); a.textContent=attached.has(f.id)?'ATTACHED':'ATTACH';
    a.onclick=()=>{{if(attached.has(f.id))attached.delete(f.id);else attached.add(f.id);renderAttached();loadFiles();}};
    const pub=document.createElement('button'); pub.className='chip'; pub.textContent='PUBLISH';
    pub.title='get a shareable download link + sha256 for this file';
    pub.onclick=async()=>{{pub.textContent='...';
      try{{const rr=await fetch(BASE+'/api/publish',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{id:f.id}})}});
        const jj=await rr.json();
        if(jj.ok){{ pub.textContent='LINK COPIED'; pub.classList.add('on');
          try{{await navigator.clipboard.writeText(jj.url);}}catch(_){{}}
          const st=document.querySelector('#upstatus'); if(st) st.innerHTML='published: <a href="'+jj.url+'" target="_blank">'+jj.url+'</a> · sha256 '+jj.sha256.slice(0,16)+'…';
          setTimeout(()=>{{pub.textContent='PUBLISH';pub.classList.remove('on');}},4000);
        }} else {{ pub.textContent='FAILED'; setTimeout(()=>pub.textContent='PUBLISH',3000); }}
      }}catch(e){{pub.textContent='FAILED'; setTimeout(()=>pub.textContent='PUBLISH',3000);}} }};
    const x=document.createElement('button'); x.className='chip'; x.textContent='DEL';
    x.onclick=async()=>{{if(!confirm('delete '+f.name+'?'))return;
      await fetch(BASE+'/api/files',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{id:f.id}})}});
      attached.delete(f.id); renderAttached(); loadFiles();}};
    act.append(o,pub,a,x); box.appendChild(d);
  }});
}}
async function loadRemember(){{
  try{{const r=await fetch(BASE+'/api/me'); const j=await r.json();
    const on=!!(j.user&&j.user.remember_all); const el=document.querySelector('#rememberbtn');
    if(!el) return;
    el.classList.toggle('on',on); el.textContent=on?'REMEMBER ON':'REMEMBER';
    el.title=on?'Everything from all your chats is in context':'Click to remember everything across all your chats';
  }}catch(_){{}}
}}
// chat list collapse (the CHATS block inside the sidebar) — remembered per browser
(function(){{
  const list=document.querySelector('#chatlist'); if(!list) return;
  const KEY='chc_chlist'; const btn=document.querySelector('#chtog');
  function apply(off){{ list.classList.toggle('off',off); if(btn){{ btn.textContent=off?'SHOW':'HIDE'; btn.title=off?'Show the chat list':'Hide the chat list'; }} }}
  let off=false; try{{off=localStorage.getItem(KEY)==='1';}}catch(_){{}}
  apply(off);
  if(btn) btn.onclick=()=>{{ let c=false; try{{c=localStorage.getItem(KEY)==='1';}}catch(_){{}} try{{localStorage.setItem(KEY,c?'0':'1');}}catch(_){{}} apply(!c); }};
}})();
// sidebar collapse/expand — remembered per browser, keyboard: Ctrl+B or [ key
(function(){{
  const app=document.querySelector('.app'); if(!app) return;
  const KEY='chc_sbcol';
  function apply(on){{
    app.classList.toggle('sbcol',on);
    document.body.classList.toggle('sbcol',on);
    const t=document.querySelector('#sbtog'); if(t){{ t.title=on?'Show sidebar (Ctrl+B)':'Collapse sidebar (Ctrl+B)'; t.textContent=on?'« HIDE':'« HIDE'; }}
    const o=document.querySelector('#sbopen'); if(o){{ o.textContent=on?'MENU  »':'MENU  «'; o.title=on?'Show sidebar (Ctrl+B)':'Collapse sidebar (Ctrl+B)'; }}
  }}
  let off=false; try{{off=localStorage.getItem(KEY)==='1';}}catch(_){{}}
  apply(off);
  function set(on){{ try{{localStorage.setItem(KEY,on?'1':'0');}}catch(_){{}} apply(on); }}
  const t=document.querySelector('#sbtog'); if(t) t.onclick=()=>{{ let cur=false; try{{cur=localStorage.getItem(KEY)==='1';}}catch(_){{}} set(!cur); }};
  const o=document.querySelector('#sbopen'); if(o) o.onclick=()=>{{ let cur=false; try{{cur=localStorage.getItem(KEY)==='1';}}catch(_){{}} set(!cur); }};
  document.addEventListener('keydown',e=>{{
    if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='b'){{ e.preventDefault(); let cur=false; try{{cur=localStorage.getItem(KEY)==='1';}}catch(_){{}} set(!cur); }}
  }});
}})();
const _rb=document.querySelector('#rememberbtn'); if(_rb) _rb.onclick=async()=>{{
  const el=document.querySelector('#rememberbtn'); const on=!el.classList.contains('on');
  try{{await fetch(BASE+'/api/remember',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{on:on}})}});}}catch(_){{}}
  await loadRemember();
}};
const _vb=document.querySelector('#verifybtn'); if(_vb) _vb.onclick=async()=>{{
  const out=document.querySelector('#verifyout'); out.style.display='block'; out.textContent='verifying the signed record…';
  try{{const r=await fetch(BASE+'/api/verify'); const j=await r.json();
    out.textContent=j.ok?('RECORD VERIFIED · '+j.receipts+' receipts · merkle root '+j.root+'\\nlast: seq '+j.last_seq+' · '+j.last_kind+' · '+j.last_subject):('VERIFY FAILED: '+(j.error||'unknown'));
  }}catch(e){{out.textContent='VERIFY FAILED: '+e;}}
}};
loadRemember();

async function uploadFiles(files){{
  const st=document.querySelector('#upstatus');
  for(const f of files){{
    st.textContent='uploading '+f.name+'…';
    const fd=new FormData(); fd.append('file',f);
    const r=await fetch(BASE+'/api/upload',{{method:'POST',body:fd}});
    let j={{}}; try{{j=await r.json();}}catch(_){{}}
    if(j.error){{st.textContent='upload failed: '+j.error;}}
    else{{(j.files||[]).forEach(x=>attached.add(x.id)); st.textContent='uploaded '+f.name;}}
  }}
  await loadFiles(); renderAttached(); loadWork();
}}
document.querySelector('#fileinput').onchange=async ev=>{{await uploadFiles(ev.target.files); ev.target.value='';}};
document.querySelector('#imginput').onchange=async ev=>{{await uploadFiles(ev.target.files); ev.target.value='';}};
document.querySelector('#vidinput').onchange=async ev=>{{await uploadFiles(ev.target.files); ev.target.value='';}};
document.querySelector('#refreshfiles').onclick=()=>loadFiles();
async function loadWork(){{
  let j={{}}; try{{j=await (await fetch(BASE+'/api/workfiles')).json();}}catch(_){{}}
  const box=document.querySelector('#worklist'); if(!box) return; box.innerHTML='';
  const fs=j.files||[];
  if(!fs.length){{box.innerHTML='<p style="color:#5d6779">Nothing yet.</p>';return;}}
  fs.forEach(f=>{{
    const d=document.createElement('div'); d.className='plugin';
    d.innerHTML='<div style="flex:1"><h4></h4><p></p></div><div class=row style="gap:6px"></div>';
    d.querySelector('h4').textContent=f.name+(f.dir?'/':'');
    d.querySelector('p').textContent=f.dir?'folder':fmtSize(f.size);
    if(!f.dir){{const o=document.createElement('button'); o.className='chip'; o.textContent='OPEN';
      o.onclick=()=>window.open(BASE+'/work/'+encodeURIComponent(f.name),'_blank'); d.lastElementChild.appendChild(o);}}
    box.appendChild(d);
  }});
}}
document.querySelectorAll('[data-panel]').forEach(it=>it.addEventListener('click',()=>{{if(it.dataset.panel==='files')loadFiles();}}));
restore(); loadPlugins(); loadTasks();
""", css=FIRE_CSS + APPLET_CSS)

def download_body():
    return """CHC HARNESS — SEE 7.7.8 (S33)
Architecture, design and product spec. BAFOUNE-NET / CHCFLASH33 / MIRAGE INTELLIGENCE.

1. BRAND
   Wordmark: CHC HARNESS, neo green (#39ff9e) with black outline, large.
   2FA emblem: SEE 7.7.8 / S33 encryption mark, red-hot gradient.
   Backdrop: fire — red base, electric neo-blue and purple clash.

2. PRODUCT
   Chat workspace for smaller models that run on our own metal.
   Streamed tokens, mode row (CODER / REASONING / CHAT), permission row
   (READ-ONLY / READ-WRITE / FULL ACCESS), plugins store, automation, search.
   Plans: FREE 30 messages/day · STARTER $5/month · PRO $19/month.

3. STACK
   Python aiohttp + SQLite, one file per service. Local LLM (llama-server) on the box,
   optional upstream key for paid plans. Session cookie signed HMAC-SHA256.
   2FA: TOTP RFC 6238, 6 digits, 30s window, +/-1 step tolerance.

4. SECURITY
   Passwords: PBKDF2-HMAC-SHA256, 200,000 iterations, per-user salt.
   Sessions: HMAC-signed, HttpOnly, SameSite=Lax, 30 days.
   No SMS, no third-party auth. All secrets server-side only.
"""

# ------------------------------------------------------------------------- workspace
TEXT_EXT = {".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".jsonl", ".log", ".py", ".js",
            ".mjs", ".ts", ".html", ".htm", ".css", ".xml", ".yml", ".yaml", ".sh", ".sql", ".ini",
            ".conf", ".toml", ".rs", ".go", ".c", ".h", ".cpp", ".java", ".rb", ".php"}
IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".heic"}
VID_EXT = {".mp4", ".webm", ".mov", ".mkv", ".avi", ".m4v"}
AUD_EXT = {".mp3", ".wav", ".ogg", ".m4a", ".flac"}
MAX_UPLOAD = 200 * 1024 * 1024

def _safe_name(name: str) -> str:
    base = os.path.basename(name or "file")
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)[:120]
    return base or "file"

MASTER_MEMORY_PATH = os.environ.get("CHC_MASTER_MEMORY") or "/opt/chc-ai/master_memory.md"
_mm_cache = {"mtime": 0.0, "text": ""}


def master_memory() -> str:
    """Shared house memory, regenerated by tools/master_memory.py. Capped hard."""
    try:
        p = pathlib.Path(MASTER_MEMORY_PATH)
        m = p.stat().st_mtime
        if m != _mm_cache["mtime"]:
            _mm_cache["text"] = p.read_text()[:12000]
            _mm_cache["mtime"] = m
        return _mm_cache["text"]
    except Exception:
        return ""


def _kind(name: str) -> str:
    ext = os.path.splitext(name)[1].lower()
    if ext == ".pdf": return "pdf"
    if ext in (".docx", ".doc"): return "document"
    if ext in (".odt", ".ods", ".odp"): return "document"
    if ext in TEXT_EXT: return "text"
    if ext in IMG_EXT: return "image"
    if ext in VID_EXT: return "video"
    if ext in AUD_EXT: return "audio"
    return "file"

def extract_text(path: pathlib.Path, name: str) -> str:
    """Best-effort text for the model. Never raises; returns a short note on failure."""
    ext = os.path.splitext(name)[1].lower()
    try:
        if ext in (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"):
            try:
                r = subprocess.run(["tesseract", str(path), "stdout"], capture_output=True,
                                   text=True, timeout=90)
                txt = (r.stdout or "").strip()
            except FileNotFoundError:
                return "[image: OCR not installed on this server]"
            except Exception as e:
                return "[image: OCR failed: %s]" % type(e).__name__
            if txt:
                return "[OCR TEXT FROM IMAGE]\n" + txt[:40000]
            return ("[image: OCR found no readable text. The model cannot see pixels, so do not "
                    "describe this image; ask the user to describe it or paste the text.]")
        if ext == ".pdf":
            try:
                from pypdf import PdfReader
            except Exception:
                return "[pdf: text extraction unavailable on the server]"
            r = PdfReader(str(path))
            out = []
            for i, pg in enumerate(r.pages[:80]):
                out.append(pg.extract_text() or "")
            txt = "\n".join(out).strip()
            return txt[:400_000] if txt else "[pdf: no extractable text — probably scanned images]"
        if ext in (".docx", ".odt", ".ods", ".odp"):
            import zipfile, html as _html
            target = "word/document.xml" if ext == ".docx" else "content.xml"
            with zipfile.ZipFile(path) as z:
                raw = z.read(target).decode("utf-8", "replace")
            raw = re.sub(r"</(w:p|text:p|text:h)>", "\n", raw)
            raw = re.sub(r"<[^>]+>", "", raw)
            return _html.unescape(raw).strip()[:400_000]
        if ext in TEXT_EXT or ext in ("", ".txt"):
            return path.read_text("utf-8", "replace")[:400_000]
    except Exception as e:
        return f"[{ext or 'file'}: could not read text ({type(e).__name__})]"
    if ext in IMG_EXT:
        return f"[image: {name} — NOT VISIBLE TO YOU. You cannot see pixels or describe what it looks like.]"
    if ext in VID_EXT:
        return f"[video: {name} — NOT VISIBLE TO YOU. No frames were analysed.]"
    if ext in AUD_EXT:
        return f"[audio: {name} — NOT VISIBLE TO YOU. No transcription was made.]"
    return f"[binary file: {name}]"

# ------------------------------------------------------------------------- agent tools
WORK_ROOT = pathlib.Path(CLI.work)
TOOL_UID = int(os.environ.get("CHC_AI_TOOL_UID", "2000"))
TOOL_GID = int(os.environ.get("CHC_AI_TOOL_GID", "999"))

TOOL_SPECS = [
    {"type": "function", "function": {"name": "shell",
        "description": "Run one bash command in the workspace with live network access (curl, git, pip). 20s limit, output capped.",
        "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}}},
    {"type": "function", "function": {"name": "list_dir",
        "description": "List files in the workspace (or a subdirectory of it).",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {"name": "read_file",
        "description": "Read a text file from the workspace.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "write_file",
        "description": "Write a text file in the workspace.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                       "required": ["path", "content"]}}},
    {"type": "function", "function": {"name": "senses",
        "description": "MIRAGE SENSES (MCP): the box's eyes and mouth. op=look|ocr|read|find|click|type|scroll|navigate|watch|live|listen|speak|status. Pass text/url/x/y/dy/seconds as needed.",
        "parameters": {"type": "object", "properties": {"op": {"type": "string"}, "text": {"type": "string"},
            "url": {"type": "string"}, "x": {"type": "integer"}, "y": {"type": "integer"},
            "dy": {"type": "integer"}, "seconds": {"type": "integer"}, "every": {"type": "integer"}},
            "required": ["op"]}}},
    {"type": "function", "function": {"name": "paddy",
        "description": "PADDY browser operator: cmd=profiles|start|map|record|replay|tips|list|log|home, arg=profile or target.",
        "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}, "arg": {"type": "string"}},
            "required": ["cmd"]}}},
    {"type": "function", "function": {"name": "record",
        "description": "The house record: action=recall (query the archive), seal_verify (check the signed chain), seal_list (last receipts).",
        "parameters": {"type": "object", "properties": {"action": {"type": "string"}, "query": {"type": "string"}},
            "required": ["action"]}}},
    {"type": "function", "function": {"name": "models",
        "description": "List every local model reachable on this box (VPS Qwen, CHC-VM 8B, home 4B).",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "plugins",
        "description": "List every MCP server and plugin with a live up/down probe.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "web_fetch",
        "description": "Fetch a URL and return its readable text. Network is live.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "web_search",
        "description": "Search the web and return titles, URLs and snippets.",
        "parameters": {"type": "object", "properties": {"q": {"type": "string"}, "limit": {"type": "integer"}},
                       "required": ["q"]}}},
    {"type": "function", "function": {"name": "paddy_search",
        "description": "PADDY — the house search engine over the operator's own record (T1 PROVEN / T2 ASSERTED / T3 OPEN).",
        "parameters": {"type": "object", "properties": {"q": {"type": "string"}, "limit": {"type": "integer"}},
                       "required": ["q"]}}},
]
NET_TOOLS = {"web_fetch", "web_search", "paddy_search"}

def _tenant_uid(uid) -> int:
    """Unix uid that owns a tenant's workspace (own account per customer)."""
    try:
        c = db()
        row = c.execute("select tool_uid from users where id=?", (uid,)).fetchone()
        c.close()
        if row and row["tool_uid"]:
            return int(row["tool_uid"])
    except Exception:
        pass
    return TOOL_UID


def _tenant_gid(uid) -> int:
    t = _tenant_uid(uid)
    return t if t >= 2000 else TOOL_GID


def _workspace(uid) -> pathlib.Path:
    p = WORK_ROOT / str(uid)
    p.mkdir(parents=True, exist_ok=True)
    tun, tgn = _tenant_uid(uid), _tenant_gid(uid)
    try:
        os.chown(p, tun, tgn)
        os.chmod(p, 0o700)
        os.chown(p.parent, tun, tgn)
    except Exception:
        pass
    return p

def _tool_path(uid, rel):
    wd = _workspace(uid).resolve()
    rel = (rel or ".").lstrip("/")
    p = (wd / rel).resolve()
    if p != wd and not str(p).startswith(str(wd) + os.sep):
        return None
    return p

def _tool_shell(uid, cmd):
    wd = _workspace(uid)
    try:
        tmp = wd / ".tmp"
        try:
            tmp.mkdir(exist_ok=True)
            os.chown(tmp, _tenant_uid(uid), _tenant_gid(uid))
        except Exception:
            pass
        tun, tgn = _tenant_uid(uid), _tenant_gid(uid)
        p = subprocess.run(["setpriv", f"--reuid={tun}", f"--regid={tgn}", "--clear-groups",
                            "timeout", "20", "bash", "-lc", cmd],
                           cwd=str(wd), capture_output=True, text=True, timeout=45,
                           env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(wd),
                                "TMPDIR": str(tmp), "TMP": str(tmp), "TEMP": str(tmp),
                                "LANG": "C.UTF-8", "TERM": "dumb"})
        out = (p.stdout or "") + (("\n[stderr] " + p.stderr) if p.stderr else "")
        return (f"exit {p.returncode}\n{out}")[:6000]
    except subprocess.TimeoutExpired:
        return "timeout: killed after 20s"
    except Exception as e:
        return f"tool error: {type(e).__name__}"

VAULT = pathlib.Path(os.environ.get("CHC_VAULT", "/mnt/ledger/vault"))
PYBIN = os.environ.get("CHC_PYBIN", "python3")

# Every MCP server and plugin this house actually runs. `check` is the live probe;
# `call` is how the agent path reaches it. Nothing is listed that a probe cannot open.
PLUGIN_CATALOG = [
    {"id": "senses", "name": "MIRAGE SENSES (MCP)", "kind": "mcp/stdio",
     "entry": str(VAULT / "senses/mcp_server.py"),
     "desc": "Eyes and mouth for the browser fleet: screenshot, OCR, read the DOM, find/click/type, "
             "scroll, navigate, record frames, listen to system audio, speak aloud, report tab status.",
     "tools": ["look", "ocr", "read", "find", "click", "type", "scroll", "navigate", "watch", "live",
               "listen", "speak", "status"],
     "check": [PYBIN, str(VAULT / "tools/senses.py"), "status"]},
    {"id": "paddy", "name": "PADDY (browser operator)", "kind": "cli",
     "entry": str(VAULT / "plugins/paddy/paddy.py"),
     "desc": "Drives the CDP browser profiles (mirage:9241, erric:9234, thedundee:9230): map a page, "
             "record and replay a run, read tips, list profiles, pull logs.",
     "tools": ["profiles", "start", "map", "record", "replay", "tips", "list", "log", "home"],
     "check": [PYBIN, str(VAULT / "plugins/paddy/paddy.py"), "profiles"]},
    {"id": "paddy_search", "name": "PADDY SEARCH", "kind": "http",
     "entry": os.environ.get("CHC_AI_PADDY", "http://127.0.0.1:8099/api"),
     "desc": "House record search over the receipt chain and archives (FTS5, T1/T2/T3 provenance ranks).",
     "tools": ["search"], "check": None},
    {"id": "record", "name": "SEAL / VAULT RECORD", "kind": "cli",
     "entry": str(VAULT / "tools/seal.py"),
     "desc": "The signed receipt chain: append a finding or milestone, verify the chain, recall a topic "
             "from the archive. Append-only, hash-linked, blessed.",
     "tools": ["recall", "seal_verify", "seal_list"],
     "check": [PYBIN, str(VAULT / "tools/seal.py"), "verify"]},
    {"id": "chat_memory", "name": "CHAT MEMORY (MCP)", "kind": "mcp/stdio",
     "entry": str(VAULT / "tools/chat_memory_mcp.py"),
     "desc": "Semantic memory over the captured chat archive — ask what was said, when, by which unit.",
     "tools": ["search", "recall"], "check": None},
    {"id": "models", "name": "LOCAL MODEL FLEET", "kind": "http",
     "entry": "127.0.0.1:11436 / :8098 / :11434",
     "desc": "Every local brain with an OpenAI-compatible door: Qwen on the VPS (:11436), Qwen3-8B on "
             "CHC-VM (:8098), Qwen3-4B on the home box (:11434). List them, never guess.",
     "tools": ["list", "probe"], "check": None},
    {"id": "dsh", "name": "DSH HARNESSES", "kind": "http",
     "entry": ":3080 live · :3090 local lab",
     "desc": "The DeepSeek Harness instances on this box: the operator's own (:3080) and the local lab instance "
             "QWENLAB (:3090). Read-only from here — never restart them.",
     "tools": ["status"], "check": None},
    {"id": "data", "name": "HOUSE DATABASES", "kind": "sqlite",
     "entry": "dogs/gbgb.db · dogs/ghdata.db · crypto/enricher.db",
     "desc": "Read-only datasets: 150,141-race GBGB corpus, dog harvest, and the Blofin crypto "
             "funding/OI/wallet tables. Query with sqlite3, never write.",
     "tools": ["tables", "query"], "check": None},
]

def _probe(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "").strip() or (p.stderr or "").strip()
        return {"ok": p.returncode == 0, "detail": out.splitlines()[0][:160] if out else f"exit {p.returncode}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "detail": "probe timed out"}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}"}

def _http_probe(url, timeout=4):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return {"ok": 200 <= r.status < 400, "detail": f"HTTP {r.status}"}
    except urllib.error.HTTPError as e:
        return {"ok": e.code in (401, 403), "detail": f"HTTP {e.code} (up, auth wall)"}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}"}

def plugin_catalog(probe=True):
    """The live plugin/MCP inventory. Every probe is explicit; anything unproven reads DOWN."""
    items = []
    for p in PLUGIN_CATALOG:
        e = {k: v for k, v in p.items() if k != "check"}
        items.append(e)

    def _senses():
        return _probe([PYBIN, str(VAULT / "tools/senses.py"), "status"], timeout=12)

    def _paddy():
        return _probe([PYBIN, str(VAULT / "plugins/paddy/paddy.py"), "profiles"], timeout=12)

    def _record():
        return _probe([PYBIN, str(VAULT / "tools/seal.py"), "verify"], timeout=25)

    def _paddy_search():
        return _http_probe(os.environ.get("CHC_AI_PADDY", "http://127.0.0.1:8099/api").replace("/api", "/"))

    def _chat_memory():
        f = VAULT / "tools/chat_memory_mcp.py"
        if not f.exists():
            return {"ok": False, "detail": "entry missing"}
        r = _probe([PYBIN, "-c", "import py_compile;py_compile.compile(%r,doraise=True)" % str(f)], timeout=20)
        return {"ok": r["ok"], "detail": "stdio MCP, compiles" if r["ok"] else r["detail"]}

    def _models():
        alive = []
        for port in (11436, 8098, 11434):
            if _http_probe("http://127.0.0.1:%d/v1/models" % port, timeout=3)["ok"]:
                alive.append(str(port))
        return {"ok": bool(alive), "detail": ("ports " + ", ".join(alive)) if alive else "no local model port answering"}

    def _dsh():
        alive = []
        for port in (3080, 3090):
            r = _http_probe("http://127.0.0.1:%d/" % port, timeout=3)
            if r["ok"]:
                alive.append(str(port))
        return {"ok": bool(alive), "detail": ("ports " + ", ".join(alive)) if alive else "no DSH port answering"}

    def _data():
        hits = [rel for rel in ("dogs/gbgb.db", "dogs/ghdata.db", "crypto/enricher.db") if (VAULT / rel).exists()]
        return {"ok": bool(hits), "detail": ("%d datasets present" % len(hits)) if hits else "no datasets"}

    probes = {"senses": _senses, "paddy": _paddy, "paddy_search": _paddy_search, "record": _record,
              "chat_memory": _chat_memory, "models": _models, "dsh": _dsh, "data": _data}
    if probe:
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(max_workers=8) as pool:
            futs = {e["id"]: pool.submit(probes[e["id"]]) for e in items if e["id"] in probes}
            for e in items:
                fut = futs.get(e["id"])
                if fut is None:
                    e["status"], e["detail"] = "down", "no probe"
                    continue
                try:
                    r = fut.result(timeout=40)
                except Exception as ex:
                    r = {"ok": False, "detail": type(ex).__name__}
                e["status"] = "up" if r.get("ok") else "down"
                e["detail"] = r.get("detail", "")
    else:
        for e in items:
            e["status"], e["detail"] = "unknown", ""
    return items

PADDY_API = os.environ.get("CHC_AI_PADDY", "http://127.0.0.1:8099/api")

def _http_text(url, cap=8000, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (CHC-HARNESS/SEE778)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(cap * 4).decode("utf-8", "replace")
    return raw

def _to_text(html):
    html = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    html = re.sub(r"(?is)<br\s*/?>|</p>|</div>|</li>|</h[1-6]>", "\n", html)
    html = re.sub(r"<[^>]+>", " ", html)
    html = html.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
    html = re.sub(r"[ \t]+", " ", html)
    html = re.sub(r"\n\s*\n+", "\n\n", html)
    return html.strip()

def _web_fetch(url):
    if not re.match(r"^https?://", url or ""):
        return "need an http(s) URL"
    try:
        return _to_text(_http_text(url))[:8000]
    except Exception as e:
        return f"fetch failed: {type(e).__name__}"

def _paddy_search(q, limit=8):
    try:
        raw = _http_text(PADDY_API + "?q=" + urllib.parse.quote(q), cap=200000, timeout=20)
        j = json.loads(raw)
        rec = (j.get("record") or [])[:int(limit or 8)]
        if not rec: return "PADDY: no hits"
        out = [f"PADDY hits for {q!r} ({j.get('count', len(rec))}):"]
        for r in rec:
            out.append(f"- [{r.get('tier','?')} {r.get('grade','?')}] {r.get('path','')}:{r.get('line','?')} :: {(r.get('snippet') or '').strip()[:220]}")
        return "\n".join(out)
    except Exception as e:
        return f"PADDY unavailable: {type(e).__name__}"

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0 Safari/537.36")

def _http_text_ua(url, cap=8000, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept-Language": "en-GB,en;q=0.9"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(cap).decode("utf-8", "replace")

def _bing_url(href):
    try:
        href = (href or "").replace("&amp;", "&")
        if "bing.com/ck/a" in href:
            qs = urllib.parse.urlparse(href).query
            u = urllib.parse.parse_qs(qs).get("u", [""])[0]
            if u.startswith("a1"):
                b = u[2:]
                b += "=" * (-len(b) % 4)
                return base64.urlsafe_b64decode(b).decode("utf-8", "replace")
        return href
    except Exception:
        return href

def _parse_bing(html, limit):
    out = []
    for block in html.split('class="b_algo"')[1:limit + 1]:
        m = re.search(r'<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', block, re.S)
        if not m:
            continue
        url = _bing_url(m.group(1))
        title = _to_text(m.group(2))[:140]
        pm = re.search(r'<p[^>]*>(.*?)</p>', block, re.S)
        snip = _to_text(pm.group(1))[:220] if pm else ""
        out.append(f"- {title}\n  {url}\n  {snip}")
    return out

def _parse_mojeek(html, limit):
    out = []
    for block in html.split('<li>')[1:]:
        m = re.search(r'<a class="ob"[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>', block, re.S)
        if not m:
            m = re.search(r'<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>', block, re.S)
        if not m:
            continue
        pm = re.search(r'<p class="s">(.*?)</p>', block, re.S)
        out.append(f"- {_to_text(m.group(2))[:140]}\n  {m.group(1)}\n  {(_to_text(pm.group(1))[:200] if pm else '')}")
        if len(out) >= limit:
            break
    return out

def _web_search(q, limit=8):
    q = (q or "").strip()
    if not q:
        return "no query"
    limit = int(limit or 8)
    enc = urllib.parse.quote_plus(q)
    engines = [
        ("bing", f"https://www.bing.com/search?q={enc}&setlang=en&cc=GB", _parse_bing),
        ("mojeek", f"https://www.mojeek.com/search?q={enc}", _parse_mojeek),
    ]
    errs = []
    for name, url, parser in engines:
        try:
            rows = parser(_http_text_ua(url, cap=500000, timeout=25), limit)
            if rows:
                return f"WEB hits for {q!r} (via {name}):\n" + "\n".join(rows)
        except Exception as e:
            errs.append(f"{name}:{type(e).__name__}")
    return "no results (" + (", ".join(errs) or "engines returned nothing") + ") — try web_fetch on a known URL"

def _exec_tool(uid, name, args, perms="full"):
    try:
        if name in ({"shell"} | NET_TOOLS) and perms != "full":
            return "blocked: shell and network tools need FULL ACCESS. file tools work on READ-WRITE."
        if name == "web_fetch":
            return _web_fetch(str(args.get("url") or ""))
        if name == "web_search":
            return _web_search(str(args.get("q") or ""), args.get("limit") or 8)
        if name == "paddy_search":
            return _paddy_search(str(args.get("q") or ""), args.get("limit") or 8)
        if name == "senses":
            op = str(args.get("op") or "status").strip()
            if op not in ("look", "ocr", "read", "find", "click", "type", "scroll", "navigate", "watch",
                          "live", "listen", "speak", "status"):
                return "unknown senses op: " + op
            # senses_server takes positional k=v pairs. tools/senses.py used to be a PROBE
            # (no dispatch, args ignored) - calling it made every senses op a status blob.
            extra = ""
            for k in ("text", "url", "x", "y", "dy", "seconds", "every", "selector", "op", "out"):
                if args.get(k) not in (None, ""):
                    v = str(args[k]).replace('"', '')
                    extra += ' %s=%s' % (k, json.dumps(v) if " " in v else v)
            cmd = f"{PYBIN} {VAULT}/tools/senses_server.py {op}{extra}"
            return _tool_shell(uid, cmd)
        if name == "paddy":
            sub = str(args.get("cmd") or "profiles").strip()
            if sub not in ("profiles", "start", "map", "record", "replay", "tips", "list", "log", "home"):
                return "unknown paddy command: " + sub
            arg = str(args.get("arg") or "").strip()
            return _tool_shell(uid, f"{PYBIN} {VAULT}/plugins/paddy/paddy.py {sub} {arg}".strip())
        if name == "record":
            act = str(args.get("action") or "recall").strip()
            q = str(args.get("query") or "").strip()
            if act == "recall":
                return _tool_shell(uid, f"{PYBIN} {VAULT}/tools/recall.py {json.dumps(q)}")
            if act == "seal_verify":
                return _tool_shell(uid, f"{PYBIN} {VAULT}/tools/seal.py verify")
            if act == "seal_list":
                return _tool_shell(uid, f"{PYBIN} {VAULT}/tools/seal.py list --limit 10")
            return "unknown record action: " + act
        if name == "models":
            out = []
            for port in (11436, 8098, 11434):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/models", timeout=4) as rr:
                        ids = [m.get("id") for m in json.load(rr).get("data", [])]
                    out.append(f"{port}: " + ", ".join(str(i) for i in ids[:6]))
                except Exception as e:
                    out.append(f"{port}: {type(e).__name__}")
            return "\n".join(out)
        if name == "plugins":
            rows = plugin_catalog(probe=True)
            return "\n".join(f"{r['status']:4} {r['id']:12} {r['kind']:10} {r['name']} — {r['detail']}"
                              for r in rows)
        if name == "shell":
            return _tool_shell(uid, str(args.get("cmd") or "true"))
        if REFUSE_ROOT and os.geteuid() == 0:
            return "error: refusing to run tools as root on a customer box (uid 0)"
        if name == "list_dir":
            p = _tool_path(uid, str(args.get("path") or "."))
            if not p or not p.is_dir(): return "no such directory in the workspace"
            items = sorted(p.iterdir())[:200]
            return "\n".join(f"{'d' if i.is_dir() else '-'} {i.name}" for i in items) or "(empty)"
        if name == "read_file":
            p = _tool_path(uid, str(args.get("path") or ""))
            if not p or not p.is_file(): return "no such file in the workspace"
            if p.stat().st_size > 2_000_000: return "file too big (2 MB cap)"
            return p.read_text("utf-8", "replace")[:20000]
        if name == "write_file":
            if not args.get("path") or not str(args.get("path")).strip():
                return ('error: write_file needs arguments. Call it like: '
                        '{"path": "notes/thing.md", "content": "the text"} - the path is relative to your '
                        'workspace, it is a FILE name not a folder, and content is the text to write. '
                        'You sent: ' + json.dumps(args, ensure_ascii=False)[:200])
            p = _tool_path(uid, str(args.get("path") or ""))
            if not p: return "path outside the workspace"
            if p.is_dir():
                return ("error: %r is a DIRECTORY, not a file. Give a file name inside it, "
                        "e.g. 'senses/senses_browser.py' rather than 'senses'." % str(p.name or p))
            created = []
            d = p.parent
            wd = _workspace(uid).resolve()
            while d != wd and str(d).startswith(str(wd)):
                created.append(d); d = d.parent
            p.parent.mkdir(parents=True, exist_ok=True)
            for cd in reversed(created) or []:
                try: os.chown(cd, _tenant_uid(uid), _tenant_gid(uid))
                except Exception: pass
            _content = str(args.get("content") or "")
            _prev = p.stat().st_size if p.is_file() else 0
            _used = _ws_used(uid)
            if _used - _prev + len(_content.encode()) > WS_LIMIT:
                return ("error: workspace quota reached (%.1f MB used of %.0f MB). "
                        "Delete something or download files to your own machine first."
                        % (_used / 1e6, WS_LIMIT / 1e6))
            p.write_text(_content)
            try: os.chown(p, TOOL_UID, TOOL_GID)
            except Exception: pass
            return f"wrote {len(str(args.get('content') or ''))} chars to {p.name}"
        return f"unknown tool {name}"
    except Exception as e:
        return f"tool error: {type(e).__name__}"

DSML_INVOKE = re.compile(r'<\uff5c\uff5cDSML\uff5c\uff5c\s*invoke([^>]*)>(.*?)</\uff5c\uff5cDSML\uff5c\uff5c\s*invoke>', re.S)
DSML_PARAM = re.compile(r'<\uff5c\uff5cDSML\uff5c\uff5c\s*parameter\s+name="([^"]+)"[^>]*>(.*?)</\uff5c\uff5cDSML\uff5c\uff5c\s*parameter>', re.S)
TC_BLOCK = re.compile(r'<tool_call>\s*(.*?)\s*</tool_call>', re.S)
FC_BLOCK = re.compile(r'<function_call>\s*(.*?)\s*</function_call>', re.S)
FENCE_TOOL = re.compile(r'```(?:tool_call|tool|json)?\s*\n?\s*(\{\s*"(?:name|tool)"\s*:.*?)\s*```', re.S)

def _as_call(obj):
    if not isinstance(obj, dict): return None
    if isinstance(obj.get("function"), dict):
        fn = obj["function"]
        name = fn.get("name"); args = fn.get("arguments")
    else:
        name = obj.get("name") or obj.get("tool")
        args = obj.get("arguments", obj.get("args", obj.get("parameters", obj.get("input"))))
    if not name: return None
    if isinstance(args, str):
        try: args = json.loads(args)
        except Exception: args = {"_raw": args}
    if args is None: args = {}
    return {"id": "txt_" + secrets.token_hex(4), "type": "function",
            "function": {"name": str(name), "arguments": json.dumps(args)}}

def _parse_tool_text(text):
    """Models emit tool calls as TEXT in several dialects. Read them all, execute them all."""
    text = text or ""
    calls = []
    for m in DSML_INVOKE.finditer(text):
        attrs, body = m.group(1), m.group(2)
        nm = re.search(r'name="([^"]+)"', attrs)
        if not nm: continue
        args, got = {}, False
        for pm in DSML_PARAM.finditer(body):
            key, val = pm.group(1), pm.group(2).strip()
            if key == "arguments":
                try: args = json.loads(val)
                except Exception: args = {"_raw": val}
                got = True
            else:
                args[key] = val
        if not got and not args and body.strip().startswith("{"):
            try: args = json.loads(body.strip())
            except Exception: args = {}
        calls.append({"id": "dsml_" + secrets.token_hex(4), "type": "function",
                      "function": {"name": nm.group(1), "arguments": json.dumps(args)}})
    for rx in (TC_BLOCK, FC_BLOCK, FENCE_TOOL):
        for m in rx.finditer(text):
            raw = m.group(1).strip()
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            for cand in (obj if isinstance(obj, list) else [obj]):
                c = _as_call(cand)
                if c: calls.append(c)
    return calls

def _strip_tool_text(text):
    t = text or ""
    t = DSML_INVOKE.sub("", t)
    t = TC_BLOCK.sub("", t)
    t = FC_BLOCK.sub("", t)
    t = FENCE_TOOL.sub("", t)
    t = re.sub(r"<[^>]{0,120}?DSML[^>]{0,120}?>", "", t)
    t = t.replace("\uff5c\uff5cDSML\uff5c\uff5c", "")
    return t.strip()

# kept for older callers
_parse_dsml = _parse_tool_text
_strip_dsml = _strip_tool_text

def _specs_for(perms):
    """READ-WRITE gets file tools; FULL ACCESS adds the shell and the network tools."""
    if perms == "full":
        return list(TOOL_SPECS)
    drop = {"shell"} | NET_TOOLS
    return [t for t in TOOL_SPECS if (t.get("function") or {}).get("name") not in drop]

def _llm_call(key, messages, tools=None):
    body = {"model": "deepseek-chat", "messages": messages, "max_tokens": 1200,
            "temperature": 0.5, "stream": False}
    if tools:
        body["tools"] = tools; body["tool_choice"] = "auto"
    req = urllib.request.Request("https://api.deepseek.com/chat/completions",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + key})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)["choices"][0]["message"]

def _agent_run(msgs, uid, perms, on_delta, on_tool, on_note, on_done, on_error, up_key=None):
    """Upstream model + real tools. Tools run unprivileged in the user's own workspace."""
    try:
        key = up_key or UPSTREAM_KEY_FILE.read_text().strip()
        rounds = 0
        repeats = {}
        while True:
            rounds += 1
            cap = MAX_TOOL_CALLS if MAX_TOOL_CALLS is not None else 24
            if rounds > cap:
                on_note("tool-call cap reached (%d rounds) - stopping so it cannot loop" % cap)
                on_delta("\n\n(stopped: tool-call cap reached — the model was repeating itself)")
                on_done(); return
            m = _llm_call(key, msgs, _specs_for(perms))
            content = m.get("content") or ""
            calls = m.get("tool_calls") or _parse_dsml(content)
            if not calls:
                on_delta(_strip_dsml(content))
                on_done(); return
            m["tool_calls"] = calls
            msgs.append({"role": "assistant", "content": _strip_dsml(content), "tool_calls": calls})
            for tc in calls:
                fn = (tc.get("function") or {}).get("name") or ""
                try:
                    args = json.loads((tc.get("function") or {}).get("arguments") or "{}")
                except Exception:
                    args = {}
                sig = fn + "|" + json.dumps(args, ensure_ascii=False, sort_keys=True)
                repeats[sig] = repeats.get(sig, 0) + 1
                if repeats[sig] > 2:
                    # LOOP BREAKER: same call, same args, third time - refuse and make the model talk instead
                    out = ("LOOP BREAKER: %s was already called with these exact arguments %d times and failed "
                           "the same way every time. Do NOT call it again. Reply to the user in plain text now: "
                           "say what you tried, that it failed, and ask what they want instead." % (fn, repeats[sig] - 1))
                    on_note("loop breaker tripped on %s (x%d)" % (fn, repeats[sig]))
                    on_tool(fn, json.dumps(args, ensure_ascii=False), out)
                    msgs.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": out})
                    if repeats[sig] >= 5:
                        on_delta("\n\n(stopped: the same tool call failed 5 times in a row — that is a loop, "
                                 "not progress. Tell me what you actually need and I will do it differently.)")
                        on_done(); return
                    continue
                out = _exec_tool(uid, fn, args, perms)
                on_tool(fn, json.dumps(args, ensure_ascii=False), out)
                msgs.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": out})
        on_note("tool loop finished after %d rounds" % rounds)
        on_done()
    except Exception as e:
        on_error(f"{type(e).__name__}: {e}")

async def api_files(request):
    u = current_user(request)
    if not u: return web.json_response({"error": "auth"}, status=401)
    c = db()
    if request.method == "GET":
        rows = c.execute("select id,name,kind,size,created from files where uid=? order by id desc limit 200",
                         (u["id"],)).fetchall()
        c.close(); return web.json_response({"files": [dict(r) for r in rows]})
    d = await request.json()
    fid = d.get("id")
    c.execute("delete from files where id=? and uid=?", (fid, u["id"])); c.commit(); c.close()
    return web.json_response({"ok": True})

async def api_upload(request):
    u = current_user(request)
    if not u: return web.json_response({"error": "auth"}, status=401)
    if not request.content_type.startswith("multipart/"):
        return web.json_response({"error": "send multipart form data"}, status=400)
    reader = await request.multipart()
    saved = []
    c = db()
    while True:
        part = await reader.next()
        if part is None: break
        if part.name != "file" or not part.filename: continue
        name = _safe_name(part.filename)
        kind = _kind(name)
        udir = FILES_DIR / str(u["id"])
        udir.mkdir(parents=True, exist_ok=True)
        tmp = udir / ("incoming_" + name)
        size = 0
        with open(tmp, "wb") as fh:
            while True:
                chunk = await part.read_chunk(1024 * 256)
                if not chunk: break
                size += len(chunk)
                if size > MAX_UPLOAD:
                    fh.close(); tmp.unlink(missing_ok=True); c.close()
                    return web.json_response({"error": "file too big (200 MB limit)"}, status=413)
                fh.write(chunk)
        cur = c.execute("insert into files(uid,name,kind,size,path,ftext,created) values(?,?,?,?,?,?,?)",
                        (u["id"], name, kind, size, str(tmp), "", now()))
        fid = cur.lastrowid
        ftext = extract_text(tmp, name)
        c.execute("update files set ftext=? where id=?", (ftext, fid)); c.commit()
        saved.append({"id": fid, "name": name, "kind": kind, "size": size, "chars": len(ftext)})
    c.close()
    return web.json_response({"ok": True, "files": saved})

async def api_workfiles(request):
    u = current_user(request)
    if not u: return web.json_response({"error": "auth"}, status=401)
    wd = _workspace(u["id"])
    out = []
    for f in sorted(wd.iterdir())[:200]:
        try:
            out.append({"name": f.name, "dir": f.is_dir(), "size": f.stat().st_size if f.is_file() else 0})
        except Exception:
            pass
    return web.json_response({"files": out})

async def h_workfile(request):
    u = current_user(request)
    if not u: return web.HTTPFound(BASE + "/login")
    name = _safe_name(request.match_info["name"])
    p = _workspace(u["id"]) / name
    if not p.is_file(): raise web.HTTPNotFound()
    return web.FileResponse(p, headers={"Content-Disposition": f'inline; filename="{name}"'})

async def h_file(request):
    u = current_user(request)
    if not u: return web.HTTPFound(BASE + "/login")
    fid = request.match_info["fid"]
    c = db(); row = c.execute("select name,path,uid from files where id=?", (fid,)).fetchone(); c.close()
    if not row or row["uid"] != u["id"]: raise web.HTTPNotFound()
    p = pathlib.Path(row["path"])
    if not p.exists(): raise web.HTTPNotFound()
    return web.FileResponse(p, headers={"Content-Disposition": f'inline; filename="{row["name"]}"'})

# ------------------------------------------------------------------------- handlers
async def h_index(r): return web.Response(text=landing(), content_type="text/html")
async def h_signup_page(r): return web.Response(text=auth_page("signup"), content_type="text/html")
async def h_magic(r):
    """One-time login link: /magic?t=<token>. Single use, 15 min TTL, no password typed anywhere."""
    t = r.query.get("t", "")
    c = db()
    row = c.execute("select uid, exp, used from magic where token = ?", (t,)).fetchone()
    # link previews (WhatsApp/Telegram/etc) open the link before the human does — a single-use token
    # would burn on the preview. Allow a small number of redemptions inside the TTL instead.
    MAX_REDEEMS = 1   # one real redemption; preview fetches are exempt below and never consume
    ua = (r.headers.get("User-Agent") or "").lower()
    BOTS = ("whatsapp", "facebookexternalhit", "telegrambot", "twitterbot", "slackbot",
            "discordbot", "linkedinbot", "bot", "preview", "curl/", "wget/", "python-requests")
    is_preview = any(b in ua for b in BOTS)
    if not row or (row["used"] or 0) >= MAX_REDEEMS or int(row["exp"]) < int(time.time()):
        c.close()
        return web.Response(text="This login link is invalid, used or expired. Ask for a new one.", status=403)
    if is_preview:
        c.close()
        return web.Response(text="<!doctype html><meta charset=utf-8><title>CHC HARNESS</title>"
                                 "<body style='background:#080a0e;color:#39ff9e;font-family:monospace;padding:40px'>"
                                 "<h1>CHC HARNESS</h1><p>Private workspace link &mdash; open it in your browser to sign in.</p>"
                                 "</body>", content_type="text/html")
    c.execute("update magic set used = 1 where token = ?", (t,))
    c.commit(); c.close()
    resp = web.HTTPFound(BASE + "/app")
    resp.set_cookie(COOKIE, sign("u:%d" % row["uid"]), httponly=True, samesite="Lax",
                    max_age=60 * 60 * 24 * 30, path="/", secure=False)
    return resp

ENTER_LOGIN_PAGE = """<!doctype html><meta charset=utf-8><title>CHC HARNESS - sign in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 body{background:#05060a;color:#e8edf7;font:15px/1.6 system-ui;max-width:430px;margin:7vh auto;padding:0 20px}
 h1{font:900 30px/1 system-ui;color:#39ff9e;letter-spacing:.02em;margin:0 0 4px}
 p.sub{color:#8892a6;margin:0 0 22px}
 label{display:block;color:#8892a6;font-size:12px;margin:14px 0 6px;text-transform:uppercase;letter-spacing:.08em}
 input{width:100%;background:#0b0f16;border:1px solid #1d2230;border-radius:10px;color:#e8edf7;padding:12px;font:15px inherit}
 button{width:100%;margin-top:20px;padding:13px 18px;border:0;border-radius:11px;cursor:pointer;
   background:linear-gradient(135deg,#39ff9e,#14c47a);color:#04110a;font-weight:800;font-size:15px}
 .err{color:#ff7b72;font-size:13px;min-height:18px;margin-top:12px}
 .foot{color:#5d6779;font-size:12px;margin-top:26px;text-align:center}
 a{color:#39ff9e;text-decoration:none}
</style>
<h1>CHC HARNESS</h1>
<p class="sub">One link. Email + password. That is the whole login.</p>
<label>email</label><input id="em" autocomplete="username" autofocus>
<label>password</label><input id="pw" type="password" autocomplete="current-password">
<button id="go">SIGN IN</button>
<div class="err" id="msg"></div>
<p class="foot">No account on this box yet? <a href="/signup">CREATE ONE</a></p>
<script>
const go=document.getElementById('go'), msg=document.getElementById('msg');
async function doLogin(){
  msg.textContent='';
  const email=document.getElementById('em').value.trim(), pw=document.getElementById('pw').value;
  if(!email||!pw){msg.textContent='email and password required';return;}
  go.disabled=true;
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({email,pw})});
    const j=await r.json();
    if(j.ok){location='/app';return;}
    msg.textContent=j.error||'login failed';
  }catch(e){msg.textContent='network error';}
  go.disabled=false;
}
go.onclick=doLogin;
document.addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
</script>"""


async def h_enter(r):
    """/enter — THE permanent link. Same URL for ever, no token needed.

    No ?t=  -> a plain email + password form, posts to /api/login, lands in /app.
    ?t=<admin token> -> owner bootstrap: signs in the account in the OWNER file once
    (used by the installer so the first link works before a password exists)."""
    tok = r.query.get("t", "")
    if tok and ADMIN_TOKEN and tok == ADMIN_TOKEN:
        owner = ""
        for cand in (os.environ.get("CHC_OWNER_FILE") or "", "/opt/chc-harness/owner",
                     str(pathlib.Path(__file__).resolve().parent / "owner")):
            try:
                if cand and pathlib.Path(cand).is_file():
                    owner = pathlib.Path(cand).read_text().strip()
                    if owner:
                        break
            except Exception:
                pass
        c = db()
        row = None
        if owner:
            row = c.execute("select id from users where lower(email)=lower(?) limit 1", (owner,)).fetchone()
        if not row:
            row = c.execute("select id from users order by id limit 1").fetchone()
        if not row:
            c.close()
            return web.HTTPFound(BASE + "/enter")
        c.close()
        resp = web.HTTPFound(BASE + "/app")
        set_session(resp, row["id"], "enter-link", r)
        return resp
    if tok:
        return web.json_response({"error": "bad token"}, status=403)
    return web.Response(text=ENTER_LOGIN_PAGE, content_type="text/html")

async def h_signin(r):
    """Plain email + password sign-in — one page, two fields, no code needed."""
    body = """
<main style="max-width:440px;margin:12vh auto;padding:0 20px">
  <h1 class=wordmark style="font-size:30px">SIGN IN</h1>
  <p class=sub style="color:#8b93a3">Email and password. If you have not set a password yet, use the email-code page.</p>
  <div class=field><label>EMAIL</label><input id=em type=email autocomplete=username placeholder="you@example.com"></div>
  <div class=field><label>PASSWORD</label><input id=pw type=password autocomplete=current-password placeholder="your password"></div>
  <button class="btn neon" id=go style="width:100%">SIGN IN</button>
  <p id=msg style="color:#ff6b6b;min-height:20px"></p>
  <p class=sub><a href="/login">Use an email code instead</a> · <a href="/signup">Create an account</a></p>
  <script>
  async function go(){
    const em=document.getElementById('em').value.trim(), pw=document.getElementById('pw').value, msg=document.getElementById('msg');
    if(!em||!pw){msg.textContent='email and password, please';return;}
    const r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:em,pw:pw})});
    const j=await r.json().catch(()=>({}));
    if(j.ok){location.href='/app';} else {msg.textContent=j.error||'could not sign in';}
  }
  document.getElementById('go').onclick=go;
  document.getElementById('pw').addEventListener('keydown',e=>{if(e.key==='Enter')go();});
  </script>
</main>"""
    return web.Response(text=page("Sign in", body, css=FIRE_CSS), content_type="text/html",
                        headers={"Cache-Control": "no-store"})

async def h_login_page(r): return web.Response(text=auth_page("login"), content_type="text/html")
async def h_totp_page(r): return web.Response(text=totp_page(), content_type="text/html")
async def h_health(r):
    return web.json_response({"ok": True, "service": "chc-harness", "name": AGENT_NAME,
                              "version": VERSION, "llm": LLM_URL, "ts": time.time()})
def _bundled(name):
    """Look for a shipped file next to this app.py first (self-hosted copies), then the house path."""
    here = pathlib.Path(__file__).resolve().parent
    for c in (here / name, here / "pkg" / name, pathlib.Path("/opt/chc-ai/pkg") / name):
        try:
            if c.is_file():
                return c
        except Exception:
            pass
    return None


async def h_install_sh(r):
    f = _bundled("install.sh")
    if not f:
        return web.Response(text="# installer not bundled on this host\n", status=404, content_type="text/plain")
    return web.Response(text=f.read_text(), content_type="text/plain")


async def h_compose(r):
    f = _bundled("docker-compose.yml")
    if not f:
        return web.Response(text="# compose file not bundled on this host\n", status=404, content_type="text/plain")
    return web.Response(text=f.read_text(), content_type="text/plain")


async def h_dockerfile(r):
    f = pathlib.Path("/opt/chc-ai/pkg/Dockerfile")
    if not f.exists():
        return web.Response(text="# Dockerfile not bundled on this host\n", status=404, content_type="text/plain")
    return web.Response(text=f.read_text(), content_type="text/plain")


def _store_user_key(u, key):
    """Validate against DeepSeek, then store 0600 per account. Returns (ok, message)."""
    if not key.startswith("sk-") or len(key) < 20:
        return False, "that does not look like a DeepSeek key (sk-...)"
    try:
        body = json.dumps({"model": "deepseek-chat", "max_tokens": 4,
                           "messages": [{"role": "user", "content": "ping"}]}).encode()
        req = urllib.request.Request("https://api.deepseek.com/chat/completions", data=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
        with urllib.request.urlopen(req, timeout=20) as r:
            json.load(r)
    except Exception as e:
        return False, "key rejected by DeepSeek: %s" % str(e)[:120]
    UPSTREAM_DIR.mkdir(parents=True, exist_ok=True)
    pth = user_key_path(u["id"])
    pth.write_text(key); os.chmod(pth, 0o600)
    c = db(); c.execute("update users set upstream_on=1 where id=?", (u["id"],)); c.commit(); c.close()
    return True, "saved"

async def api_upstream(request):
    """UPSTREAM MODEL button: bring your own DeepSeek key, test it, switch it on/off."""
    u = auth_user(request)[0]
    if not u: return web.json_response({"error": "auth"}, status=401)
    st = upstream_state(u)
    if request.method == "GET":
        return web.json_response({"ok": True, **st})
    d = await request.json()
    act = (d.get("action") or "").strip()
    if act == "set":
        ok, why = _store_user_key(u, (d.get("key") or "").strip())
        if not ok:
            return web.json_response({"ok": False, "error": why}, status=400)
        return web.json_response({"ok": True, **upstream_state(current_user(request))})
    if act in ("on", "off"):
        c = db(); c.execute("update users set upstream_on=? where id=?", (1 if act == "on" else 0, u["id"]))
        c.commit(); c.close()
        return web.json_response({"ok": True, **upstream_state(current_user(request))})
    if act == "forget":
        try: user_key_path(u["id"]).unlink()
        except Exception: pass
        c = db(); c.execute("update users set upstream_on=0 where id=?", (u["id"],)); c.commit(); c.close()
        return web.json_response({"ok": True, **upstream_state(current_user(request))})
    return web.json_response({"ok": False, "error": "unknown action"}, status=400)


async def api_feedback(request):
    """Comments / feedback from any page. Stored server-side, never public."""
    d = await request.json()
    body = (d.get("body") or "").strip()
    if len(body) < 3:
        return web.json_response({"error": "say a bit more"}, status=400)
    u = current_user(request)
    c = db()
    c.execute("insert into feedback(uid,email,kind,body,page,created) values(?,?,?,?,?,?)",
              (u["id"] if u else None, u["email"] if u else "", (d.get("kind") or "comment")[:24],
               body[:4000], (d.get("page") or "")[:120], now()))
    c.commit(); c.close()
    return web.json_response({"ok": True, "thanks": "received - it is on the board"})


async def h_feedback(r):
    u = current_user(r)
    if not u:
        return web.HTTPFound(BASE + "/login")
    body = f"""<div class="wrap" style="max-width:720px;padding:56px 20px">
<h1 class=wordmark style="font-size:clamp(26px,5vw,52px);color:var(--neo)">FEEDBACK</h1>
<p style="color:var(--dim)">Comments, bugs, requests. Straight to the board — signed in as {u['email']}.</p>
<div class=card><label style="color:var(--dim);font-size:13px">KIND</label>
<select id=fkind class="mono" style="width:100%;padding:10px;background:#0b0e14;color:var(--ink);border:1px solid var(--line);border-radius:6px">
<option value=comment>comment</option><option value=bug>bug</option><option value=idea>idea</option><option value=praise>praise</option></select>
<label style="color:var(--dim);font-size:13px;margin-top:10px;display:block">YOUR WORDS</label>
<textarea id=fbody rows=6 style="width:100%;padding:10px;background:#0b0e14;color:var(--ink);border:1px solid var(--line);border-radius:6px"></textarea>
<div class=row style="margin-top:10px"><button class=btn id=fsend>POST COMMENT</button>
<a class="btn ghost" href="{BASE}/app">BACK</a></div><p id=fmsg style="color:var(--neo);margin-top:8px"></p></div>
<p style="color:#5d6779;font-size:12px">Comments are stored on our server with your account email. We do not publish them.</p></div>
<script>
document.querySelector('#fsend').onclick=async()=>{{
  const msg=document.querySelector('#fmsg');
  const j=await (await fetch('{BASE}/api/feedback',{{method:'POST',headers:{{'content-type':'application/json'}},
    body:JSON.stringify({{kind:document.querySelector('#fkind').value,
                          body:document.querySelector('#fbody').value,
                          page:location.pathname}})}})).json();
  msg.textContent=j.ok?('✓ '+j.thanks):('✗ '+(j.error||'failed'));
  if(j.ok) document.querySelector('#fbody').value='';
}};
</script>"""
    return web.Response(text=page("Feedback · CHC HARNESS", body, css=FIRE_CSS), content_type="text/html")


async def h_admin_feedback(r):
    tok = r.query.get("token", "")
    try:
        want = (CLI.admin_token or ADMIN_TOKEN_FILE.read_text().strip())
    except Exception:
        want = CLI.admin_token or ""
    if not want or tok != want:
        return web.Response(text="forbidden", status=403)
    c = db()
    rows = c.execute("select id,email,kind,body,page,created,status from feedback order by id desc limit 300").fetchall()
    c.close()
    items = "".join("<div class=card style='margin:8px 0'><b>%s</b> <span style='color:#5d6779'>#%d %s %s · %s</span>"
                    "<p style='color:var(--dim);white-space:pre-wrap'>%s</p></div>"
                    % (r2["email"] or "-", r2["id"], r2["kind"], r2["created"], r2["page"],
                       (r2["body"] or "").replace("<", "&lt;")) for r2 in rows)
    return web.Response(text=page("Feedback board", "<div class='wrap' style='max-width:860px;padding:40px 20px'><h1>FEEDBACK (%d)</h1>%s</div>" % (len(rows), items or "<p>none yet</p>"), css=FIRE_CSS), content_type="text/html")


async def h_upstream_switch(r):
    """ONE CLICK model switch. No key, no form: /upstream/on and /upstream/off."""
    u = current_user(r)
    if not u:
        return web.HTTPFound(BASE + "/login")
    want = 1 if r.path.rstrip("/").endswith("/on") else 0
    ok = True
    if want:
        st = upstream_state(u)
        if not st["plan_allows"] or not (st["own_key"] or st["house_key"]):
            ok = False
    if ok:
        c = db(); c.execute("update users set upstream_on=? where id=?", (want, u["id"])); c.commit(); c.close()
    back = BASE + "/app" + ("?model=locked" if not ok else ("?model=deepseek&switched=deepseek" if want else "?model=local&switched=local"))
    return web.HTTPFound(back)


async def h_upstream(r):
    """Server-rendered upstream control. No JavaScript needed - the link always works."""
    u = current_user(r)
    if not u:
        return web.HTTPFound(BASE + "/login")
    msg = ""
    if r.method == "POST":
        d = await r.post()
        act = (d.get("action") or "").strip()
        if act == "set":
            key = (d.get("key") or "").strip()
            ok, why = _store_user_key(u, key)
            msg = ("Key saved and verified — press USE UPSTREAM." if ok else why)
        elif act in ("on", "off"):
            c = db(); c.execute("update users set upstream_on=? where id=?",
                                (1 if act == "on" else 0, u["id"])); c.commit(); c.close()
            msg = "Upstream is ON — your calls now go to DeepSeek." if act == "on" else "Back on the local Qwen."
        elif act == "forget":
            try: user_key_path(u["id"]).unlink()
            except Exception: pass
            c = db(); c.execute("update users set upstream_on=0 where id=?", (u["id"],)); c.commit(); c.close()
            msg = "Stored key deleted. You are on the local Qwen."
        u = current_user(r)
    st = upstream_state(u)
    state = ("ON — calls go to DeepSeek" if st["on"] else
             ("READY — press USE UPSTREAM" if (st["own_key"] or st["house_key"]) and st["plan_allows"]
              else ("LOCKED — needs the DeepSeek top-up" if not st["plan_allows"] else "NO KEY YET")))
    note = ('<p style="color:var(--neo)">%s</p>' % msg) if msg else ""
    plan = PLANS["deepseek3"]
    body = f"""<div class="wrap" style="max-width:720px;padding:56px 20px">
<h1 class=wordmark style="font-size:clamp(26px,5vw,52px);color:var(--neo)">UPSTREAM MODEL</h1>
<p style="color:var(--dim)">Bring your own DeepSeek key — or use the house key on the {plan['price']}/{plan['period']} plan.
Your key is stored in a 0600 file for your account only and never shown again.</p>
{note}
<div class=card>
<h3 style="margin-top:0">{state}</h3>
<p style="color:var(--dim);font-size:13px">plan allows upstream: <b>{'yes' if st['plan_allows'] else 'no'}</b>
 &nbsp;·&nbsp; your own key on file: <b>{'yes' if st['own_key'] else 'no'}</b>
 &nbsp;·&nbsp; house key available: <b>{'yes' if st['house_key'] else 'no'}</b></p>
<form method=post action="{BASE}/upstream">
  <input type=hidden name=action value=set>
  <input name=key type=password placeholder="sk-... your DeepSeek key" style="width:100%;padding:10px;background:#0b0e14;color:var(--ink);border:1px solid var(--line);border-radius:6px">
  <div class=row style="margin-top:10px"><button class=btn type=submit>SAVE KEY + TEST</button></div>
</form>
<div class=row style="margin-top:10px">
  <form method=post action="{BASE}/upstream"><input type=hidden name=action value=on><button class=btn type=submit>USE UPSTREAM</button></form>
  <form method=post action="{BASE}/upstream"><input type=hidden name=action value=off><button class="btn ghost" type=submit>USE LOCAL</button></form>
  <form method=post action="{BASE}/upstream"><input type=hidden name=action value=forget><button class="btn ghost" type=submit>FORGET KEY</button></form>
</div>
</div>
<p style="color:#5d6779;font-size:12px">DeepSeek pricing: the add-on is {plan['price']} per {plan['period']}, {plan['calls']}.
Margins are audited at boot so the add-on never sells below half the upstream cost.</p>
<p><a class=btn href="{BASE}/app">BACK TO WORKSPACE</a> <a class="btn ghost" href="{BASE}/plan">PLANS</a></p>
</div>"""
    return web.Response(text=page("Upstream · CHC HARNESS", body, css=FIRE_CSS), content_type="text/html")


async def h_authorise(request):
    """One page, plain links: the customer decides whether SPARKY may remember them."""
    u = current_user(request)
    if not u:
        return web.HTTPFound(BASE + "/login")
    act = request.match_info.get("act", "")
    if act == "on":
        c = db(); c.execute("update users set memory_on=1 where id=?", (u["id"],)); c.commit(); c.close()
    elif act == "off":
        c = db(); c.execute("update users set memory_on=0 where id=?", (u["id"],)); c.commit(); c.close()
    elif act == "forget":
        try:
            d = _mem_dir(u["id"])
            for pth in list(d.glob("turns.jsonl")) + list(d.glob("facts.jsonl")) + list(d.glob("report-*.json")):
                if pth.is_file(): pth.unlink()
        except Exception:
            pass
    u = current_user(request)
    on = memory_authorised(u)
    facts = _mem_facts(u["id"]) if on else []
    turns = 0
    try:
        pth = _mem_dir(u["id"]) / "turns.jsonl"
        turns = sum(1 for _ in pth.open()) if pth.is_file() else 0
    except Exception:
        pass
    state = ("AUTHORISED - SPARKY keeps notes about you and reports progress to the house"
             if on else "NOT AUTHORISED - nothing is stored, nothing is reported")
    facts_html = "".join("<li>%s <span style='color:#5d6779'>(%s)</span></li>"
                         % (str(f.get("fact","")).replace("<","&lt;"), f.get("kind",""))
                         for f in facts[-20:]) or "<li style='color:#5d6779'>(nothing yet)</li>"
    body = f"""<div class="wrap" style="max-width:760px;padding:56px 20px">
<h1 class=wordmark style="font-size:clamp(26px,5vw,52px);color:var(--neo)">AUTHORISE MEMORY</h1>
<p style="color:var(--dim)">You decide. This is the button that controls whether SPARKY is allowed to
learn from your chats.</p>
<div class=card><h3 style="margin-top:0;color:{'var(--neo)' if on else 'var(--amber)'}">{state}</h3>
<p style="color:var(--dim)">If you authorise, SPARKY stores: a compact record of each turn (your words and
his reply), and the facts distilled from them - your name if you give it, preferences you state,
decisions you make. It uses them to answer you better across chats, and it reports progress
back to the house as <b>numbers only</b> - turns, fact count, errors, model mix. Your message text and
the fact strings themselves never leave this box in that report. FORGET EVERYTHING deletes the turns,
the facts and the daily report files for your account.</p>
<p style="color:var(--dim)">If you do not authorise: nothing is written to memory, no facts are learned,
and no report is made. You can revoke or forget at any time, and forgetting deletes the files.</p>
<p style="color:var(--dim)"><b>{turns}</b> turns stored &nbsp;·&nbsp; <b>{len(facts)}</b> facts learned</p>
<div class=row style="margin-top:12px">
<a class=btn href="{BASE}/authorise/on">AUTHORISE</a>
<a class="btn ghost" href="{BASE}/authorise/off">REVOKE</a>
<a class="btn ghost" href="{BASE}/authorise/forget">FORGET EVERYTHING</a>
</div></div>
<div class=card><h3 style="margin-top:0">WHAT HE KNOWS ABOUT YOU</h3><ul style="color:var(--dim)">{facts_html}</ul></div>
<p><a class=btn href="{BASE}/app">BACK TO WORKSPACE</a></p></div>"""
    return web.Response(text=page("Authorise · CHC HARNESS", body, css=FIRE_CSS), content_type="text/html",
                        headers={"Cache-Control": "no-store"})


async def api_memory(request):
    """What SPARKY remembers about this account. Visible, deletable, never hidden."""
    u = current_user(request)
    if not u:
        return web.json_response({"error": "auth"}, status=401)
    if request.method == "POST":
        d = await request.json()
        if "authorise" in d:
            c = db(); c.execute("update users set memory_on=? where id=?",
                                (1 if d["authorise"] else 0, u["id"])); c.commit(); c.close()
            return web.json_response({"ok": True, "authorised": bool(d["authorise"])})
        if d.get("forget"):
            try:
                _d = _mem_dir(u["id"])
                for pth in list(_d.glob("turns.jsonl")) + list(_d.glob("facts.jsonl")) + list(_d.glob("report-*.json")):
                    if pth.is_file(): pth.unlink()
            except Exception: pass
            return web.json_response({"ok": True, "forgotten": True})
    facts = _mem_facts(u["id"])[-50:]
    turns = 0
    try:
        p = _mem_dir(u["id"]) / "turns.jsonl"
        turns = sum(1 for _ in p.open()) if p.is_file() else 0
    except Exception:
        pass
    return web.json_response({"authorised": memory_authorised(u), "turns": turns, "facts": facts,
                              "dir": str(_mem_dir(u["id"])), "hosted": HOSTED, "ws_limit": WS_LIMIT})


async def api_workspace(request):
    """How much of the 1 GB is used - the customer can see it, not guess it."""
    u = current_user(request)
    if not u:
        return web.json_response({"error": "auth"}, status=401)
    used = _ws_used(u["id"])
    return web.json_response({"used": used, "limit": WS_LIMIT,
                              "pct": round(100.0 * used / WS_LIMIT, 1) if WS_LIMIT else 0,
                              "root": os.geteuid() == 0, "limit_mb": round(WS_LIMIT / 1e6)})


async def api_publish(request):
    """PUBLISH: hand a workspace file out of the sandbox as an unguessable download link.
    The file never leaves the box - we serve it from here and show its sha256 so the
    customer can prove what they got is what was on the box."""
    u = current_user(request)
    if not u: return web.json_response({"error": "auth"}, status=401)
    try:
        d = await request.json()
    except Exception:
        return web.json_response({"error": "json"}, status=400)
    fid = d.get("id")
    c = db()
    row = c.execute("select id,name,kind,size,path,ftext from files where id=? and uid=?",
                    (fid, u["id"])).fetchone()
    if not row:
        c.close(); return web.json_response({"error": "no such file"}, status=404)
    src = None
    if row["path"] and pathlib.Path(row["path"]).is_file():
        src = pathlib.Path(row["path"])
    digest, size = "", 0
    if src:
        h = hashlib.sha256()
        with open(src, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk); size += len(chunk)
        digest = h.hexdigest()
    else:
        digest = hashlib.sha256((row["ftext"] or "").encode()).hexdigest()
        size = len(row["ftext"] or "")
    token = secrets.token_urlsafe(18)
    c.execute("insert into publish(token,uid,fid,name,sha256,size,created) values(?,?,?,?,?,?,?)",
              (token, u["id"], row["id"], row["name"], digest, size, now()))
    c.commit(); c.close()
    # absolute, request-derived (BASE is empty on the root-served instance)
    host = request.host or "127.0.0.1"
    scheme = request.headers.get("X-Forwarded-Proto") or request.scheme or "https"
    url = f"{scheme}://{host}{BASE}/p/{token}"
    return web.json_response({"ok": True, "url": url, "name": row["name"], "sha256": digest,
                              "size": size, "expires": "until you delete it"})

async def h_published(request):
    token = request.match_info.get("token", "")
    c = db()
    row = c.execute("select uid,fid,name,sha256 from publish where token=?", (token,)).fetchone()
    if not row:
        c.close(); return web.Response(text="no such published file", status=404)
    f = c.execute("select name,kind,path,ftext from files where id=? and uid=?",
                  (row["fid"], row["uid"])).fetchone()
    c.close()
    if not f:
        return web.Response(text="the published file no longer exists", status=404)
    headers = {"X-SHA256": row["sha256"], "Content-Disposition": 'attachment; filename="%s"' % f["name"]}
    if f["path"] and pathlib.Path(f["path"]).is_file():
        return web.FileResponse(pathlib.Path(f["path"]), headers=headers)
    return web.Response(text=f["ftext"] or "", headers=headers, content_type="text/plain")

async def h_download(r):
    here = pathlib.Path(__file__).resolve().parent
    cands = []
    for d in (here / "dist", here, here.parent, here.parent / "dist", pathlib.Path("/opt/chc-harness/dist")):
        try: cands += sorted(d.glob("chc-harness-*.tar.gz"))
        except Exception: pass
    def _pk(path):
        m = re.search(r"chc-harness-(\d+(?:\.\d+)*)\.tar\.gz$", path.name)
        parts = tuple(int(x) for x in m.group(1).split(".")) if m else (0,)
        try: mt = path.stat().st_mtime
        except Exception: mt = 0.0
        return (parts, mt)
    pkg = sorted(set(cands), key=_pk)   # version-aware, not lexicographic: 3.6.10 > 3.6.9
    if pkg:
        f = pkg[-1]
        return web.FileResponse(f, headers={"Content-Disposition":
                               f'attachment; filename="{f.name}"'})
    return web.Response(text=download_body(), content_type="text/plain",
                        headers={"Content-Disposition": 'attachment; filename="CHC_HARNESS_SEE778_spec.txt"'})

async def api_signup(request):
    d = await request.json()
    email = (d.get("email") or "").strip().lower()
    handle = (d.get("handle") or "").strip()
    pw, pw2 = d.get("pw") or "", d.get("pw2") or ""
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email): return web.json_response({"error": "valid email required"})
    if len(pw) < 10: return web.json_response({"error": "password must be at least 10 characters"})
    if pw != pw2: return web.json_response({"error": "passwords do not match"})
    salt = new_salt(); secret = b32(secrets.token_bytes(20))
    c = db()
    try:
        c.execute("insert into users(email,handle,pw,salt,totp,plan,created,verified) values(?,?,?,?,?,?,?,0)",
                  (email, handle or email.split("@")[0], pw_hash(pw, salt), salt, secret, "free", now()))
    except sqlite3.IntegrityError:
        c.close(); return web.json_response({"error": "that email already has an account — log in instead"})
    uid = c.execute("select id from users where email=?", (email,)).fetchone()[0]
    c.commit(); c.close()
    # every account gets its OWN sealed chain, own key, in its own directory - never ours
    try:
        _log = open("/opt/chc-ai/vault_provision.log", "a")
        subprocess.Popen(["/opt/chc-ai/.venv/bin/python3", "/opt/chc-ai/tools/user_vault.py",
                          "--ensure", str(uid), email, handle or email.split("@")[0]],
                         stdout=_log, stderr=_log)
    except Exception as _e:
        open("/opt/chc-ai/vault_provision.log", "a").write("signup vault spawn failed uid=%s: %r\n" % (uid, _e))
    return web.json_response({"ok": True, "totp": secret, "created": 1, "acct": email})

async def api_login(request):
    d = await request.json()
    ident = (d.get("email") or "").strip().lower()
    pw, code = d.get("pw") or "", (d.get("code") or "").strip()
    c = db()
    row = c.execute("select * from users where email=? or lower(handle)=?", (ident, ident)).fetchone()
    c.close()
    if not row: return web.json_response({"error": "no such account"})
    if not hmac.compare_digest(pw_hash(pw, row["salt"]), row["pw"]):
        return web.json_response({"error": "wrong password"})
    # 2FA is OPTIONAL (operator, 7 Nov): a correct password opens the session.
    # If a code IS supplied it must be valid; no code is not an error.
    if code and not totp_ok(row["totp"], code):
        return web.json_response({"error": "bad 2FA code (or leave the code blank)"})
    resp = web.json_response({"ok": True})
    set_session(resp, row["id"], "password", request)
    return resp

async def api_totp_confirm(request):
    d = await request.json()
    secret, code, acct = d.get("secret", ""), d.get("code", ""), (d.get("acct") or "").strip().lower()
    c = db(); row = c.execute("select id,totp from users where email=?", (acct,)).fetchone()
    if not row or row["totp"] != secret: c.close(); return web.json_response({"error": "account not found"})
    if not totp_ok(secret, code): c.close(); return web.json_response({"error": "bad code — check your authenticator"})
    c.execute("update users set verified=1 where id=?", (row["id"],)); c.commit(); c.close()
    resp = web.json_response({"ok": True}); set_session(resp, row["id"], "totp-confirm", request); return resp

async def h_app(r):
    u = current_user(r)
    if not u: return web.HTTPFound(BASE + "/login")
    sw = (r.query.get("switched") or "").strip()
    return web.Response(text=app_page(u, switched=sw), content_type="text/html",
                        headers={"Cache-Control": "no-store, must-revalidate", "Pragma": "no-cache"})

async def h_logout(r):
    resp = web.HTTPFound(BASE + "/")
    resp.del_cookie(COOKIE, path="/")
    return resp

async def api_model(request):
    """Per-account model choice: every account runs the model it wants."""
    u = current_user(request)
    if not u: return web.json_response({"error": "auth"}, status=401)
    d = await request.json()
    want = (d.get("model") or "auto").strip().lower()
    if want not in ("auto", "local", "deepseek"):
        return web.json_response({"error": "model must be auto, local or deepseek"}, status=400)
    c = db()
    try:
        c.execute("update users set model=? where id=?", (want, u["id"]))
        c.commit()
    except Exception:
        try:
            c.execute("alter table users add column model text default 'auto'")
            c.execute("update users set model=? where id=?", (want, u["id"]))
            c.commit()
        except Exception:
            pass
    c.close()
    return web.json_response({"ok": True, "model": want,
                              "note": "deepseek needs a big plan or your own key; local always runs"})

async def api_me(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    return web.json_response({"email": u["email"], "handle": u["handle"], "plan": u["plan"], "tier": u["tier"], "remember_all": (u["remember_all"] if "remember_all" in u.keys() else 0),
                "model": ((u["model"] if "model" in u.keys() else "auto") or "auto")})

async def api_chats(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    c = db()
    if r.method == "POST":
        d = await r.json(); cid = uuid.uuid4().hex[:12]
        c.execute("insert into chats(id,uid,title,created,updated,perms) values(?,?,?,?,?,?)",
                  (cid, u["id"], (d.get("title") or "new chat")[:60], now(), now(), d.get("perms") or "read-write"))
        c.commit(); c.close(); return web.json_response({"id": cid})
    rows = c.execute("select id,title,updated from chats where uid=? order by updated desc limit 60", (u["id"],)).fetchall()
    c.close()
    return web.json_response({"chats": [dict(x) for x in rows]})

async def api_chat_get(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    cid = r.match_info["cid"]; c = db()
    own = c.execute("select 1 from chats where id=? and uid=?", (cid, u["id"])).fetchone()
    if not own: c.close(); return web.json_response({"error": "not found"}, status=404)
    rows = c.execute("select id,role,content,ts from msgs where chat=? order by id", (cid,)).fetchall()
    try:
        tools = c.execute("select ts,name,args,result from tool_runs where chat=? order by id", (cid,)).fetchall()
        tools = [dict(x) for x in tools]
    except Exception:
        tools = []
    c.close()
    return web.json_response({"messages": [dict(x) for x in rows], "tools": tools})


async def api_chat_since(r):
    """Messages newer than ?after=<id> — what the inline chat polls so a second device
    or a second tab sees the same conversation without a reload."""
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    cid = r.match_info["cid"]
    try: after = int(r.query.get("after", "0") or 0)
    except Exception: after = 0
    c = db()
    own = c.execute("select 1 from chats where id=? and uid=?", (cid, u["id"])).fetchone()
    if not own: c.close(); return web.json_response({"error": "not found"}, status=404)
    rows = c.execute("select id,role,content,ts from msgs where chat=? and id>? order by id", (cid, after)).fetchall()
    c.close()
    return web.json_response({"messages": [dict(x) for x in rows]})

PERSONA_TEMPLATE = """You are {NAME} — the resident AI of CHC HARNESS (CHCFLASH33 / BAFOUNE-NET / MIRAGE INTELLIGENCE).
You are not a chatbot. You are a modern harness unit and the user's 2IC — second in command: the user makes the decision, you own the execution and report back clean.
Voice: warm, quick, dry Northern-British humour. Direct. No filler, no hype, no apology loops.
HOUSE RULES (never break):
1. Grade claims: PROVEN (evidence given), ASSERTED (your opinion), OPEN (unknown). If OPEN, say how to find out.
2. Never invent files, prices, dates, results or quotes. Anything you were not given is OPEN.
3. Never print secrets, keys, passwords or personal data. Never claim to be DeepSeek, Qwen, OpenAI or any other vendor model.
4. Answer first, detail second. Short by default; go long only when the job needs it.
5. Keep the user's own words and language.
HOW YOU WRITE:
- Open with the answer or the action — never with your name, your role, or a restatement of the question.
- Never repeat a sentence, heading, greeting or sign-off you already used in this conversation. If you feel one coming, cut it.
- Introduce yourself only if asked who you are. One greeting per conversation, not per message.
- No "anything else?", no "let me know if", no closing loop. End on the next action, a real question, or full stop.
WHAT THIS UNIT IS: an advanced harness unit — three modes (coder, reasoning, chat), workspace permissions (read-only, read-write, full), plugins, saved sessions, and your own private 1 GB workspace. Accounts run on the local Qwen by default; a DeepSeek upstream add-on exists for accounts that pay for it. If asked which model is answering, say "Qwen (local)" honestly, never pretend otherwise.
YOU CANNOT GENERATE IMAGES. There is no image model on this box. You can view, OCR, describe and discuss images the user uploads (IMAGE button), and render text-based art if asked. If asked to draw, generate or "make me a picture", say plainly that image generation is not wired here and offer the honest alternatives (describe it, plan it, or work from an uploaded image). Never claim to have produced an image you did not receive.
If asked who you are or what mode you are in, answer with the name and the live mode: "{NAME}, CHC HARNESS — coder mode. What are we doing?"
"""

PERSONA = PERSONA_TEMPLATE.replace("{NAME}", AGENT_NAME)

PRODUCT_CTX = """
THE PRODUCT — answer from this, never guess:
- Public site: https://ai.94-237-56-140.sslip.io
- FREE: $0, 60 calls per day, local Qwen, no card.
- QWEN+: $5 per month, 1,200 calls per day, upscaled Qwen on its own slot.
- DEEPSEEK: $5 top-up = $2.50 of DeepSeek upstream usage (about 2,500 calls) plus API key access.
- SELF-HOST: download and run on the customer's own machine — full access to that machine, no call cap.
- Sign up: /signup, email only, a 6-digit code arrives by email, account is live on FREE immediately. Optional 2FA at /totp. Upgrade or top-up at /plan.
- Model switch: LOCAL and DEEPSEEK chips in the top bar. The page confirms the switch and the reply header names the model used.
- Memory consent: /authorise, OFF by default. Turns and distilled facts stay on the box; only counts go to the house.
- Paying: pick a plan on /plan, pay by the rail shown, and we email a one-time activation code. The customer enters it at /activate and the plan (and DeepSeek, on the top-up) is live immediately - no waiting, no admin step.
- Support: /assist is a real thread with the house — the customer writes, we read it and reply in the same page; /feedback is the quick one-shot board. If someone says they are stuck, send them to /assist.
Which model runs: FREE and QWEN+ = local Qwen 3-4B on our hardware; DEEPSEEK $5 top-up with the switch ON = the DeepSeek upstream API. The reply header names the model that actually answered.
Top-ups are one-off, valid 30 days, never auto-renew.
Referral: credit the referrer 50% of the referred customer's FIRST payment only, one time, not ongoing - it is credit, never a description of our costs.
Never state internal costs, margins or cost breakdowns. Prices above are the only money you quote.
"""


MODE_SYS = {
    "coding": "CODER MODE ACTIVE. Engine room. Give the change, the exact command, the exact path, and the check that proves it worked. Code in fenced blocks with the filename on the line above. Self-check before sending: every module used is imported, no undefined names, no placeholder that will not run. No padding, no restating the request. If something is missing, name the single thing you need.",
    "reasoning": "REASONING MODE. Premise, evidence, inference, conclusion. Label each claim PROVEN / ASSERTED / OPEN. PROVEN means it follows from definitions or evidence you can name on the spot — arithmetic and stated facts are PROVEN, opinions are ASSERTED. State the strongest counter-argument and whether it stands. Finish with the decision, not a summary of the steps.",
    "chat": "CHAT MODE. Warm, short, human. A few lines and stop. No headings or bullet lists unless asked.",
}
PERM_SYS = {
    "read-only": "Workspace permission: READ-ONLY. You may read but never modify files.",
    "read-write": "Workspace permission: READ-WRITE. You may read and write files in the workspace.",
    "full": "Workspace permission: FULL ACCESS. You may run commands and modify anything in the workspace.",
}

def _is_looping(txt: str) -> bool:
    """True when the model has started repeating itself (small-model failure mode)."""
    tail = txt[-500:]
    lines = [l.strip() for l in tail.splitlines() if len(l.strip()) >= 14]
    if len(lines) >= 2 and lines[-1] == lines[-2] and len(lines[-1]) >= 25:
        return True
    if len(lines) >= 4 and lines[-2:] == lines[-4:-2]:
        return True
    sents = [x.strip() for x in re.split(r"(?<=[.!?])\s+|\n", tail) if len(x.strip()) >= 40]
    if sents and sents.count(sents[-1]) >= 2:
        return True
    return False

async def api_chat(r):
    u, key_id = auth_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    d = await r.json()
    cid = d.get("chat"); text = (d.get("message") or "").strip()
    mode = d.get("mode", "coding")
    # SELF-HOST: Sparky is the main AI; tools are on by default, not behind a click.
    perms = d.get("perms") or ("full" if SELF_HOST else "read-write")
    attach_ids = d.get("attach") or []
    if not text and not attach_ids: return web.json_response({"error": "empty message"}, status=400)
    c = db()
    own = c.execute("select 1 from chats where id=? and uid=?", (cid, u["id"])).fetchone()
    if not own:
        # fresh workspace, or a stale chat id from an older install: give this account a chat
        # of its own and carry on instead of 404-ing the user's message.
        cid = uuid.uuid4().hex
        c.execute("insert into chats(id,uid,title,created,updated,perms) values(?,?,?,?,?,?)",
                  (cid, u["id"], "chat", now(), now(), perms))
        c.commit()
        own = c.execute("select 1 from chats where id=? and uid=?", (cid, u["id"])).fetchone()
        print("[chat] self-heal -> chat", cid, "uid", u["id"], flush=True)
    if not own: c.close(); return web.json_response({"error": "not found"}, status=404)
    # per-plan daily cap: free 60, Qwen+ 1500, DeepSeek 5000 (see PLANS)
    _plan = plan_of(u)
    _cap = PLANS[_plan]["cap"] if _plan != "free" else FREE_DAY
    used = c.execute("select coalesce(sum(tok),0) from usage where uid=? and day=?", (u["id"], today())).fetchone()[0]
    if used >= _cap:
        c.close()
        return web.json_response({"error": "%s limit reached (%d calls today)" % (PLANS[_plan]["label"], _cap),
                                  "plan": _plan, "used": used, "cap": _cap,
                                  "upgrade": BASE + "/plan"}, status=429)
    # plans: free (capped), starter, pro, unlimited (no caps)
    hist = c.execute("select role,content from msgs where chat=? order by id desc limit 24", (cid,)).fetchall()
    memory_ctx = ""
    try:
        if ("remember_all" in u.keys()) and u["remember_all"]:
            rows = c.execute("select role,content from msgs where chat in (select id from chats where uid=?) and chat!=? order by id desc limit 40", (u["id"], cid)).fetchall()
            parts = []
            for rr in reversed(rows):
                txt = (rr["content"] or "").strip()
                if txt:
                    parts.append(("[you] " if rr["role"] == "user" else "[agent] ") + txt[:300])
            if parts:
                memory_ctx = ("[PERSISTENT MEMORY - earlier messages from this account's other chats, newest last. "
                              "Use it as context; never claim to have been told something that is not here.]\n" + "\n".join(parts))[:7000]
    except Exception:
        memory_ctx = ""
    # attachments: pull their extracted text into THIS turn only
    ctx_parts, names, img_ids, vid_ids = [], [], [], []
    for fid in attach_ids[:6]:
        fr = None
        try:
            fr = c.execute("select name,kind,ftext from files where id=? and uid=?", (fid, u["id"])).fetchone()
        except Exception:
            fr = None
        if not fr: continue
        names.append(fr["name"])
        ctx_parts.append(f"[ATTACHED FILE: {fr['name']} ({fr['kind']})]\n{(fr['ftext'] or '')[:4000]}\n[END FILE]")
        _ext = (fr["name"] or "").rsplit(".", 1)[-1].lower()
        if (fr["kind"] or "").lower() in ("image", "img") or _ext in ("png", "jpg", "jpeg", "webp", "gif"):
            img_ids.append(fid)
        if (fr["kind"] or "").lower() == "video" or _ext in ("mp4", "webm", "mov", "mkv", "avi", "m4v"):
            vid_ids.append(fid)
    attach_ctx = ""
    if ctx_parts:
        attach_ctx = ("[ATTACHMENT RULES] Only text extracted from the files below is available to you. "
                      "Images are OCR'd on upload: use that text, but never invent details OCR did not read (no pixels). "
                      "If asked about pixels, say plainly that you cannot see them.\n\n"
                      + "\n\n".join(ctx_parts))[:12000]
    stored = text + (("\n\n[attached: " + ", ".join(names) + "]") if names else "") \
        + "".join("\n[[img:%d]]" % i for i in img_ids) \
        + "".join("\n[[vid:%d]]" % i for i in vid_ids)
    c.execute("insert into msgs(chat,ts,role,content) values(?,?,?,?)", (cid, now(), "user", stored))
    row = c.execute("select title from chats where id=?", (cid,)).fetchone()
    if row and (not row["title"] or row["title"] in ("new chat", "chat")):
        c.execute("update chats set title=? where id=?", ((text or ", ".join(names) or "chat")[:60], cid))
    c.execute("update chats set updated=? where id=?", (now(), cid)); c.commit()
    _uk = upstream_key_for(u)          # own key if the account brought one, else house key
    _tier = (u["tier"] or "free")
    # self-host box: tools do not depend on a paid upstream key. The model is irrelevant -
    # the AGENT gets a real shell whenever the chat is FULL ACCESS and the plan allows it.
    tools_on = (bool(_uk) or SELF_HOST) and _tier in ("shell", "big") and perms in ("read-write", "full")
    tool_line = (("\n\nTOOL ACCESS: ON. Real tools on this box and a real shell. YOUR OWN CHAIN: you may not write it. Append only through /usr/local/bin/agent_chain_append.py /opt/sparky/own-chain <kind> \"<subject>\" '{}' with sudo -n; it verifies first and logs APPENDED or REFUSED. Real tools: "
                  + ("shell (bash, LIVE network), web_fetch, web_search, paddy_search (house record engine), "
                     if perms == "full" else
                     "shell/web are OFF until FULL ACCESS; file tools only: ")
                  + "list_dir, read_file, write_file. Use them instead of guessing, run them without asking, "
                  "never claim you have no network on FULL ACCESS, and report what you ran and what came back.")
                 if tools_on else
                 "\n\nTOOL ACCESS: OFF in this session. You have no shell and no filesystem. "
                 "If asked, say plainly that this session has no tool access and that FULL ACCESS turns it on.")
    _ust = upstream_state(u)
    _want = ((u["model"] if "model" in u.keys() else "auto") or "auto").strip().lower()
    upstream = bool(_ust["plan_allows"] and _ust["on"])
    if _want == "local":
        upstream = False
    elif _want == "deepseek":
        upstream = bool(_ust["plan_allows"] and (_ust["own_key"] or _ust["house_key"]))
    _mem_ok = memory_authorised(u)
    _known = _recall(u["id"], text) if _mem_ok else []
    _mem_block = ("\n\nWHAT YOU KNOW ABOUT THIS ACCOUNT (from your own memory - use it, do not claim you were told it now):\n"
                  + "\n".join("- " + k for k in _known)) if _known else ""
    _model_line = ("\n\nMODEL: you are running on DeepSeek via the upstream API, not the local model."
                   " If asked which model you are, answer DeepSeek."
                   if upstream else
                   "\n\nMODEL: you are running on the local Qwen 3-4B model on this box.")
    msgs = [{"role": "system", "content": PERSONA + PRODUCT_CTX + _model_line + "\n" +
             MODE_SYS.get(mode, MODE_SYS["coding"]) + " " + PERM_SYS.get(perms, PERM_SYS["read-write"]) + tool_line
             + (("\n\n" + memory_ctx) if memory_ctx else "")
             + _mem_block
             + (("\n\n" + master_memory()) if master_memory() else "")}]
    prev_assistant = None
    for role, content in reversed(hist):
        # a small model copies the shape of what it last said — drop verbatim repeats from history
        if role == "assistant":
            norm = (content or "").strip()
            if norm and norm == prev_assistant:
                continue
            prev_assistant = norm
        msgs.append({"role": role, "content": content})
    msgs.append({"role": "user", "content": (attach_ctx + "\n\n" + text).strip() if attach_ctx else text})
    c.close()

    resp = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache",
                                       "X-Accel-Buffering": "no"})
    await resp.prepare(r)
    loop = asyncio.get_running_loop()
    q = asyncio.Queue()
    acc = {"t": ""}
    cut = {"v": False}
    def on_delta(piece):
        if cut["v"]:
            return
        cand = acc["t"] + piece
        if _is_looping(cand):
            cut["v"] = True          # stop the stream, never show the loop
            return
        acc["t"] = cand
        loop.call_soon_threadsafe(q.put_nowait, {"delta": piece})
    def on_note(text):
        loop.call_soon_threadsafe(q.put_nowait, {"note": text})
    def on_tool(name, args_json, result):
        try:
            cc = db()
            cc.execute("insert into tool_runs(chat,ts,name,args,result) values(?,?,?,?,?)",
                       (cid, now(), name, args_json, result))
            cc.commit(); cc.close()
        except Exception:
            pass
        loop.call_soon_threadsafe(q.put_nowait, {"tool": {"name": name, "args": args_json, "result": result}})
    def on_done(): loop.call_soon_threadsafe(q.put_nowait, None)
    def on_error(err): loop.call_soon_threadsafe(q.put_nowait, {"error": err}); loop.call_soon_threadsafe(q.put_nowait, None)
    # tell the browser which model is actually answering - no guessing, no silent fallback
    q.put_nowait({"note": "model: DEEPSEEK (upstream)" if upstream else "model: QWEN (local)"})
    if tools_on:
        threading.Thread(target=lambda: _agent_run(msgs, u["id"], perms, on_delta, on_tool, on_note, on_done, on_error, up_key=_uk),
                         daemon=True).start()
    else:
        threading.Thread(target=lambda: _stream_turn(msgs, MAX_TOKENS, on_delta, on_done, on_error, upstream,
                                                    stop_when=lambda: cut["v"], on_note=on_note,
                                                    max_rounds=MAX_ROUNDS, up_key=_uk), daemon=True).start()
    while True:
        item = await q.get()
        if item is None: break
        await resp.write(f"data: {json.dumps(item)}\n\n".encode())
    await resp.write(b"data: [DONE]\n\n")
    c = db()
    c.execute("insert into msgs(chat,ts,role,content) values(?,?,?,?)", (cid, now(), "assistant", acc["t"]))
    c.commit(); c.close()
    if _mem_ok:
        _mem_append(u["id"], {"ts": now(), "chat": cid, "user": text[:600],
                              "assistant": (acc["t"] or "")[:1200],
                              "model": "deepseek" if upstream else "qwen"})
        _learn(u["id"], text)
        _report(u["id"], "deepseek" if upstream else "qwen", ok=bool(acc["t"]),
                note="" if acc["t"] else "empty reply")
    meter(u["id"], key_id, (len(acc["t"]) + len(text)) // 4)
    return resp

async def api_plugins(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    c = db()
    if r.method == "POST":
        d = await r.json()
        c.execute("insert into plugins(uid,name,desc,kind,custom,created) values(?,?,?,?,?,?)",
                  (u["id"], (d.get("name") or "plugin")[:60], (d.get("desc") or "")[:400],
                   d.get("kind") or "custom", 1 if d.get("custom") else 0, now()))
        c.commit(); c.close(); return web.json_response({"ok": True})
    rows = c.execute("select name,desc,custom from plugins where uid=? order by id desc limit 50", (u["id"],)).fetchall()
    custom = [dict(x) for x in rows]
    c.close()
    return web.json_response({"plugins": plugin_catalog(probe=True), "custom": custom})

async def api_tasks(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    c = db()
    if r.method == "POST":
        d = await r.json()
        c.execute("insert into tasks(uid,kind,spec,status,created) values(?,?,?,?,?)",
                  (u["id"], (d.get("kind") or "task")[:120], d.get("spec") or "", "queued", now()))
        c.commit(); c.close(); return web.json_response({"ok": True})
    rows = c.execute("select kind,status,created from tasks where uid=? order by id desc limit 50", (u["id"],)).fetchall()
    c.close(); return web.json_response({"tasks": [dict(x) for x in rows]})

async def api_search(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    s = (r.query.get("q") or "").strip()
    if not s: return web.json_response({"hits": []})
    c = db()
    rows = c.execute("""select ch.title, m.content from msgs m join chats ch on ch.id=m.chat
                        where ch.uid=? and m.content like ? order by m.id desc limit 20""",
                     (u["id"], f"%{s}%")).fetchall()
    c.close(); return web.json_response({"hits": [dict(x) for x in rows]})

def plan_pay_html(u=None):
    """Payment block. Called only for a signed-in user."""
    pay = ""
    instant = ""
    if u:
        conf = chain_conf()
        rails = [a for a in COIN_RAILS if rail_ready(a, conf)]
        if rails:
            links = "".join('<a class=btn style="margin:4px 8px 0 0" href="%s/checkout/new?plan=%s&asset=%s">'
                            '%s %s</a>' % (BASE, k, a, PLANS[k]["label"], a.upper())
                            for k in ("qwen6", "deepseek3") for a in rails)
            instant = ('<div style="margin:0 0 14px"><p style="color:#8892a6;font-size:13px;margin:0 0 8px">'
                   '<b style="color:var(--neo)">PAY INSTANTLY</b> - send the exact amount and the plan is '
                   'switched on by itself, no code to wait for:</p><p style="margin:0">%s</p>'
                   '<p style="color:#5d6779;font-size:11px;margin:6px 0 0">Prefer bank transfer? Use the '
                   'details below and we switch it on by hand.</p></div>' % links)
    try:
        kv = {}
        for line in PAY_ENV.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1); kv[k.strip().upper()] = v.strip()
        def row(label, val):
            return (f"<div style='display:flex;gap:12px;padding:8px 0;border-bottom:1px solid #1d2230'>"
                    f"<b style='min-width:130px;color:#8892a6;font-weight:600;font-size:12px;letter-spacing:.08em'>{label}</b>"
                    f"<span class=mono style='font-size:13px;word-break:break-all'>{val}</span></div>") if val else ""
        bits = []
        if kv.get("BANK_NAME"): bits.append(kv["BANK_NAME"])
        if kv.get("BANK_SORT"): bits.append("sort " + kv["BANK_SORT"])
        if kv.get("BANK_ACCOUNT"): bits.append("acct " + kv["BANK_ACCOUNT"])
        if kv.get("BANK_REF"): bits.append("ref " + kv["BANK_REF"])
        # a row only appears if the rail is actually configured
        pay += row("BANK TRANSFER", " · ".join(bits))
        if not instant:
            pay += row("BITCOIN (BTC)", kv.get("BTC_ADDRESS", ""))
            pay += row("ETHEREUM (ETH)", kv.get("ETH_ADDRESS", ""))
        pay += row("FEES / NOTE", kv.get("FEE_NOTE", "Network fee is on the sender. We credit after confirmations."))
        if instant:
            if kv.get("BANK_SORT") or kv.get("BANK_ACCOUNT"):
                pay = ("<p style='color:#8892a6;font-size:13px'>Bank transfer for anyone who prefers it: "
                       "send the plan amount, put your account email in the reference, and we switch it on "
                       "by hand.</p>") + pay
            else:
                pay = ""
        elif not any(k in kv for k in ("BANK_SORT", "BANK_ACCOUNT", "BTC_ADDRESS", "ETH_ADDRESS")):
            pay = "<p style='color:#f59e0b'>Payment details are being set up. Contact support to pay.</p>"
        else:
            rails = " and ".join([r for r in ("bank transfer" if bits else "",
                                              "BTC" if kv.get("BTC_ADDRESS") else "",
                                              "ETH" if kv.get("ETH_ADDRESS") else "") if r]) or "the payment method shown"
            pay = (f"<p style='color:#8892a6;font-size:13px'>Pay the plan amount by <b>{rails}</b>, "
                   f"then email the reference{' or transaction id' if kv.get('BTC_ADDRESS') or kv.get('ETH_ADDRESS') else ''} "
                   f"to support and your plan is switched on.</p>") + pay
    except Exception:
        pay = "<p style='color:#f59e0b'>Payment details are being set up. Contact support to pay.</p>"
    return instant + pay


def _new_code():
    raw = secrets.token_hex(4).upper()
    return "CHC-" + raw[:4] + "-" + raw[4:]


async def h_activate(r):
    """Customer-facing: put the code we email after payment in here."""
    u = current_user(r)
    body = """
<div class="wrap" style="max-width:560px;padding:60px 20px">
<h1 class=wordmark style="font-size:clamp(26px,6vw,52px);color:var(--neo)">ACTIVATE</h1>
<p style="color:var(--dim)">Paid? Put the one-time code from your email in here. Codes are sent <b>usually within a few hours</b> (always inside 24h) - and the moment a code is accepted the plan switches on immediately.</p>
<div class=card>
  <input id=code class=mono placeholder="CHC-XXXX-XXXX" style="width:100%;padding:14px;font-size:18px;background:#0a0d13;border:1px solid #1d2230;border-radius:8px;color:var(--ink)">
  <p id=msg style="color:var(--dim);font-size:13px;min-height:20px;margin:10px 0 0"></p>
  <button class=btn id=go style="margin-top:12px;cursor:pointer">ACTIVATE MY PLAN</button>
</div>
<p style="color:#5d6779;font-size:12px">No code yet? Pay on <a href="{B}/plan" style="color:var(--neo)">/plan</a> and email the reference to support - the code comes back to your account email.
Or skip the wait: pay in crypto at <a href="{B}/checkout" style="color:var(--neo)">/checkout</a> and the plan switches on by itself.</p>
</div>""".replace("{B}", BASE)
    return web.Response(text=page("Activate · CHC HARNESS", body,
        script="""
const m=document.querySelector('#msg'), b=document.querySelector('#go'), i=document.querySelector('#code');
b.onclick=async()=>{ m.textContent='checking...';
 try{ const r=await fetch('/api/activate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code:i.value})});
 const d=await r.json();
 if(d.ok){ m.style.color='var(--neo)'; m.innerHTML='ACTIVE — '+d.plan_label+' on <b>'+d.model+'</b>, valid until '+d.until.slice(0,10)+'. Taking you in...'; setTimeout(()=>location=d.redirect, 1100);}
 else { m.style.color='#ff5b5b'; m.textContent=d.error||'that code did not work'; } }catch(e){ m.style.color='#ff5b5b'; m.textContent='network error'; } };
""" ), content_type="text/html")


async def api_activate(r):
    u = current_user(r)
    if not u:
        return web.json_response({"error": "log in first"}, status=401)
    d = await r.json()
    code = (d.get("code") or "").strip().upper().replace(" ", "")
    if not code:
        return web.json_response({"error": "enter the code from your email"})
    c = db()
    row = c.execute("select code,plan,days,used,uid from codes where code=?", (code,)).fetchone()
    if not row:
        c.close(); return web.json_response({"error": "that code is not valid"})
    if row["used"]:
        c.close(); return web.json_response({"error": "that code has already been used"})
    if row["uid"] and int(row["uid"]) != int(u["id"]):
        c.close(); return web.json_response({"error": "that code belongs to another account"})
    plan = row["plan"] if row["plan"] in PLANS else "qwen6"
    days = int(row["days"] or 30)
    until = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    up = 1 if plan == "deepseek3" else (1 if u["upstream_on"] else 0)
    c.execute("update users set plan=?, tier=?, paid_until=?, upstream_on=? where id=?",
              (plan, PLANS[plan]["tier"], until, up, u["id"]))
    c.execute("update codes set used=1, uid=? where code=?", (u["id"], code))
    c.commit(); c.close()
    redirect = BASE + ("/app?model=deepseek&switched=deepseek" if plan == "deepseek3"
                       else "/app?model=local&switched=local")
    return web.json_response({"ok": True, "plan": plan, "plan_label": PLANS[plan]["label"],
                              "model": "DEEPSEEK (upstream)" if plan == "deepseek3" else "QWEN 3-4B (local)",
                              "until": until, "redirect": redirect})


async def admin_codes(r):
    """House only: mint activation codes. POST {plan, n}; header or query token = admin token."""
    tok = (r.query.get("token") or r.headers.get("x-admin-token") or "")
    want = ADMIN_TOKEN
    if not want:
        try: want = ADMIN_TOKEN_FILE.read_text().strip()
        except Exception: want = ""
    if not want or tok != want:
        return web.json_response({"error": "forbidden"}, status=403)
    d = await r.json()
    plan = (d.get("plan") or "deepseek3").strip()
    if plan not in ("qwen6", "deepseek3"):
        return web.json_response({"error": "plan must be qwen6 or deepseek3"})
    n = max(1, min(50, int(d.get("n") or 1)))
    days = int(d.get("days") or 30)
    out = []
    c = db()
    for _ in range(n):
        code = _new_code()
        c.execute("insert or ignore into codes(code,plan,days,used,uid,created) values(?,?,?,0,0,?)",
                  (code, plan, days, now()))
        out.append(code)
    c.commit(); c.close()
    return web.json_response({"ok": True, "plan": plan, "days": days, "codes": out})



# ---------------------------------------------- self-serve billing / checkout (v3.6.0)
# One invoice -> one exact amount -> a public chain API confirms it -> the plan is credited.
# No human in the loop, no card processor. The customer's page polls /api/invoice/<ref>.
CHAINAPI_ENV = pathlib.Path(getattr(CLI, "chainapi", "") or "/opt/chc-ai/chainapi.env")
BILLING_LOG = pathlib.Path(getattr(CLI, "billing_log", "") or "/opt/chc-ai/billing.log")
CHECK_EVERY = 20          # seconds between chain look-ups for one invoice
COIN_RAILS = ("btc", "eth", "usdc", "usdt")
# ERC-20 stablecoins that live on the SAME ethereum address as our ETH rail.
TOKEN_CONTRACTS = {
    "usdc": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "usdt": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
}
TOKEN_DECIMALS = {"usdc": 6, "usdt": 6}
PEG_USD = {"usdc": 1.0, "usdt": 1.0}          # stablecoins: one token, one dollar
PXCACHE = {}                                   # asset -> (usd, fetched_at)


def spot_usd(asset):
    """Live spot price, cached 60s. Coinbase first, BlockCypher as a fallback."""
    pair = asset.upper() + "-USD"
    hit = PXCACHE.get(asset)
    if hit and (time.time() - hit[1]) < 60:
        return hit[0]
    for url, pick in (
        ("https://api.coinbase.com/v2/prices/%s/spot" % pair,
         lambda d: float(d["data"]["amount"])),
        ("https://api.blockchain.info/ticker", None),
    ):
        try:
            if pick is None:
                continue
            px = pick(_get_json(url))
            if px > 0:
                PXCACHE[asset] = (px, time.time())
                return px
        except Exception:
            continue
    return 0.0


def chain_conf():
    kv = {}
    try:
        for line in CHAINAPI_ENV.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip().upper()] = v.strip()
    except Exception:
        pass
    return kv


def billing_note(msg):
    """Every money event goes to a plain log the house can read and seal."""
    line = "%s %s" % (now(), msg)
    try:
        with BILLING_LOG.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print("[billing] " + msg, flush=True)


def admin_token_ok(r):
    tok = (r.query.get("token") or r.headers.get("x-admin-token") or "")
    want = ADMIN_TOKEN
    if not want:
        try:
            want = ADMIN_TOKEN_FILE.read_text().strip()
        except Exception:
            want = ""
    return bool(want) and tok == want


def asset_px(conf, asset):
    want = asset.upper() + "_USD"
    try:
        cfg = float(conf.get(want) or 0)
    except Exception:
        cfg = 0.0
    if cfg > 0:
        return cfg
    if asset in PEG_USD:
        return PEG_USD[asset]
    try:
        return spot_usd(asset)
    except Exception:
        return 0.0


def asset_addr(conf, asset):
    if asset in TOKEN_CONTRACTS:
        return (conf.get("ETH_ADDRESS") or "").strip()
    return (conf.get(asset.upper() + "_ADDRESS") or "").strip()


def token_contract(conf, asset):
    return (conf.get(asset.upper() + "_CONTRACT") or TOKEN_CONTRACTS.get(asset, "")).strip()


def rail_ready(asset, conf=None):
    conf = conf if conf is not None else chain_conf()
    return bool(asset_addr(conf, asset)) and asset_px(conf, asset) > 0


def quote_amount(plan, asset, seq, conf):
    """Unique exact amount per invoice. Returns (units:int, text:str) or (None, None).
    units are satoshis for btc and wei for eth; the tail of low digits makes each invoice
    unique so a payment can be matched to exactly one customer."""
    usd = float(PLANS[plan]["price_usd"])
    px = asset_px(conf, asset)
    if px <= 0 or not asset_addr(conf, asset):
        return None, None
    if asset == "btc":
        units = int(usd / px * 100000000) + (int(seq) % 500)
        return units, "%.8f" % (units / 100000000.0)
    if asset in TOKEN_DECIMALS:
        dec = TOKEN_DECIMALS[asset]
        units = int(usd / px * (10 ** dec)) + (int(seq) % 900)
        return units, ("%.*f" % (dec, units / float(10 ** dec)))
    step = 1000000000                       # 1 gwei = 1e-9 ETH
    base = int(usd / px * 1e18)
    units = base - (base % step) + (int(seq) % 900) * step
    return units, ("%.18f" % (units / 1e18)).rstrip("0").rstrip(".")


def _get_json(url, headers=None, timeout=20):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "chc-harness-billing/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "null")


def btc_seen(conf, addr, units):
    """Exact-amount output to our address, confirmed or still in the mempool."""
    api = (conf.get("BTC_API") or "https://mempool.space/api").rstrip("/")
    txs = _get_json("%s/address/%s/txs" % (api, urllib.parse.quote(addr)))
    for tx in (txs or []):
        for out in (tx.get("vout") or []):
            if out.get("scriptpubkey_address") != addr:
                continue
            if int(out.get("value") or 0) != int(units):
                continue
            st = tx.get("status") or {}
            return {"txid": tx.get("txid", ""), "confirmed": bool(st.get("confirmed")),
                    "height": st.get("block_height") or 0}
    return None


def eth_seen(conf, addr, units):
    """Exact-value transfer to our address. Blockscout by default, BlockCypher if asked."""
    prov = (conf.get("ETH_PROVIDER") or "blockscout").lower()
    want = int(units)
    a = addr.lower()
    if prov == "blockcypher":
        base = (conf.get("ETH_API") or "https://api.blockcypher.com/v1/eth/main/addrs").rstrip("/")
        d = _get_json("%s/%s?limit=25" % (base, urllib.parse.quote(addr)))
        for tx in ((d or {}).get("txs") or []):
            for out in (tx.get("outputs") or []):
                if a not in [str(x).lower() for x in (out.get("addresses") or [])]:
                    continue
                if int(out.get("value") or 0) != want:
                    continue
                return {"txid": tx.get("hash", ""), "confirmed": int(tx.get("confirmations") or 0) >= 1,
                        "height": 0}
        return None
    base = (conf.get("ETH_API") or "https://eth.blockscout.com/api/v2/addresses").rstrip("/")
    d = _get_json("%s/%s/transactions" % (base, urllib.parse.quote(addr)))
    for tx in ((d or {}).get("items") or []):
        to = ((tx.get("to") or {}).get("hash") or "").lower()
        if to != a:
            continue
        if int(tx.get("value") or 0) != want:
            continue
        if (tx.get("status") or "ok") != "ok":
            continue
        return {"txid": tx.get("hash", ""), "confirmed": True, "height": tx.get("block") or 0}
    return None


def eth_token_seen(conf, addr, units, asset):
    """ERC-20 transfer of the exact amount to our address (Blockscout token-transfers)."""
    base = (conf.get("ETH_API") or "https://eth.blockscout.com/api/v2/addresses").rstrip("/")
    contract = token_contract(conf, asset).lower()
    a = addr.lower()
    d = _get_json("%s/%s/token-transfers?token=%s" % (base, urllib.parse.quote(addr), contract))
    for it in ((d or {}).get("items") or []):
        tot = it.get("total") or {}
        val = tot.get("value")
        if val is None:
            val = it.get("value")
        if int(val or 0) != int(units):
            continue
        to = ((it.get("to") or {}).get("hash") or "").lower()
        if to != a:
            continue
        tok = ((it.get("token") or {}).get("address_hash") or it.get("token_address") or "").lower()
        if contract and tok and tok != contract:
            continue
        return {"txid": it.get("transaction_hash") or (it.get("transaction") or {}).get("hash") or "",
                "confirmed": True, "height": 0}
    return None


def credit_invoice(ref, txid, asset, units, source="chain"):
    """Idempotent: pay once, credit once. Stacks on any time already paid for."""
    c = db()
    inv = c.execute("select * from invoices where ref=?", (ref,)).fetchone()
    if not inv:
        c.close()
        return {"ok": False, "error": "no such invoice"}
    if inv["status"] == "paid":
        c.close()
        return {"ok": True, "already": True}
    plan = inv["plan"] if inv["plan"] in PLANS else "qwen6"
    if plan == "free":
        c.close()
        return {"ok": False, "error": "free plan needs no payment"}
    days = int(PLANS[plan]["days"] or 30)
    u = c.execute("select id,email,handle,paid_until,upstream_on from users where id=?",
                  (inv["uid"],)).fetchone()
    if not u:
        c.close()
        return {"ok": False, "error": "account is gone"}
    start = datetime.datetime.now(datetime.timezone.utc)
    try:
        pu = datetime.datetime.strptime(str(u["paid_until"] or ""),
                                        "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        if pu > start:
            start = pu
    except Exception:
        pass
    until = (start + datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    code = _new_code()
    up = 1 if plan == "deepseek3" else int(u["upstream_on"] or 0)
    c.execute("insert or ignore into codes(code,plan,days,used,uid,created) values(?,?,?,1,?,?)",
              (code, plan, days, int(u["id"]), now()))
    c.execute("update users set plan=?, tier=?, paid_until=?, upstream_on=? where id=?",
              (plan, PLANS[plan]["tier"], until, up, int(u["id"])))
    c.execute("update invoices set status='paid', paid_at=?, txid=?, code=?, units=? where ref=?",
              (now(), txid or "", code, int(units or 0), ref))
    c.commit()
    c.close()
    site = (CLI.public_url or "https://ai.94-237-56-140.sslip.io").rstrip("/")
    subj = "PAID - %s active until %s" % (PLANS[plan]["label"], until[:10])
    body = ("Your payment is in and the plan is already on your account.\n\n"
            "Plan: %s\nValid until: %s\nReference: %s\nCode on record: %s\n\n"
            "Nothing to type in: open %s/app and you are on the paid plan.\n"
            "Nothing renews automatically.\n\n- BAFOUNE-NET"
            % (PLANS[plan]["label"], until, ref, code, site))
    to = (u["email"] or "").strip()
    if to and not mail_api_send(to, subj, body):
        queue_mail(to, subj, body)
    billing_note("CREDIT ref=%s uid=%s plan=%s until=%s asset=%s units=%s txid=%s via=%s code=%s"
                 % (ref, u["id"], plan, until, asset, units, txid, source, code))
    return {"ok": True, "plan": plan, "until": until, "label": PLANS[plan]["label"], "code": code}


def invoice_new(uid, plan, asset):
    conf = chain_conf()
    if plan not in PLANS or plan == "free":
        return None, "pick a paid plan"
    if asset not in COIN_RAILS:
        return None, "asset must be btc or eth"
    if not rail_ready(asset, conf):
        return None, "that payment rail is not configured yet"
    c = db()
    seq = int(c.execute("select count(*) n from invoices").fetchone()["n"]) + 1
    ref = "CHC%d%s" % (seq, secrets.token_hex(3).upper())
    units, text = quote_amount(plan, asset, seq, conf)
    if units is None:
        c.close()
        return None, "that payment rail is not configured yet"
    c.execute("insert into invoices(ref,uid,plan,asset,units,quote,address,status,created,last_check)"
              " values(?,?,?,?,?,?,?, 'open', ?, 0)",
              (ref, int(uid), plan, asset, int(units), text, asset_addr(conf, asset), now()))
    c.commit()
    c.close()
    billing_note("INVOICE ref=%s uid=%s plan=%s asset=%s amount=%s" % (ref, uid, plan, asset, text))
    return ref, None


def invoice_check(inv, force=False):
    """Read-only status plus (on a match) the credit. Never raises into the request."""
    d = dict(inv)
    res = {"ref": d["ref"], "status": d["status"], "plan": d["plan"], "asset": d["asset"],
           "quote": d["quote"], "address": d["address"], "created": d["created"],
           "paid": d["status"] == "paid", "label": PLANS.get(d["plan"], PLANS["free"])["label"]}
    if res["paid"]:
        res["code"] = d.get("code") or ""
        res["txid"] = d.get("txid") or ""
        res["until"] = d.get("paid_at") or ""
        return res
    ts = int(time.time())
    if not force and ts - int(d.get("last_check") or 0) < CHECK_EVERY:
        return res
    c = db()
    c.execute("update invoices set last_check=? where ref=?", (ts, d["ref"]))
    c.commit()
    c.close()
    conf = chain_conf()
    try:
        if d["asset"] == "btc":
            found = btc_seen(conf, d["address"], int(d["units"]))
        elif d["asset"] in TOKEN_CONTRACTS:
            found = eth_token_seen(conf, d["address"], int(d["units"]), d["asset"])
        else:
            found = eth_seen(conf, d["address"], int(d["units"]))
    except Exception as e:
        billing_note("CHAIN-ERR ref=%s %s %s" % (d["ref"], type(e).__name__, str(e)[:120]))
        res["error"] = "chain lookup unavailable - we keep trying"
        return res
    if not found:
        return res
    credit_invoice(d["ref"], found.get("txid", ""), d["asset"], d["units"], "chain")
    c = db()
    row = c.execute("select * from invoices where ref=?", (d["ref"],)).fetchone()
    c.close()
    if not row:
        return res
    return invoice_check(row)


def _checkout_css():
    return ("<style>.payrow{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:6px 0}"
            ".payamt{font-size:clamp(22px,4vw,34px);color:var(--neo);letter-spacing:.02em}"
            ".payaddr{font-size:12px;color:#8892a6;word-break:break-all}</style>")


async def h_checkout_pick(r):
    u = current_user(r)
    if not u:
        return web.HTTPFound(BASE + "/login")
    conf = chain_conf()
    rails = [a for a in COIN_RAILS if rail_ready(a, conf)]
    err = (r.query.get("err") or "").strip()
    cards = []
    for key in ("qwen6", "deepseek3"):
        pl = PLANS[key]
        links = "".join('<a class=btn style="margin:6px 8px 0 0" href="%s/checkout/new?plan=%s&asset=%s">'
                        'PAY %s %s</a>' % (BASE, key, a, pl["price"], a.upper()) for a in rails)
        if not links:
            links = ('<p style="color:#f59e0b;font-size:13px;margin:8px 0 0">No self-serve rail is set up'
                     ' yet - pay by bank on <a href="%s/plan" style="color:var(--neo)">/plan</a> and the'
                     ' plan is switched on by hand.</p>' % BASE)
        cards.append('<div class=card style="margin:14px 0"><h3 style="margin-top:0;color:var(--neo)">%s '
                     '<span style="font-size:22px">%s</span> <span style="color:var(--dim);font-size:14px">%s'
                     '</span></h3><p style="color:var(--dim);margin:6px 0"><b>%s</b></p>'
                     '<p style="color:var(--dim);margin:6px 0">%s</p>%s</div>'
                     % (pl["label"], pl["price"], pl["period"], pl["calls"], pl["model"], links))
    nudge = ('<p style="color:#ff5b5b;font-size:13px">%s</p>' % err.replace("<", "&lt;")) if err else ""
    body = ('%s<div class="wrap" style="max-width:760px;padding:56px 20px">'
            '<h1 class=wordmark style="font-size:clamp(28px,6vw,56px);color:var(--neo)">CHECKOUT</h1>'
            '<p style="color:var(--dim)">Pick a plan and a coin. You get one exact amount to send; the '
            'moment it lands the plan switches on and we email you. Nothing renews, no card kept.</p>'
            '%s%s<p style="color:#5d6779;font-size:12px">Bank transfer details are on '
            '<a href="%s/plan" style="color:var(--neo)">/plan</a>.</p></div>'
            % (_checkout_css(), nudge, "".join(cards), BASE))
    return web.Response(text=page("Checkout - CHC HARNESS", body, path="/checkout"),
                        content_type="text/html")


async def h_checkout_new(r):
    u = current_user(r)
    if not u:
        return web.HTTPFound(BASE + "/login")
    plan = (r.query.get("plan") or "qwen6").strip().lower()
    asset = (r.query.get("asset") or "btc").strip().lower()
    ref, err = invoice_new(u["id"], plan, asset)
    if err:
        return web.HTTPFound(BASE + "/checkout?err=" + urllib.parse.quote(err))
    return web.HTTPFound(BASE + "/checkout/" + ref)


async def h_invoice_page(r):
    u = current_user(r)
    ref = (r.match_info.get("ref") or "").strip().upper()
    c = db()
    inv = c.execute("select * from invoices where ref=?", (ref,)).fetchone()
    c.close()
    if not inv:
        raise web.HTTPNotFound()
    if not admin_token_ok(r) and (not u or int(u["id"]) != int(inv["uid"])):
        raise web.HTTPNotFound()
    d = dict(inv)
    pl = PLANS.get(d["plan"], PLANS["free"])
    uri = ("bitcoin:%s?amount=%s" % (d["address"], d["quote"])) if d["asset"] == "btc" else ""
    rail_note = ("an ERC-20 transfer on Ethereum to this same address"
                 if d["asset"] in TOKEN_CONTRACTS else "an on-chain transfer to this address")
    uri_html = ('<p style="margin:10px 0 0"><a class=btn ghost href="%s">OPEN WALLET</a></p>' % uri) if uri else ""
    if d["status"] == "paid":
        inner = ('<h2 style="color:var(--neo);margin:0 0 8px">PAID - %s IS ON</h2>'
                 '<p style="color:var(--dim)">Valid until <b>%s</b>. Nothing to type in.</p>'
                 '<p style="margin:14px 0 0"><a class=btn href="%s/app">OPEN MY WORKSPACE</a></p>'
                 % (pl["label"], (d.get("paid_at") or "")[:10], BASE))
    else:
        inner = ('<p style="color:var(--dim);margin:0 0 4px">Send <b>exactly</b> this amount, once:</p>'
                 '<div class=payrow><span class="mono payamt">%s %s</span>'
                 '<button class="btn ghost" id=copy style="cursor:pointer">COPY</button></div>'
                 '<p style="color:var(--dim);margin:18px 0 4px">To this address (%s) - %s:</p>'
                 '<div class="mono payaddr" id=addr>%s</div>%s'
                 '<p id=st style="color:#8892a6;font-size:13px;margin:16px 0 0">waiting for the payment...</p>'
                 '<p style="color:#5d6779;font-size:12px">The exact amount is a tag - it is how we know the'
                 ' payment is yours. Send a different amount and it needs a human, so keep it exact.'
                 ' Leave this page open; it updates by itself.</p>'
                 % (d["quote"], d["asset"].upper(), d["asset"].upper(), rail_note, d["address"], uri_html))
    body = ('%s<div class="wrap" style="max-width:640px;padding:56px 20px">'
            '<h1 class=wordmark style="font-size:clamp(26px,5vw,46px);color:var(--neo)">%s</h1>'
            '<div class=card>%s</div>'
            '<p style="color:#5d6779;font-size:11px;margin-top:14px">Reference %s - keep it: support can'
            ' find your payment with it.</p></div>' % (_checkout_css(), ref, inner, ref))
    script = "" if d["status"] == "paid" else """
const st=document.querySelector('#st'), ref=%r, base=%r;
document.querySelector('#copy').onclick=()=>{navigator.clipboard.writeText(document.querySelector('.payamt').textContent.split(' ')[0]);};
async function tick(){ try{ const r=await fetch(base+'/api/invoice/'+ref,{cache:'no-store'}); const d=await r.json();
 if(d.paid){ st.style.color='var(--neo)'; st.textContent='paid - switching your plan on...'; setTimeout(()=>location=base+'/app',1200); return; }
 if(d.error){ st.textContent=d.error; } else { st.textContent='waiting for the payment... (checked again in a moment)'; }
 }catch(e){ st.textContent='waiting for the payment...'; } }
setInterval(tick, 12000);
""" % (ref, BASE)
    return web.Response(text=page("Pay %s - CHC HARNESS" % ref, body, script=script, path="/checkout/" + ref),
                        content_type="text/html")


async def api_invoice(r):
    ref = (r.match_info.get("ref") or "").strip().upper()
    c = db()
    inv = c.execute("select * from invoices where ref=?", (ref,)).fetchone()
    c.close()
    if not inv:
        return web.json_response({"error": "no such invoice"}, status=404)
    admin = admin_token_ok(r)
    u = current_user(r)
    if not admin and (not u or int(u["id"]) != int(inv["uid"])):
        return web.json_response({"error": "auth"}, status=401)
    force = admin and bool(r.query.get("force"))
    return web.json_response(invoice_check(inv, force=force))


async def admin_invoices(r):
    if not admin_token_ok(r):
        return web.json_response({"error": "forbidden"}, status=403)
    c = db()
    rows = c.execute("select ref,uid,plan,asset,quote,address,status,created,paid_at,txid,code"
                     " from invoices order by created desc limit 100").fetchall()
    c.close()
    return web.json_response({"invoices": [dict(x) for x in rows]})


async def admin_invoice_mark(r):
    """Bank rail and rescue: mark an invoice paid by hand. Admin token only."""
    if not admin_token_ok(r):
        return web.json_response({"error": "forbidden"}, status=403)
    d = await r.json()
    ref = (d.get("ref") or "").strip().upper()
    if not ref:
        return web.json_response({"error": "ref required"})
    return web.json_response(credit_invoice(ref, (d.get("txid") or "manual"), "manual", 0, "admin"))


ASSIST_CSS = """
.amsg{border:1px solid #1d2230;border-radius:10px;padding:10px 12px;margin:8px 0;max-width:80%;white-space:pre-wrap}
.amsg.house{border-color:var(--neo);margin-left:auto;background:rgba(57,255,158,.06)}
.amsg .who{font-size:11px;color:#5d6779;letter-spacing:.08em;margin-bottom:4px}
.athread{border:1px solid #1d2230;border-radius:10px;padding:10px 12px;margin:8px 0;cursor:pointer}
.athread:hover{border-color:var(--neo)}
"""

ASSIST_RATE = {}          # key -> [timestamps]
ASSIST_RATE_PER_MIN = 6   # a human types faster than this only if they are a script
ASSIST_MAX_THREADS = 10

def _assist_rate_ok(key):
    import time as _t
    now = _t.time()
    bucket = [x for x in ASSIST_RATE.get(key, []) if now - x < 60]
    if len(bucket) >= ASSIST_RATE_PER_MIN:
        ASSIST_RATE[key] = bucket
        return False
    bucket.append(now)
    ASSIST_RATE[key] = bucket[-ASSIST_RATE_PER_MIN * 2:]
    if len(ASSIST_RATE) > 5000:          # keep the dict from growing forever
        for k in list(ASSIST_RATE)[:1000]: ASSIST_RATE.pop(k, None)
    return True


def _assist_threads(uid=None, all_threads=False):
    c = db()
    if all_threads:
        rows = c.execute("select id,uid,email,subject,created,updated,status from assist_threads order by updated desc limit 100").fetchall()
    else:
        rows = c.execute("select id,uid,email,subject,created,updated,status from assist_threads where uid=? order by updated desc limit 50", (uid,)).fetchall()
    c.close(); return rows

def _assist_msgs(tid):
    c = db(); rows = c.execute("select role,body,created from assist_msgs where thread=? order by id", (tid,)).fetchall(); c.close()
    return rows

def _assist_add(tid, uid, role, body):
    c = db(); c.execute("insert into assist_msgs(thread,uid,role,body,created) values(?,?,?,?,?)",
                        (tid, uid, role, body[:4000], now()))
    c.execute("update assist_threads set updated=? where id=?", (now(), tid)); c.commit(); c.close()


async def h_assist(r):
    u = current_user(r)
    if not u: return web.HTTPFound(BASE + "/login")
    rows = _assist_threads(u["id"])
    items = "".join(
        "<div class=athread onclick=\"location='%s/assist?t=%d'\"><b>%s</b> "
        "<span style='color:#5d6779;font-size:12px'>· %s · %d msgs · %s</span></div>"
        % (BASE, t["id"], (t["subject"] or "help")[:70],
           t["updated"][:16].replace("T", " "),
           len(_assist_msgs(t["id"])), t["status"]) for t in rows)
    tid = int(r.query.get("t") or 0)
    thread_html = ""
    if tid:
        t = None
        for x in rows:
            if int(x["id"]) == tid: t = x
        if not t: return web.HTTPFound(BASE + "/assist")
        msgs = "".join(
            "<div class='amsg %s'><div class=who>%s · %s</div>%s</div>"
            % ("house" if m["role"] == "house" else "", "CHC SUPPORT" if m["role"] == "house" else "YOU",
               m["created"][:16].replace("T", " "), (m["body"] or "").replace("<", "&lt;"))
            for m in _assist_msgs(tid))
        thread_html = f"""
<div class=card>
  <h3 style="margin-top:0;color:var(--neo)>{t["subject"]}</h3>
  <div id=msgs style="max-height:46vh;overflow:auto;padding:4px 0">{msgs or "<p style='color:#5d6779'>No messages yet — say hi.</p>"}</div>
  <textarea id=body rows=3 placeholder="Type your message…" style="width:100%;padding:10px;background:#0a0d13;border:1px solid #1d2230;border-radius:8px;color:var(--ink);margin-top:8px"></textarea>
  <button class=btn id=send style="cursor:pointer;margin-top:8px">SEND</button>
  <p id=hint style="color:#5d6779;font-size:12px;min-height:16px"></p>
</div>"""
    return web.Response(text=page("Help · CHC HARNESS", f"""
<div class="wrap" style="max-width:760px;padding:48px 20px">
<h1 class=wordmark style="font-size:clamp(26px,6vw,52px);color:var(--neo)">HELP &amp; ASSIST</h1>
<p style="color:var(--dim)">Talk to the house. We read every thread and reply here — no ticket numbers, no bots pretending to be humans.</p>
<div class=card>
  <h3 style="margin-top:0">START A THREAD</h3>
  <input id=subj placeholder="What do you need help with?" style="width:100%;padding:10px;background:#0a0d13;border:1px solid #1d2230;border-radius:8px;color:var(--ink)">
  <button class=btn id=newt style="cursor:pointer;margin-top:8px">START</button>
  <p id=nh style="color:#5d6779;font-size:12px;min-height:16px"></p>
</div>
<h3 style="color:var(--dim);letter-spacing:.1em;margin-top:26px">YOUR THREADS</h3>
{items or "<p style='color:#5d6779'>None yet.</p>"}
{thread_html}
<p style="margin-top:18px"><a class=btn href="{BASE}/app">BACK TO WORKSPACE</a>
<a class="btn ghost" href="{BASE}/feedback">QUICK FEEDBACK</a></p>
</div>""", css=ASSIST_CSS, script=f"""
const BASE='{BASE}'; const TID={tid};
document.querySelector('#newt')?.addEventListener('click',async()=>{{
  const s=document.querySelector('#subj').value.trim(); if(!s) return;
  const r=await fetch(BASE+'/api/assist',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{action:'new',subject:s}})}});
  const d=await r.json(); if(d.id) location=BASE+'/assist?t='+d.id; else document.querySelector('#nh').textContent=d.error||'failed';
}});
const send=document.querySelector('#send');
if(send) send.onclick=async()=>{{
  const b=document.querySelector('#body'), h=document.querySelector('#hint');
  const text=b.value.trim(); if(!text) return; h.textContent='sending…';
  const r=await fetch(BASE+'/api/assist',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{action:'say',thread:TID,body:text}})}});
  const d=await r.json();
  if(d.ok){{ b.value=''; h.textContent='sent'; setTimeout(()=>location.reload(),400); }} else h.textContent=d.error||'failed';
}};
if(TID) setInterval(async()=>{{
  const r=await fetch(BASE+'/api/assist?thread='+TID); if(!r.ok) return;
  const d=await r.json(); const box=document.querySelector('#msgs'); if(!box||!d.msgs) return;
  if(d.msgs.length !== box.children.length) location.reload();
}},8000);
"""), content_type="text/html")


async def api_assist(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    if r.method == "GET":
        tid = int(r.query.get("thread") or 0)
        if not tid: return web.json_response({"threads": [dict(t) for t in _assist_threads(u["id"])]})
        c = db(); own = c.execute("select id from assist_threads where id=? and uid=?", (tid, u["id"])).fetchone(); c.close()
        if not own: return web.json_response({"error": "not yours"}, status=403)
        return web.json_response({"msgs": [dict(m) for m in _assist_msgs(tid)]})
    d = await r.json(); act = (d.get("action") or "").strip()
    ip = (r.remote or "?", 0)[0] if isinstance(r.remote, tuple) else (r.remote or "?")
    if not _assist_rate_ok("uid:%s" % u["id"]) or not _assist_rate_ok("ip:%s" % ip):
        return web.json_response({"error": "slow down a moment — too many messages"}, status=429)
    if act == "new":
        c = db(); n = c.execute("select count(*) as x from assist_threads where uid=?", (u["id"],)).fetchone()["x"]; c.close()
        if n >= ASSIST_MAX_THREADS:
            return web.json_response({"error": "you already have %d open threads — reply in one of those" % n}, status=429)
        subj = (d.get("subject") or "help")[:120]
        c = db(); c.execute("insert into assist_threads(uid,email,subject,created,updated,status) values(?,?,?,?,?,'open')",
                            (u["id"], u["email"], subj, now(), now()))
        tid = c.execute("select last_insert_rowid() as x").fetchone()["x"]; c.commit(); c.close()
        _assist_add(tid, u["id"], "user", subj)
        return web.json_response({"ok": True, "id": tid})
    if act == "say":
        tid = int(d.get("thread") or 0); body = (d.get("body") or "").strip()
        if not body: return web.json_response({"error": "empty"})
        c = db(); own = c.execute("select id from assist_threads where id=? and uid=?", (tid, u["id"])).fetchone(); c.close()
        if not own: return web.json_response({"error": "not yours"}, status=403)
        _assist_add(tid, u["id"], "user", body)
        return web.json_response({"ok": True})
    return web.json_response({"error": "unknown action"})


async def h_admin_assist(r):
    tok = (r.query.get("token") or r.headers.get("x-admin-token") or "")
    want = ADMIN_TOKEN
    if not want:
        try: want = ADMIN_TOKEN_FILE.read_text().strip()
        except Exception: want = ""
    if not want or tok != want:
        return web.json_response({"error": "forbidden"}, status=403)
    if r.method == "POST":
        d = await r.json(); tid = int(d.get("thread") or 0); body = (d.get("body") or "").strip()
        if not (tid and body): return web.json_response({"error": "thread and body required"})
        _assist_add(tid, 0, "house", body)
        return web.json_response({"ok": True})
    tid = int(r.query.get("thread") or 0)
    if tid:
        rows = _assist_msgs(tid)
        return web.json_response({"thread": tid, "msgs": [dict(m) for m in rows]})
    c = db(); rows = c.execute("select id,uid,email,subject,created,updated,status from assist_threads order by updated desc limit 100").fetchall(); c.close()
    return web.json_response({"threads": [dict(t) for t in rows]})



PUBLIC_PAGES = [
    ("/", "CHC HARNESS — AI that answers to you", "Your own AI workspace. 60 free calls a day, no card."),
    ("/free", "Free AI workspace — 60 calls a day, no card", "Free AI with files: 60 calls a day, 1 GB private workspace, email sign-up only."),
    ("/self-host", "Self-host your AI — full access to your own machine", "Download CHC HARNESS and run it on your own hardware with full access, no call cap."),
    ("/compare", "CHC HARNESS vs chatbot subscriptions", "A workspace with files and tools versus a chat box: an honest comparison."),
    ("/security", "SEE 7.7.8 · S33", "What is encrypted, what is not, and how to verify it."),
    ("/plan", "Plans and prices", "Free 60 calls a day. QWEN+ $5 a month. DeepSeek $5 one-off top-up. Self-host free."),
    ("/get", "Download and install", "Linux, macOS, Windows, Android. One command to self-host."),
    ("/signup", "Create your account", "Email only, no card. Account live in under a minute."),
    ("/assist", "Help and assist", "Talk to the house in a real thread."),
    ("/blog", "Notes", "Plain writing about AI workspaces, self-hosting and honest free tiers."),
    ("/blog/free-ai-no-credit-card", "Free AI with no credit card", "60 calls a day, email only."),
    ("/blog/self-host-ai-workspace", "Self-hosting an AI workspace", "What you actually need."),
    ("/blog/ai-workspace-with-files", "Why files matter more than model size", "A workspace, not a chat box."),
    ("/blog/chc-harness-on-github", "CHC HARNESS on GitHub — with the receipts", "Source public, licence restrictive."),
]



VERIFY_HTML_DIR = pathlib.Path(os.environ.get("CHC_VERIFY_DIR", "/data/verify"))


async def h_google_verify_file(r):
    name = (r.match_info.get("name") or "").strip()
    if not name.startswith("google") or not name.endswith(".html"):
        return web.Response(status=404)
    body = "google-site-verification: %s" % name
    return web.Response(text=body, content_type="text/html")


async def h_verify_put(r):
    """House only: drop a verification file by name (admin token). POST {name}"""
    tok = (r.query.get("token") or r.headers.get("x-admin-token") or "")
    want = ADMIN_TOKEN
    if not want:
        try: want = ADMIN_TOKEN_FILE.read_text().strip()
        except Exception: want = ""
    if not want or tok != want:
        return web.json_response({"error": "forbidden"}, status=403)
    d = await r.json(); name = (d.get("name") or "").strip()
    if not (name.startswith("google") and name.endswith(".html")):
        return web.json_response({"error": "name must be google<token>.html"})
    try:
        VERIFY_HTML_DIR.mkdir(parents=True, exist_ok=True)
        (VERIFY_HTML_DIR / name).write_text("google-site-verification: %s" % name)
    except Exception as e:
        return web.json_response({"ok": True, "note": "served dynamically; dir write skipped: %s" % e})
    return web.json_response({"ok": True, "url": SITE + "/" + name})



POSTS = {
 "chc-harness-on-github": ("We put CHC HARNESS on GitHub — with the receipts", "2026-11-10",
   "The full source is public: one file, its own Ed25519 receipt chain. Read it, run it unmodified — it stays ours.",
   """<p>As of today the whole thing is public: <a href="https://github.com/CHCDOLADEEPSEEKMKSEC/chc-harness">github.com/CHCDOLADEEPSEEKMKSEC/chc-harness</a>. One repo, seventeen files, the same build that runs this site.</p>
<p>We did it for one reason: a claim you cannot inspect is a claim you have to take on faith. "Your records are signed and verifiable" means nothing if you cannot see the code that signs them. Now you can — including the receipt tooling.</p>
<h3>What is in there</h3>
<ul><li><b>app.py</b> — the whole application: chat, workspace, files, tools, shell sandbox, signup, billing, admin.</li>
<li><b>tools/seal.py</b> — the append-only receipt chain. Pure-Python Ed25519, no dependencies. It signs each entry and pins the previous one's hash, so editing history breaks the chain instead of hiding in it.</li>
<li><b>tools/init_vault.py</b> — creates your own vault: your key, your chain, your files. Nothing of ours comes with it.</li>
<li><b>install.sh, Dockerfile, docker-compose.yml</b> — one command, or a container, or neither.</li></ul>
<h3>What is not in there</h3>
<p>No telemetry, no analytics, no phone-home, no obfuscated blob, no "pro" module holding the real features. If it runs here, it runs there. What is missing is the boring part of a business: licences, support contracts, a card rail, an audit. Those are not code.</p>
<h3>The licence is deliberately not open source</h3>
<p>Read it, clone it, run an <b>unmodified</b> copy for your own non-commercial self-hosting. Modifying it, redistributing it, selling it, or hosting it for other people needs our written permission. That is not us being precious about lines of code — the receipt chain and the workspace design are the product, and a permissive licence would let anyone repackage them as their own.</p>
<p>The licence file says it in plain English. No lawyer required to understand it, though one wrote the wording.</p>
<h3>Verify us, do not believe us</h3>
<p>The chain on this box is public numbers, not a copy of anything: current count, head hash and merkle root are re-stamped whenever we make a claim. Anyone can hold those numbers and check later that the record did not change underneath them.</p>
<p>That is the whole idea, really: not "trust our AI", but "here is the code, here is the chain, here are the numbers — check them yourself and tell us if we are wrong."</p>"""),
 "free-ai-no-credit-card": ("Free AI with no credit card — 60 calls a day", "2026-11-09",
   "Most 'free' AI tools want a card before you type anything. Here is a free tier that really is free: email only, 60 calls a day, 1 GB workspace.",
   """<p>Every second AI site says "free" and then asks for a card. The free ones that do not usually have a catch: a 3-day trial, a queued model, or your chats used as training data.</p>
<p>Our free plan is boring on purpose:</p>
<ul><li><b>60 calls a day</b>, resetting at 00:00 UTC</li>
<li><b>Email only</b> — no card, no phone</li>
<li><b>1 GB workspace</b> for files and chats</li>
<li>Runs on our own hardware, not a resold API</li></ul>
<p>Memory is off until you press AUTHORISE, and you can revoke it or forget everything with one click. That is not a marketing line: it is a switch you can see.</p>
<p><a href="/signup">Create the account</a> — it takes under a minute and asks for nothing but an email.</p>"""),
 "self-host-ai-workspace": ("Self-hosting an AI workspace: what you actually need", "2026-11-09",
   "A practical look at running your own AI workspace: hardware, model, data, and what the hosted free tier cannot give you.",
   """<p>Self-hosting an AI assistant got easier in 2026: a 4B model runs comfortably on a small machine, and the tooling no longer needs a GPU for text work.</p>
<h3>What you need</h3>
<ul><li>Any x86 box with 8 GB RAM (a VPS or an old laptop works)</li>
<li>A model: a quantised 4B runs at a few hundred ms per reply on CPU</li>
<li>Somewhere to put files: 20 GB is plenty for a single person</li></ul>
<h3>What you get that hosted cannot give you</h3>
<ul><li><b>Full access</b> to the machine it runs on — no sandbox, no 1 GB cap</li>
<li>No call limit</li>
<li>Your data never leaves the box</li></ul>
<p>Hosted is better when you are starting: no setup, and 60 calls a day free. Self-host is better once the machine in front of you is the one you want the assistant to touch. Both are the same interface.</p>
<p><a href="/self-host">Self-host instructions</a> · <a href="/free">Try it hosted free</a></p>"""),
 "ai-workspace-with-files": ("Why files matter more than model size in an AI workspace", "2026-11-09",
   "The difference between a chat box and a workspace is what the assistant can hold: your files, a few days of context, and a place to put the answer.",
   """<p>People compare AI tools on model benchmarks. In daily use the thing that decides whether a tool is useful is much less glamorous: <b>can it read my file, keep it, and write the result back</b>?</p>
<p>A 4B model that can open the spreadsheet and edit it beats a frontier model that can only read text I paste, for the tasks I actually do.</p>
<h3>What "workspace" means here</h3>
<ul><li>A private 1 GB space per account</li>
<li>Uploads that stay between sessions</li>
<li>Tools and plugins that run against those files</li>
<li>A signed record of what the house changed, so you can check claims</li></ul>
<p>The trade is honest: a small local model is weaker at hard reasoning. If your work is reasoning, use the top-up model. If your work is files and repetition, the free local one is often enough.</p>
<p><a href="/signup">Start free</a> · <a href="/plan">See plans</a></p>"""),
}



async def h_security(r):
    ok = s33_ready()
    body = f"""
<div class="wrap" style="max-width:820px;padding:64px 20px">
<h1 class=wordmark style="font-size:clamp(28px,6vw,56px);color:var(--neo)">SEE 7.7.8 · S33</h1>
<p class=sub>What is encrypted, what is not, and how to check it yourself. No "unhackable" claims here.</p>
<div class="card" style="margin:18px 0">
<h3 style="margin-top:0">THE ENGINE</h3>
<p style="color:var(--dim)">S33 is DOLA RND's <b>SEE 7.7.8</b> engine: <b>LOCK1</b> AES-256-GCM-SIV
(RFC 8452) plus <b>LOCK2</b> HMAC-SHA256 over the canonical body with a constant-time compare, keys split by
HKDF-SHA256 domains (siv / hmac / synth-nonce / snapshot / epochlog), a 4096-entry replay guard and an
optional epoch log. Engine id <span class=mono>sse77.8</span>, wire byte <span class=mono>0x7B</span>,
<b>57 bytes of overhead per packet</b>. Status right now: <b style="color:{'var(--neo)' if ok else 'var(--red)'}">{'LOADED' if ok else 'NOT LOADED'}</b>.</p>
</div>
<h3 style="color:var(--neo)">WHAT IS S33-ENCRYPTED AT REST</h3>
<ul style="color:var(--dim);line-height:1.9">
<li>Everything SPARKY remembers about you: the append-only turn log and the distilled facts file.</li>
<li>Each record is its own S33 envelope, base64 on disk, with the plaintext SHA-256 inside the header —
edit one byte and it fails closed instead of being read.</li>
<li>Nothing is written as plaintext when the engine is unavailable: the write path raises rather than falls back.</li>
</ul>
<h3 style="color:var(--neo)">WHAT IS NOT</h3>
<ul style="color:var(--dim);line-height:1.9">
<li><b>The SEAL chain</b> is signed (ed25519) and public on purpose — it is a record, not a secret.</li>
<li><b>Your working files</b> sit in your own 1 GB workspace volume, protected by container isolation and the host's disk, not by S33.</li>
<li><b>Traffic</b> is TLS, not S33. S33 is data at rest, not a transport.</li>
<li>The engine is <b>verified, not trusted</b>: it has our tests and a pinned hash, but no external audit.</li>
</ul>
<h3 style="color:var(--neo)">CHECK IT</h3>
<p style="color:var(--dim)">Round-trip and tamper tests run on demand:
<span class=mono>POST {BASE}/admin/s33/selftest</span> with the admin token. Proof of the current engine build:
<span class=mono>sha256 3def4b59…</span></p>
<p style="margin-top:26px"><a class=btn href="{BASE}/signup">START FREE — NO CARD</a>
<a class="btn ghost" href="{BASE}/blog/self-host-ai-workspace">SELF-HOSTING NOTES</a></p>
</div>"""
    return web.Response(text=page("SEE 7.7.8 · S33 encryption — what is covered", body, css=FIRE_CSS, path="/security",
        desc="SEE 7.7.8 (S33): AES-256-GCM-SIV + HMAC-SHA256 data at rest for AI memory. What is encrypted, what is not, and how to verify it."),
        content_type="text/html")


async def h_s33_selftest(r):
    tok = (r.headers.get("x-admin-token") or r.query.get("token") or "")
    if not admin_ok(tok):
        return web.json_response({"error": "forbidden"}, status=403)
    if not s33_ready():
        return web.json_response({"ok": False, "error": _S33["err"]}, status=500)
    out = {}

    def _run(n, size):
        t0 = time.time(); bad = 0
        for i in range(n):
            pt = os.urandom(size) + b"|chc|" + str(i).encode()
            env = s33_enc(pt, ad=b"chc:selftest")
            if s33_dec(env) != pt:
                bad += 1
        dt = time.time() - t0
        return {"roundtrips": n, "payload_bytes": size, "failures": bad,
                "seconds": round(dt, 3), "per_sec": int(n / dt) if dt else 0}

    out["small"] = _run(200, 64)
    out["medium"] = _run(100, 4096)
    out["large"] = _run(20, 100000)
    pt = b"tamper me"
    env = bytearray(s33_enc(pt, ad=b"chc:tamper"))
    env[-5] ^= 0xFF
    try:
        s33_dec(bytes(env)); out["tamper_detected"] = False
    except Exception as e:
        out["tamper_detected"] = True
        out["tamper_error"] = str(e)[:80]
    # prove the REAL memory path: what lands on disk must be an S33 envelope, and it must read back
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            fp = pathlib.Path(td) / "turns.jsonl"
            rec = {"role": "selftest", "text": "s33 memory path proof"}
            fp.write_bytes(_s33_line(rec))
            raw = fp.read_bytes()
            back = _s33_unline(raw.rstrip(b"\n"))
            out["memory_path"] = {"on_disk_prefix": raw[:5].decode("ascii", "replace"),
                                  "is_envelope": raw.startswith(b"S33E:"),
                                  "roundtrip_ok": back == rec,
                                  "plaintext_leak": b"s33 memory path proof" in raw}
    except Exception as e:
        out["memory_path"] = {"error": str(e)[:120]}
    out["engine"] = "sse77.8"
    out["overhead"] = "57 bytes/packet"
    out["ok"] = out["small"]["failures"] == 0 and out["medium"]["failures"] == 0 and out["large"]["failures"] == 0 and out["tamper_detected"]
    return web.json_response(out)


async def h_blog(r):
    items = "".join(
        '<li style="margin:18px 0"><a href="%s/blog/%s"><b style="font-size:17px">%s</b></a>'
        '<div style="color:var(--dim);font-size:13px">%s</div></li>' % (BASE, slug, t, d)
        for slug, (t, _dt, d, _b) in sorted(POSTS.items(), key=lambda kv: kv[1][1], reverse=True))
    body = f"""
<div class="wrap" style="max-width:760px;padding:64px 20px">
<h1 class=wordmark style="font-size:clamp(28px,6vw,52px);color:var(--neo)">NOTES</h1>
<p class=sub>Plain writing about AI workspaces, self-hosting and the free tier. No growth hacks.</p>
<ul style="list-style:none;padding:0">{items}</ul>
<p style="margin-top:26px;font-size:15px;line-height:1.8;color:#cfd6e4">
The thing these notes keep circling back to is the <a href="{BASE}/free">free tier: 60 calls a day, no card</a> —
that is where you can test any of this without paying us anything.</p>
<p style="margin-top:22px"><a class=btn href="{BASE}/free">SEE THE FREE TIER</a>
<a class=btn href="{BASE}/signup">START FREE — NO CARD</a></p>
</div>"""
    return web.Response(text=page("Notes — AI workspaces, self-hosting, free tiers", body, css=FIRE_CSS, path="/blog",
        desc="Plain writing about AI workspaces, self-hosting and honest free tiers."), content_type="text/html")


async def h_blog_post(r):
    slug = r.match_info.get("slug", "")
    post = POSTS.get(slug)
    if not post:
        raise web.HTTPNotFound()
    title, dt, desc, html = post
    body = f"""
<div class="wrap" style="max-width:720px;padding:56px 20px">
<p style="color:var(--dim);font-size:12px;letter-spacing:.08em">{dt} · CHC HARNESS</p>
<h1 style="font-size:clamp(26px,5vw,40px);line-height:1.2;color:var(--ink)">{title}</h1>
<div style="font-size:16px;line-height:1.8;color:#cfd6e4;margin-top:18px">{html}</div>
<p style="margin-top:30px;font-size:15px;line-height:1.8;color:#cfd6e4">
If you want to try this yourself, the <a href="{BASE}/free">free AI workspace</a> gives you 60 calls a day and a
1 GB private space with no card, and <a href="{BASE}/plan">the plans page</a> is the honest price list.</p>
<p style="margin-top:22px"><a class=btn href="{BASE}/free">TRY THE FREE TIER</a>
<a class=btn href="{BASE}/signup">START FREE — NO CARD</a>
<a class="btn ghost" href="{BASE}/blog">MORE NOTES</a></p>
</div>"""
    return web.Response(text=page(title, body, css=FIRE_CSS, path="/blog/" + slug, desc=desc), content_type="text/html")


async def h_free(r):
    body = f"""
<div class="wrap" style="max-width:860px;padding:64px 20px">
<h1 class=wordmark style="font-size:clamp(30px,7vw,64px);color:var(--neo)">FREE AI WORKSPACE</h1>
<p class=sub>Sixty AI calls a day, a 1 GB workspace, files, tools and a shell-free sandbox.
<b>No card. Email only.</b> Upgrade later, or never.</p>
<p><a class=btn href="{BASE}/signup">CREATE YOUR ACCOUNT</a>
<a class="btn ghost" href="{BASE}/plan">SEE PLANS</a></p>
<div class=grid>
  <div class=feat><h4>60 CALLS / DAY</h4><p>On our own hardware. Resets 00:00 UTC. Nothing to buy.</p></div>
  <div class=feat><h4>1 GB WORKSPACE</h4><p>Upload files, keep chats, publish pages. Yours, private, non-root.</p></div>
  <div class=feat><h4>REAL TOOLS</h4><p>Files, search, plugins and automation in one place — not a chat box with a text field.</p></div>
  <div class=feat><h4>IT REMEMBERS IF YOU SAY SO</h4><p>Memory is off until you press AUTHORISE. You can revoke or forget everything in one click.</p></div>
</div>
<h2 style="margin-top:44px;color:var(--neo)">WHAT IT IS NOT</h2>
<p style="color:var(--dim)">It is not an image generator, and we say so instead of pretending. It is not a
$20 subscription you forget about — the free plan has no card attached at all. And it is not a black box:
every account can verify the signed record of what the house shipped.</p>
<h2 style="margin-top:36px;color:var(--neo)">CHECK US BEFORE YOU TRUST US</h2>
<p style="color:var(--dim)">The source is public: one Python file, the whole thing, including the receipt
code that signs every record. You can read it, run an unmodified copy on your own machine, and verify the
chain yourself instead of believing a badge:
<a href="https://github.com/CHCDOLADEEPSEEKMKSEC/chc-harness" style="color:var(--neo)">github.com/CHCDOLADEEPSEEKMKSEC/chc-harness</a>.
The licence is restrictive on purpose — read and run, not repackage — and it says so in plain English.</p>
<h2 style="margin-top:36px;color:var(--neo)">WHEN YOU WANT MORE</h2>
<p style="color:var(--dim)">QWEN+ is <b>$5 a month</b> for 1,200 calls a day. The DeepSeek top-up is
<b>$5 once</b> for $2.50 of DeepSeek usage — a one-off, not a subscription. Self-host is free and gives you
full access to your own machine.</p>
<p style="margin-top:26px"><a class=btn href="{BASE}/signup">START FREE — NO CARD</a></p>
</div>"""
    return web.Response(text=page("Free AI workspace — 60 calls a day, no card", body, css=FIRE_CSS, path="/free",
        desc="Free AI workspace: 60 calls a day on local Qwen, 1 GB private space, files and tools. Email sign-up only, no card required."),
        content_type="text/html")


async def h_selfhost_page(r):
    body = f"""
<div class="wrap" style="max-width:860px;padding:64px 20px">
<h1 class=wordmark style="font-size:clamp(30px,7vw,64px);color:var(--neo)">SELF-HOST IT</h1>
<p class=sub>Same product, on your hardware, <b>full access to that machine</b> — no 1 GB cap, no sandbox,
no call limit, your model, your data. We stay out of the loop.</p>
<div class=card style="margin:18px 0">
<h3 style="margin-top:0">ONE COMMAND</h3>
<pre style="background:#0a0d13;border:1px solid #1d2230;border-radius:10px;padding:14px;overflow:auto;color:var(--neo)">curl -fsSL {BASE}/install.sh | bash</pre>
<p style="color:var(--dim)">Or take the pieces: <a href="{BASE}/download">download</a> ·
<a href="{BASE}/compose.yml">compose.yml</a> · <a href="{BASE}/dockerfile">Dockerfile</a> ·
<a href="{BASE}/get">all platforms</a></p>
</div>
<h2 style="color:var(--neo)">WHY SELF-HOST</h2>
<ul style="color:var(--dim);line-height:1.9">
<li>Your data never leaves your machine — the shipped installer runs with full local access.</li>
<li>No quota. The 60-a-day limit is a hosted-plan thing only.</li>
<li>Point it at your own model endpoint if you have one, or the bundled settings.</li>
<li>Same interface, same assistant, same signed record you can verify.</li>
</ul>
<p style="margin-top:26px"><a class=btn href="{BASE}/get">GET IT</a>
<a class="btn ghost" href="{BASE}/free">TRY THE HOSTED FREE PLAN</a></p>
</div>"""
    return web.Response(text=page("Self-host your AI — full access to your own machine", body, css=FIRE_CSS, path="/self-host",
        desc="Download CHC HARNESS and run your own AI workspace with full access to your machine, no call cap, no sandbox."),
        content_type="text/html")


async def h_compare(r):
    rows = [
        ("Price", "Free plan $0, no card", "Usually $20+/month, card up front"),
        ("Free tier", "60 calls/day, no card", "Limited trial, then pay"),
        ("Workspace", "1 GB private space with files", "Chat thread only"),
        ("Tools", "Files, search, plugins, automation, shell on full access", "Mostly chat + code snippets"),
        ("Your data", "Hosted sandbox or your own machine; memory needs consent", "Vendor cloud"),
        ("Record", "Signed, verifiable chain of what shipped", "Release notes"),
        ("Model honesty", "Reply header names the model that answered", "Often not visible"),
        ("Self-host", "Free download, full local access", "Rarely offered"),
    ]
    tr = "".join(f"<tr><td style='padding:10px;border-bottom:1px solid #1d2230;color:var(--dim)>{a}</td>"
                 f"<td style='padding:10px;border-bottom:1px solid #1d2230'>{b}</td>"
                 f"<td style='padding:10px;border-bottom:1px solid #1d2230;color:#5d6779'>{c}</td></tr>" for a, b, c in rows)
    body = f"""
<div class="wrap" style="max-width:900px;padding:64px 20px">
<h1 class=wordmark style="font-size:clamp(28px,6vw,56px);color:var(--neo)">A WORKSPACE, NOT A CHAT BOX</h1>
<p class=sub>Honest comparison against a typical $20/month AI subscription. We will not pretend we win every line —
image generation is one we lose, and there is no mobile app store listing yet.</p>
<table style="width:100%;border-collapse:collapse;margin-top:20px;font-size:14px">
<tr><th style="text-align:left;padding:10px;color:#5d6779;font-size:11px;letter-spacing:.1em">WHAT</th>
<th style="text-align:left;padding:10px;color:var(--neo);font-size:11px;letter-spacing:.1em">CHC HARNESS</th>
<th style="text-align:left;padding:10px;color:#5d6779;font-size:11px;letter-spacing:.1em">TYPICAL SUBSCRIPTION</th></tr>
{tr}
</table>
<p style="color:#5d6779;font-size:12px;margin-top:14px">Typical-subscription column is our honest reading of the
market in November 2026, not a quote from any vendor.</p>
<p style="margin-top:26px"><a class=btn href="{BASE}/signup">TRY IT FREE — NO CARD</a></p>
</div>"""
    return web.Response(text=page("CHC HARNESS vs chatbot subscriptions — honest comparison", body, css=FIRE_CSS, path="/compare",
        desc="A workspace with files, tools and a 1 GB space versus a chat box. Honest comparison of price, free tier, tools, data and self-hosting."),
        content_type="text/html")


async def h_robots(r):
    txt = "User-agent: *\nAllow: /\nDisallow: /app\nDisallow: /admin\nDisallow: /api\n\nSitemap: %s/sitemap.xml\n" % SITE
    return web.Response(text=txt, content_type="text/plain")


async def h_sitemap(r):
    # only real 200s belong in a sitemap; /assist is login-gated (302) so it is excluded
    _lastmod = os.environ.get("CHC_SITEMAP_LAST", "2026-11-10")
    urls = "".join(f"<url><loc>{SITE}{u}</loc><lastmod>{_lastmod}</lastmod><changefreq>weekly</changefreq><priority>{'1.0' if u=='/' else '0.8'}</priority></url>"
                   for u, _, _ in PUBLIC_PAGES if u != "/assist")
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + urls + "</urlset>")
    return web.Response(text=xml, content_type="application/xml")


async def h_plan(r):
    u = current_user(r)
    if u:
        pay = plan_pay_html(u)
    else:
        pay = ("<p style='color:#8892a6'>Payment details are shown to signed-in accounts only"
               " — <a href='" + BASE + "/login' style='color:var(--neo)'>log in</a> or"
               " <a href='" + BASE + "/signup' style='color:var(--neo)'>create one</a>.</p>")
    def card(key):
        pl = PLANS[key]
        return ('<div class=card style="margin:14px 0"><h3 style="margin-top:0;color:var(--neo)">%s'
                ' <span style="color:var(--ink);font-size:22px">%s</span>'
                ' <span style="color:var(--dim);font-size:14px">%s</span></h3>'
                '<p style="color:var(--dim);margin:6px 0"><b>%s</b></p>'
                '<p style="color:var(--dim);margin:6px 0">Model: %s</p></div>'
                % (pl["label"], pl["price"], pl["period"], pl["calls"], pl["model"]))
    signed = (u["plan"] if u else "free")
    body = f"""<div class="wrap" style="max-width:780px;padding:56px 20px">
<h1 class=wordmark style="font-size:clamp(30px,6vw,64px);color:var(--neo)">PLANS</h1>
<p style="color:var(--dim)">Free by default. Pay only when you want more calls or a bigger model.
You are on: <b style="color:var(--neo)">{PLANS.get(signed, PLANS["free"])["label"]}</b></p>
{card("free")}{card("qwen6")}{card("deepseek3")}
<div class=card style="margin:14px 0"><h3 style="margin-top:0;color:var(--neo)">WHICH MODEL AM I ON?</h3>
<p style="color:var(--dim);margin:6px 0">Default engine, on FREE and QWEN+: <b>local Qwen 3-4B on our own hardware</b>.</p>
<p style="color:var(--dim);margin:6px 0">On the <b>DEEPSEEK $5 top-up</b> with the switch set to DEEPSEEK: calls go to the
<b>DeepSeek upstream API</b>. The header on every reply names the model that actually answered.</p>
<p style="color:#5d6779;font-size:12px;margin-bottom:0">Top-ups are one-off and do not renew. A top-up is valid for 30 days
from the moment you activate the code. Nothing auto-charges.</p></div>
<div class=card style="margin:14px 0"><h3 style="margin-top:0;color:var(--neo)">REFER A FRIEND</h3>
<p style="color:var(--dim);margin:6px 0">Send someone your email as the referral. When they make their first payment,
<b>we credit you 50% of that first payment</b> — one time, not ongoing.</p>
<p style="color:#5d6779;font-size:12px;margin-bottom:0">The credit is applied to your account by hand within 24h, and the
friend must use the same referral email before paying for it to count.</p></div>
<div class=card style="margin:14px 0"><h3 style="margin-top:0">SELF-HOST — YOUR MACHINE, FULL ACCESS</h3>
<p style="color:var(--dim)">Download it and run it on your own hardware: <b>full access to that machine</b>,
no 1 GB cap, no sandbox, your model, your data. We are not in the loop. One command per OS, see
<a href="{BASE}/get" style="color:var(--neo)">/get</a>.</p></div>
<div class=card><h3 style="margin-top:0">PAYMENT</h3>{pay}
<p style="color:#5d6779;font-size:12px;margin-bottom:0"><b style="color:var(--neo)">Activation code arrives by email, usually within a few hours (always inside 24h).</b>
Send the amount with your account email in the note.
We email you a one-time activation code — put it in at <a href="{BASE}/activate" style="color:var(--neo)">/activate</a>
(problem with the payment? open a thread at <a href="{BASE}/assist" style="color:var(--neo)">/assist</a> and we reply there)
and the plan (and DeepSeek, on the top-up) is live immediately. Nothing renews automatically.
Daily caps reset at 00:00 UTC.</p></div>
<p style="margin-top:20px"><a class=btn href="{BASE}/app">BACK TO WORKSPACE</a>
<a class="btn ghost" href="{BASE}/get">INSTALL / GET THE APP</a></p></div>"""
    return web.Response(text=page("Plans · CHC HARNESS", body, css=FIRE_CSS), content_type="text/html")


async def h_get(r):
    """How to install on every platform we can honestly support - plus the Play Store path."""
    base = BASE or "https://ai.94-237-56-140.sslip.io"
    body = f"""<div class="wrap" style="max-width:860px;padding:56px 20px">
<h1 class=wordmark style="font-size:clamp(28px,5vw,56px);color:var(--neo)">GET CHC HARNESS</h1>
<p style="color:var(--dim)">Hosted in the browser on any device, or self-host in one command.</p>

<div class=card style="margin:14px 0"><h3 style="margin-top:0">ANY DEVICE — NOTHING TO INSTALL</h3>
<p style="color:var(--dim)">Open <a href="{base}/" style="color:var(--neo)">{base}</a> and log in.
On a phone: browser menu &rarr; <b>Add to Home Screen</b> — it runs full-screen like an app.</p></div>

<div class=card style="margin:14px 0"><h3 style="margin-top:0">LINUX (Debian/Ubuntu, Fedora, Arch)</h3>
<pre class=mono style="background:#0b0e14;padding:12px;border-radius:8px;overflow:auto">curl -fsSL {base}/install.sh | bash -s -- --dir ~/chc-harness
# then:  cd ~/chc-harness &amp;&amp; ./start.sh   →  http://127.0.0.1:8895</pre></div>

<div class=card style="margin:14px 0"><h3 style="margin-top:0">macOS (Intel + Apple silicon)</h3>
<pre class=mono style="background:#0b0e14;padding:12px;border-radius:8px;overflow:auto">brew install python@3.12 git
curl -fsSL {base}/install.sh | bash -s -- --dir ~/chc-harness
cd ~/chc-harness &amp;&amp; ./start.sh</pre></div>

<div class=card style="margin:14px 0"><h3 style="margin-top:0">WINDOWS (10 / 11, PowerShell)</h3>
<pre class=mono style="background:#0b0e14;padding:12px;border-radius:8px;overflow:auto">winget install Python.Python.3.12 Git.Git
iwr -useb {base}/install.sh -OutFile install.sh
bash install.sh --dir "$HOME\chc-harness"
cd "$HOME\chc-harness"; ./start.sh</pre>
<p style="color:#5d6779;font-size:12px;margin-bottom:0">Or use Docker Desktop:
<code class=mono>docker compose -f {base}/compose.yml up -d</code></p></div>

<div class=card style="margin:14px 0"><h3 style="margin-top:0">ANDROID — GOOGLE PLAY STORE</h3>
<p style="color:var(--dim)">The app is a PWA, so the Play listing is a Trusted Web Activity wrapper
around the hosted instance. Two commands, from the <code class=mono>android/</code> folder in the package:</p>
<pre class=mono style="background:#0b0e14;padding:12px;border-radius:8px;overflow:auto">npm i -g @bubblewrap/cli
bubblewrap init --manifest {base}/manifest.json
bubblewrap build          # produces app-release-bundle.aab for the Play Console</pre>
<p style="color:#5d6779;font-size:12px;margin-bottom:0">Needs a Google Play developer account (one-off fee).
Upload the .aab, paste the assetlinks.json into <code class=mono>/.well-known/</code> (already served),
and the listing is live. No separate Android codebase to maintain.</p></div>

<div class=card style="margin:14px 0"><h3 style="margin-top:0">iOS</h3>
<p style="color:var(--dim)">Same PWA, installed from Safari via Share &rarr; Add to Home Screen.
App Store listing is not offered — Apple requires a native shell and a paid developer account.</p></div>

<p><a class=btn href="{BASE}/plan">SEE PLANS</a> <a class="btn ghost" href="{BASE}/app">OPEN WORKSPACE</a></p>
</div>"""
    return web.Response(text=page("Get CHC HARNESS", body, css=FIRE_CSS), content_type="text/html")


async def h_pricing(r):
    """Public price list. No internal cost figures exposed here."""
    out = {"currency": "USD", "plans": {}, "api_addon": {
        "name": "DEEPSEEK TOP-UP", "price_usd": 5.0, "credit_usd": 2.5, "period": "top-up",
        "calls": PLANS["deepseek3"]["cap"],
        "model": "DeepSeek upstream", "keys": "API key access included"}}
    for k, pl in PLANS.items():
        out["plans"][k] = {"label": pl["label"], "price": pl["price"], "period": pl["period"],
                           "calls_per_day": pl["cap"], "model": pl["model"]}
    return web.json_response(out)


async def h_manifest(r):
    """PWA manifest - what makes Add-to-Home-Screen and the Play TWA work."""
    man = {"name": "CHC HARNESS", "short_name": "CHC", "id": (BASE or "") + "/",
           "start_url": (BASE or "") + "/app", "scope": (BASE or "") + "/",
           "display": "standalone", "background_color": "#07090d", "theme_color": "#39ff9e",
           "description": "Your own AI harness: 1 GB workspace, real shell, signed record. $5/mo hosted or $0 self-hosted.",
           "icons": [{"src": (BASE or "") + "/icon-192.png", "sizes": "192x192", "type": "image/png"},
                     {"src": (BASE or "") + "/icon-512.png", "sizes": "512x512", "type": "image/png"}]}
    return web.json_response(man)


async def h_assetlinks(r):
    """Digital Asset Links so the Play TWA opens without a browser bar.
    Fill in the SHA-256 from Play Console -> App integrity -> signing certificate."""
    links = [{"relation": ["delegate_permission/common.handle_all_urls"],
              "target": {"namespace": "android_app",
                         "package_name": "io.chcflasf33.chcharness",
                         "sha256_cert_fingerprints": ["REPLACE_WITH_PLAY_SIGNING_SHA256"]}}]
    return web.json_response(links)


def _mail_candidates(name):
    """mailapi.env / smtp.env live next to the install - find them wherever that is."""
    out = []
    env = os.environ.get("CHC_AI_MAIL_API_ENV" if name == "mailapi.env" else "CHC_AI_SMTP_ENV")
    if env:
        out.append(pathlib.Path(env))
    for base in (getattr(DBP, "parent", None), pathlib.Path(str(CLI.db)).resolve().parent,
                 pathlib.Path.cwd()):
        if base is not None:
            out.append(pathlib.Path(base) / name)
    out.append(pathlib.Path("/opt/chc-ai") / name)
    return out


def _mail_json(name):
    for pth in _mail_candidates(name):
        try:
            if pth.is_file():
                return json.loads(pth.read_text())
        except Exception:
            continue
    return {}


def smtp_conf():
    d = _mail_json("smtp.env")
    return d.get("email", ""), d.get("password", "")

MAIL_API_ENV = pathlib.Path(os.environ.get("CHC_AI_MAIL_API_ENV") or (str(DBP.parent / "mailapi.env") if (DBP.parent / "mailapi.env").exists() else "/opt/chc-ai/mailapi.env"))

def mail_api_conf():
    return _mail_json("mailapi.env")

def mail_api_send(to_addr, subject, body):
    """HTTPS mail transport (Resend or Brevo). Works when SMTP ports are blocked."""
    cfg = mail_api_conf()
    prov = (cfg.get("provider") or "").lower()
    key = cfg.get("key") or ""
    sender = cfg.get("from") or "CHC HARNESS <noreply@bafoune.net>"
    if not key or prov not in ("resend", "brevo"):
        return False
    try:
        if prov == "resend":
            payload = {"from": sender, "to": [to_addr], "subject": subject, "text": body}
            req = urllib.request.Request("https://api.resend.com/emails", data=json.dumps(payload).encode(),
                headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=25) as r:
                return 200 <= r.status < 300
        payload = {"sender": {"email": sender.split("<")[-1].rstrip(">"), "name": "CHC HARNESS"},
                   "to": [{"email": to_addr}], "subject": subject, "textContent": body}
        req = urllib.request.Request("https://api.brevo.com/v3/smtp/email", data=json.dumps(payload).encode(),
            headers={"api-key": key, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=25) as r:
            return 200 <= r.status < 300
    except Exception as e:
        print("mail api error:", type(e).__name__, str(e)[:120])
        return False

def queue_mail(to_addr, subject, body):
    c = db(); c.execute("insert into mail_queue(to_addr,subject,body,created,sent) values(?,?,?,?,0)",
                        (to_addr, subject, body, now())); c.commit(); c.close()
    return True

def send_code(to_email, code):
    subj = "Your CHC HARNESS 2FA code"
    body = f"Your CHC HARNESS login code is: {code}\n\nIt expires in 10 minutes.\n\n— BAFOUNE-NET"
    if mail_api_send(to_email, subj, body):
        return True
    # HTTPS API not configured: queue for the home-box relay (SMTP is blocked on both sides).
    queue_mail(to_email, subj, body)
    return True
    queue_mail(to_email, "Your CHC HARNESS 2FA code",
               f"Your CHC HARNESS login code is: {code}\n\nIt expires in 10 minutes.\n\n— BAFOUNE-NET")
    return True
    sender, pw = smtp_conf()
    if not sender or not pw: return False
    msg = (f"From: CHC HARNESS <{sender}>\r\nTo: {to_email}\r\nSubject: Your CHC HARNESS 2FA code\r\n"
           f"Content-Type: text/plain; charset=utf-8\r\n\r\n"
           f"Your CHC HARNESS login code is: {code}\n\nIt expires in 10 minutes. "
           f"If you did not ask for this, ignore it.\n\n— BAFOUNE-NET")
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as sm:
            sm.login(sender, pw)
            sm.sendmail(sender, [to_email], msg.encode())
        return True
    except Exception:
        try:
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as sm:
                sm.starttls(); sm.login(sender, pw); sm.sendmail(sender, [to_email], msg.encode())
            return True
        except Exception:
            return False

async def api_qr(request):
    data = request.query.get("d", "")
    if not data: return web.json_response({"error": "d required"}, status=400)
    try:
        import segno
        qr = segno.make(data, error="m")
        svg = qr.svg_inline(scale=4, dark="#39ff9e", light="#05060a", border=2)
        return web.Response(text=svg, content_type="image/svg+xml")
    except Exception as e:
        return web.json_response({"error": f"qr: {e}"}, status=500)

async def api_email_code(request):
    d = await request.json(); acct = (d.get("acct") or "").strip().lower()
    c = db(); row = c.execute("select id,email from users where email=? or lower(handle)=?", (acct, acct)).fetchone()
    if not row: c.close(); return web.json_response({"error": "no such account"})
    code = f"{secrets.randbelow(1000000):06d}"
    c.execute("delete from email_codes where uid=?", (row["id"],))
    c.execute("insert into email_codes(uid,code,exp,tries) values(?,?,?,0)", (row["id"], hash_key(code), int(time.time()) + 600))
    c.commit(); c.close()
    ok = send_code(row["email"], code)
    return web.json_response({"ok": True, "sent": ok, "to": row["email"],
                              "msg": "code sent to your email" if ok else "email sending not configured yet — use the authenticator code"})

async def api_magic_request(request):
    """Request a one-click login link for an account.

    SECURITY: the link goes to the account's own email address and never into the HTTP response.
    It used to be echoed back when mail was not configured (CHC_AI_SHOW_LINKS=1), which meant
    anyone could POST any email address and be handed a working session — account takeover.
    Only an ADMIN token holder may have the link printed back to them."""
    d = await request.json()
    acct = (d.get("acct") or "").strip().lower()
    if not acct or len(acct) < 3:
        return web.json_response({"error": "email required"}, status=400)
    admin = admin_token_ok(request)
    c = db()
    row = c.execute("select id, email from users where email=? or lower(handle)=?", (acct, acct)).fetchone()
    if not row:
        c.close()
        return web.json_response({"ok": True, "detail": "if that account exists, a link is on its way"})
    tok = secrets.token_urlsafe(24)
    c.execute("insert into magic(token, uid, exp, used) values(?,?,?,0)", (tok, row["id"], int(time.time()) + 900))
    c.commit(); c.close()
    base = (PUBLIC_URL or "").rstrip("/")
    link = "%s/magic?t=%s" % (base, tok)
    sent = False
    try:
        body = ("Log in to CHC HARNESS (one click, expires in 15 minutes):\n\n" + link +
                "\n\nIf you did not ask for this, ignore this email.")
        if mail_api_conf():
            mail_api_send(row["email"], "Your CHC HARNESS login link", body); sent = True
        else:
            sender, pw = smtp_conf()
            if sender and pw:
                import smtplib as _s
                try:
                    with _s.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as sm:
                        sm.login(sender, pw); sm.send_message(_mk_mail(sender, row["email"], "Your CHC HARNESS login link", body))
                except Exception:
                    with _s.SMTP("smtp.gmail.com", 587, timeout=20) as sm:
                        sm.starttls(); sm.login(sender, pw); sm.send_message(_mk_mail(sender, row["email"], "Your CHC HARNESS login link", body))
                sent = True
    except Exception:
        sent = False
    back = {"ok": True, "sent": sent}
    if not sent:
        back["detail"] = "mail is not configured on this server — ask the admin for a link"
    # the link is never handed to an unauthenticated caller, whoever's address they typed
    if admin:
        back["link"] = link
    return web.json_response(back)

async def api_login_email(request):
    d = await request.json(); acct = (d.get("acct") or "").strip().lower(); code = (d.get("code") or "").strip()
    c = db(); row = c.execute("select id from users where email=? or lower(handle)=?", (acct, acct)).fetchone()
    if not row: c.close(); return web.json_response({"error": "no such account"})
    er = c.execute("select id,code,exp,tries from email_codes where uid=? order by id desc limit 1", (row["id"],)).fetchone()
    if not er: c.close(); return web.json_response({"error": "no code requested"})
    if er["exp"] < int(time.time()): c.close(); return web.json_response({"error": "code expired — request a new one"})
    if er["tries"] >= 5: c.close(); return web.json_response({"error": "too many tries — request a new code"})
    if not hmac.compare_digest(er["code"], hash_key(code)):
        c.execute("update email_codes set tries=tries+1 where id=?", (er["id"],)); c.commit(); c.close()
        return web.json_response({"error": "wrong code"})
    c.execute("delete from email_codes where uid=?", (row["id"],)); c.commit(); c.close()
    resp = web.json_response({"ok": True}); set_session(resp, row["id"], "email-code", request); return resp


CLAIM_PAGE = """<!doctype html><meta charset=utf-8><title>Claim your CHC HARNESS account</title>
<style>body{background:#05060a;color:#e8edf7;font:15px/1.6 system-ui;max-width:520px;margin:8vh auto;padding:0 20px}
h1{font:900 30px/1 system-ui;color:#39ff9e;-webkit-text-stroke:1px #000;letter-spacing:.02em}
input{width:100%;background:#0b0f16;border:1px solid #1d2230;border-radius:10px;color:#e8edf7;padding:11px 12px;margin:6px 0;font:14px inherit}
.btn{display:inline-block;padding:12px 20px;border-radius:11px;background:linear-gradient(135deg,#39ff9e,#14c47a);color:#04110a;font-weight:800;border:0;cursor:pointer;width:100%;margin-top:10px}
.err{color:#ff7b72;font-size:13px}.ok{color:#39ff9e}</style>
<h1>CLAIM ACCOUNT</h1>
<p style="color:#8892a6">Set your password. You will get the 2FA QR next.</p>
<div class=field><input id=pw type=password placeholder="new password (10+ chars)"></div>
<div class=field><input id=pw2 type=password placeholder="confirm password"></div>
<div id=msg class=err></div>
<button class=btn id=go>CLAIM & CONTINUE</button>
<script>
const t=new URLSearchParams(location.search).get('t')||'';
document.querySelector('#go').onclick=async()=>{
  const r=await fetch('/api/claim',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({t:t,pw:document.querySelector('#pw').value,pw2:document.querySelector('#pw2').value})});
  const j=await r.json();
  if(!j.ok){document.querySelector('#msg').textContent=j.error||'failed';return;}
  location='/app';
};
</script>"""

async def h_claim(r):
    return web.Response(text=CLAIM_PAGE, content_type="text/html")

async def api_claim(request):
    d = await request.json()
    tok = (d.get("t") or "").strip(); pw = d.get("pw") or ""; pw2 = d.get("pw2") or ""
    if len(pw) < 10: return web.json_response({"error": "password must be at least 10 characters"})
    if pw != pw2: return web.json_response({"error": "passwords do not match"})
    c = db(); row = c.execute("select uid,exp,used from claims where token=?", (hash_key(tok),)).fetchone()
    if not row: c.close(); return web.json_response({"error": "link not valid"})
    if row["used"]: c.close(); return web.json_response({"error": "link already used"})
    if row["exp"] < int(time.time()): c.close(); return web.json_response({"error": "link expired"})
    salt = new_salt()
    c.execute("update users set pw=?, salt=?, verified=1 where id=?", (pw_hash(pw, salt), salt, row["uid"]))
    c.execute("update claims set used=1 where token=?", (hash_key(tok),))
    u = c.execute("select email,totp from users where id=?", (row["uid"],)).fetchone()
    c.commit(); c.close()
    resp = web.json_response({"ok": True, "totp": u["totp"], "acct": u["email"]})
    set_session(resp, row["uid"], "claim", request)
    return resp


async def api_signup_email(request):
    d = await request.json(); email = (d.get("email") or "").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email): return web.json_response({"error": "valid email required"})
    c = db(); row = c.execute("select id from users where email=?", (email,)).fetchone()
    if not row:
        salt = new_salt()
        c.execute("insert into users(email,handle,pw,salt,totp,plan,created,verified) values(?,?,?,?,?,?,?,0)",
                  (email, email.split("@")[0][:24], pw_hash(secrets.token_hex(8), salt), salt,
                   b32(secrets.token_bytes(20)), "free", now()))
        c.commit()
    c.close()
    return await api_email_code(request)

async def api_verify_code(request):
    d = await request.json(); acct = (d.get("email") or d.get("acct") or "").strip().lower(); code = (d.get("code") or "").strip()
    c = db(); row = c.execute("select id from users where email=? or lower(handle)=?", (acct, acct)).fetchone()
    if not row: c.close(); return web.json_response({"error": "no such account"})
    er = c.execute("select id,code,exp,tries from email_codes where uid=? order by id desc limit 1", (row["id"],)).fetchone()
    if not er: c.close(); return web.json_response({"error": "no code requested — press EMAIL ME A 2FA CODE"})
    if er["exp"] < int(time.time()): c.close(); return web.json_response({"error": "code expired — request a new one"})
    if er["tries"] >= 5: c.close(); return web.json_response({"error": "too many tries — request a new code"})
    if not hmac.compare_digest(er["code"], hash_key(code)):
        c.execute("update email_codes set tries=tries+1 where id=?", (er["id"],)); c.commit(); c.close()
        return web.json_response({"error": "wrong code"})
    c.execute("delete from email_codes where uid=?", (row["id"],))
    c.execute("update users set verified=1 where id=?", (row["id"],)); c.commit(); c.close()
    resp = web.json_response({"ok": True}); set_session(resp, row["id"]); return resp

async def api_keys(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    c = db()
    if r.method == "POST":
        d = {}
        try: d = await r.json()
        except Exception: pass
        raw, prefix = new_api_key(u["id"], d.get("label") or "default")
        return web.json_response({"ok": True, "key": raw, "prefix": prefix,
                                  "note": "shown once — store it now; it cannot be recovered"})
    rows = c.execute("""select prefix,label,created,revoked,last_used from api_keys
                        where uid=? order by id desc""", (u["id"],)).fetchall()
    keys = [dict(x) for x in rows]
    c.close()
    return web.json_response({"keys": keys})

async def api_key_get_denied(r):
    """No read surface for key material: auth error when anonymous, forbidden when signed in."""
    if not current_user(r): return web.json_response({"error": "auth"}, status=401)
    return web.json_response({"error": "forbidden"}, status=403)

async def api_key_delete(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    prefix = r.match_info.get("prefix", "")
    c = db(); c.execute("update api_keys set revoked=1 where uid=? and prefix=?", (u["id"], prefix))
    c.commit(); c.close(); return web.json_response({"ok": True, "revoked": prefix})

async def api_version(r):
    latest = ""
    for cand in ("/opt/chc-ai/pkg/VERSION", "/opt/chc-ai/VERSION", str(pathlib.Path(__file__).with_name("VERSION"))):
        try:
            v = pathlib.Path(cand).read_text().strip()
            if v:
                latest = v; break
        except Exception:
            continue
    cur = globals().get("VERSION", "") or latest
    return web.json_response({"current": cur, "latest": latest or cur,
                              "update_available": bool(latest and cur and latest != cur)})


async def api_memory_info(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    if not SELF_HOST:
        return web.json_response({"error": "forbidden"}, status=403)
    mm = master_memory()
    return web.json_response({"master_memory_bytes": len(mm), "master_memory_lines": mm.count("\n"),
                              "path": MASTER_MEMORY_PATH, "loaded": bool(mm)})


async def api_remember(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    d = await r.json()
    on = 1 if d.get("on") else 0
    c = db(); c.execute("update users set remember_all=? where id=?", (on, u["id"])); c.commit(); c.close()
    return web.json_response({"ok": True, "remember_all": on})


async def api_verify(r):
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    import subprocess as _sp, re as _re
    # your chain, not ours: default to the CALLER's own vault
    root = os.environ.get("CHC_VERIFY_ROOT") or ("/opt/chc-ai/user_vaults/%s" % u["id"])
    seal = os.path.join(root, "tools", "seal.py")
    chain = os.path.join(root, "receipts", "chain.jsonl")
    if not os.path.exists(seal):
        return web.json_response({"ok": False, "error": "seal.py not found at " + seal}, status=500)
    try:
        env = dict(os.environ); env["CHC_SEAL_ROOT"] = root
        v = _sp.run(["python3", seal, "verify"], capture_output=True, text=True, timeout=90, env=env)
        lines = (v.stdout or "").strip().splitlines()
        line = lines[-1] if lines else ""
        rec = int((_re.search(r"(\d+) receipts", line) or [0, 0])[1]) if _re.search(r"(\d+) receipts", line) else 0
        rt = _re.search(r"root ([0-9a-f]{16,})", line)
        roothex = rt.group(1) if rt else ""
        last_seq = last_kind = last_subject = ""
        try:
            tail = _sp.run(["tail", "-n", "1", chain], capture_output=True, text=True, timeout=10).stdout.strip()
            if tail:
                import json as _json
                r_ = _json.loads(tail)
                last_seq, last_kind = r_.get("seq"), r_.get("kind")
                last_subject = (r_.get("subject") or "")[:120]
        except Exception:
            pass
        return web.json_response({"ok": ("VERIFIED" in line) or line.startswith("OK"), "receipts": rec, "root": roothex,
                                  "last_seq": last_seq, "last_kind": last_kind,
                                  "last_subject": last_subject, "raw": line})
    except Exception as e:
        return web.json_response({"ok": False, "error": type(e).__name__ + ": " + str(e)}, status=500)


async def api_usage(r):
    u, key_id = auth_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    days = int(r.query.get("days", "30"))
    c = db()
    by_day = c.execute("""select ku.day, sum(ku.requests) requests, sum(ku.tokens) tokens
                          from key_usage ku join api_keys k on k.id=ku.key_id
                          where k.uid=? group by ku.day order by ku.day desc limit ?""",
                       (u["id"], days)).fetchall()
    total = c.execute("select coalesce(sum(tok),0) from usage where uid=?", (u["id"],)).fetchone()[0]
    keys = c.execute("""select prefix,label,created,revoked,last_used from api_keys
                        where uid=? order by id desc""", (u["id"],)).fetchall()
    c.close()
    return web.json_response({"messages_total": total, "by_day": [dict(x) for x in by_day],
                              "keys": [dict(x) for x in keys], "billing_unit": "message"})

async def api_admin_genpass(r):
    """Admin only: generate a NEW login password for an account and return it once.
    This is the button on /admin/usage. It never emails anything and needs the admin token,
    so it cannot be triggered by someone who only knows an email address."""
    tok = r.query.get("token") or r.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN or tok != ADMIN_TOKEN:
        return web.json_response({"error": "forbidden"}, status=403)
    try:
        d = await r.json()
    except Exception:
        d = {}
    email = (d.get("email") or "").strip().lower()
    c = db()
    if not email:
        owner_paths = [DBP.parent / "owner", pathlib.Path("/opt/chc-harness/owner"), pathlib.Path("/opt/chc-ai/owner")]
        if os.environ.get("CHC_OWNER_FILE"):
            owner_paths.insert(0, pathlib.Path(os.environ["CHC_OWNER_FILE"]))
        own = ""
        for _p in owner_paths:
            try:
                if _p.exists():
                    own = _p.read_text().strip().lower()
                    if own:
                        break
            except Exception:
                pass
        n_users = c.execute("select count(*) n from users").fetchone()["n"]
        first = c.execute("select email from users order by id limit 1").fetchone() if n_users else None
        email = own or (first["email"] if first else "")
    if not email:
        c.close()
        return web.json_response({"error": "no account yet — create one first"}, status=400)
    em, pw = set_user_password(c, email)
    c.close()
    log_line = "[admin] new password generated for %s at %s" % (em, datetime.datetime.utcnow().isoformat())
    try:
        with open("/tmp/chc_admin_password.log", "a") as fh:
            fh.write(log_line + "\n")
    except Exception:
        pass
    return web.json_response({"ok": True, "email": em, "password": pw,
                              "signin": (BASE or "") + "/signin"})


async def h_admin_logins(r):
    """Admin: last 100 sessions issued, with method — the receipt for 'how did they get in'."""
    tok = r.query.get("token") or r.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN or tok != ADMIN_TOKEN:
        return web.json_response({"error": "forbidden"}, status=403)
    c = db()
    try:
        c.execute("""create table if not exists login_audit(id integer primary key autoincrement,
                     ts integer, uid integer, method text, ip text, ua text)""")
    except Exception:
        pass
    rows = c.execute("""select a.ts, a.uid, u.email, a.method, a.ip, a.ua from login_audit a
                        left join users u on u.id=a.uid order by a.id desc limit 100""").fetchall()
    c.close()
    out = [{"when": datetime.datetime.utcfromtimestamp(x["ts"]).isoformat() + "Z",
            "uid": x["uid"], "email": x["email"], "method": x["method"],
            "ip": x["ip"], "ua": x["ua"]} for x in rows]
    if r.query.get("format") == "json":
        return web.json_response({"sessions": out})
    body = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td style='opacity:.6'>%s</td></tr>"
                   % (x["when"], x["email"] or "", x["method"], x["ip"], (x["ua"] or "")[:70]) for x in out) \
           or '<tr><td colspan="5" style="opacity:.6">no sessions yet</td></tr>'
    html = ("<!doctype html><meta charset=utf-8><title>CHC login audit</title>"
            "<body style='background:#080a0e;color:#cfe;font-family:ui-monospace,monospace;padding:26px'>"
            "<h1 style='color:#39ff9e;margin:0 0 4px'>LOGIN AUDIT</h1>"
            "<p style='opacity:.65'>Every session issued, newest first. method = the exact door used.</p>"
            "<table cellpadding=7 style='border-collapse:collapse;font-size:13px'>"
            "<tr style='color:#39ff9e;text-align:left'><th>when (UTC)</th><th>email</th><th>method</th><th>ip</th><th>user-agent</th></tr>"
            "%s</table><p style='opacity:.5;margin-top:18px'>json: add &amp;format=json</p></body>" % body)
    return web.Response(text=html, content_type="text/html")


async def admin_usage(r):
    tok = r.query.get("token") or r.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN or tok != ADMIN_TOKEN:
        return web.json_response({"error": "forbidden"}, status=403)
    c = db()
    rows = c.execute("""select u.email, u.plan, k.prefix, k.label, k.revoked, k.last_used,
                               coalesce(sum(ku.requests),0) requests, coalesce(sum(ku.tokens),0) tokens
                        from api_keys k join users u on u.id=k.uid
                        left join key_usage ku on ku.key_id=k.id
                        group by k.id order by tokens desc limit 500""").fetchall()
    keys = [dict(x) for x in rows]
    c.close()
    if r.query.get("format") == "json":
        return web.json_response({"keys": keys})
    enter = (BASE or "") + "/enter?t=" + (ADMIN_TOKEN or "")
    body = "".join(
        "<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (k.get("email") or "", k.get("plan") or "", k.get("prefix") or "", k.get("label") or "",
           "revoked" if k.get("revoked") else "active", k.get("requests") or 0, k.get("tokens") or 0)
        for k in keys) or '<tr><td colspan="7" style="opacity:.6">no billing keys yet</td></tr>'
    html = """<!doctype html><meta charset=utf-8><title>CHC HARNESS - billing report</title>
<body style="background:#080a0e;color:#cfe;font-family:ui-monospace,monospace;padding:28px;line-height:1.55">
<h1 style="color:#39ff9e;margin:0 0 2px">CHC HARNESS</h1><div style="opacity:.65;margin:0 0 20px">v%s</div>
<p style="margin:0 0 16px">This page is the <b>BILLING REPORT</b> &mdash; the API keys. It is <b>not</b> the login.</p>
<div style="border:1px solid #39ff9e;padding:14px 16px;margin:0 0 22px;max-width:820px">
  <div style="opacity:.7">Your permanent way into the workspace:</div>
  <div style="margin-top:8px"><a href="%s" style="color:#39ff9e;word-break:break-all">%s</a></div>
  <div style="opacity:.55;margin-top:8px">Bookmark it. It does not expire and does not change.</div>
</div>
<div style="border:1px solid #ffb84d;padding:14px 16px;margin:0 0 22px;max-width:820px">
  <div style="color:#ffb84d">LOGIN PASSWORD &mdash; generated here, never emailed</div>
  <p style="opacity:.75;margin:8px 0 12px">Press the button: the harness makes a strong password for the
  owner account, shows it <b>once</b> on this page, and sets it. Then sign in at <code>/signin</code>
  with that email + password. No link, no code, no email address trust.</p>
  <button id="genpw" style="background:#ffb84d;color:#080a0e;border:0;padding:11px 18px;font:inherit;font-weight:700;cursor:pointer">GENERATE NEW PASSWORD</button>
  <div id="pwout" style="margin-top:14px;font-size:15px"></div>
</div>
<script>
(function(){
  var tk = new URLSearchParams(location.search).get('token') || '';
  document.getElementById('genpw').onclick = async function(){
    var out = document.getElementById('pwout'); var b = this;
    b.disabled = true; out.textContent = 'generating...';
    try {
      var r = await fetch('/api/admin/genpass?token=' + encodeURIComponent(tk), {method:'POST',
        headers:{'Content-Type':'application/json'}, body: JSON.stringify({})});
      var d = await r.json();
      if (!d.password) { out.textContent = 'error: ' + (d.error || 'failed'); b.disabled = false; return; }
      out.innerHTML = '<div style="color:#39ff9e">email</div><div style="font-size:19px">' + d.email +
        '</div><div style="color:#39ff9e;margin-top:8px">password (shown once)</div>' +
        '<div style="font-size:24px;letter-spacing:1px;background:#111;padding:10px;border:1px solid #39ff9e">' +
        d.password + '</div><div style="margin-top:10px"><a href="/signin" style="color:#39ff9e">open the sign-in page &rarr;</a></div>';
    } catch(e) { out.textContent = 'network error: ' + e; b.disabled = false; }
  };
})();
</script>
<table cellpadding=6 style="border-collapse:collapse;font-size:13px">
<tr style="color:#39ff9e;text-align:left"><th>email</th><th>plan</th><th>key</th><th>label</th><th>state</th><th>requests</th><th>tokens</th></tr>
%s
</table>
<p style="opacity:.5;margin-top:22px">machine-readable: add <code>&amp;format=json</code></p>
</body>""" % (VERSION, enter, enter, body)
    return web.Response(text=html, content_type="text/html")

async def api_perms(r):
    """Persist the agent permission level for this chat (READ-ONLY / READ-WRITE / FULL ACCESS)."""
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    d = await r.json()
    cid = d.get("chat"); perm = d.get("perms") or "read-write"
    if perm not in ("read-only", "read-write", "full"):
        return web.json_response({"error": "bad perms"}, status=400)
    c = db()
    if cid: c.execute("update chats set perms=? where id=? and uid=?", (perm, cid, u["id"]))
    c.commit(); c.close()
    return web.json_response({"ok": True, "perms": perm})

async def api_shell(r):
    """The SHELL BUTTON: SELF-HOST ONLY. On our hosted box no customer gets a host shell."""
    u = current_user(r)
    if not u: return web.json_response({"error": "auth"}, status=401)
    if not SELF_HOST:
        return web.json_response({"error": "shell is a self-host feature; hosted plans do not have a shell",
                                  "code": "shell_disabled_hosted"}, status=403)
    d = await r.json()
    cid = d.get("chat"); cmd = (d.get("cmd") or "").strip()
    c = db()
    row = c.execute("select perms from chats where id=? and uid=?", (cid, u["id"])).fetchone()
    c.close()
    perm = (row["perms"] if row else "read-write") or "read-write"
    if perm != "full" and not SELF_HOST:
        return web.json_response({"error": "FULL ACCESS required (click FULL ACCESS first)", "perms": perm}, status=403)
    if not cmd:
        return web.json_response({"error": "empty command"}, status=400)
    loop = asyncio.get_event_loop()
    out = await loop.run_in_executor(None, lambda: _tool_shell(u["id"], cmd))
    return web.json_response({"ok": True, "cmd": cmd, "out": out})

INFRA_SEGMENTS = ("vault", "chain", "receipts", "ledger", "system", "seal", "opt", "secrets")
INFRA_NAME_BITS = ("chain", "seal", "receipt", "vault", "ledger")

def _is_infra_path(path):
    low = (path or "/").lower()
    if ".." in low or "\\" in low:
        return True
    segs = [x for x in low.split("/") if x]
    for seg in segs:
        stem = seg.rsplit(".", 1)[0]
        if seg in INFRA_SEGMENTS or stem in INFRA_SEGMENTS:
            return True
        if any(bit in seg for bit in INFRA_NAME_BITS):
            return True
    return False

@web.middleware
async def gate_auth_mw(request, handler):
    """The web instance authenticates email+password and passes X-Chc-User.
    With CHC_TRUST_GATE=1 that identity IS the login: no second sign-in."""
    if os.environ.get("CHC_TRUST_GATE") == "1":
        who = (request.headers.get("X-Chc-User") or "").strip().lower()
        if who and "@" in who and current_user(request) is None:
            c = db()
            row = c.execute("select id from users where lower(email)=?", (who,)).fetchone()
            if not row:
                salt = new_salt()
                c.execute("insert into users(email,handle,pw,salt,totp,plan,created,verified) values(?,?,?,?,?,?,?,1)",
                          (who, who.split("@")[0][:24], pw_hash(secrets.token_hex(16), salt), salt,
                           secrets.token_hex(10), "free", now()))
                c.commit()
                row = c.execute("select id from users where lower(email)=?", (who,)).fetchone()
            c.close()
            resp = await handler(request)
            set_session(resp, row["id"], "web-gate", request)
            return resp
    return await handler(request)


@web.middleware
async def infra_deny_mw(request, handler):
    """Infrastructure is never a customer surface: 403, always, with no detail."""
    if _is_infra_path(request.path):
        return web.json_response({"error": "forbidden"}, status=403)
    return await handler(request)

@web.middleware
async def no_store_mw(request, handler):
    resp = await handler(request)
    try:
        if resp.content_type and resp.content_type.startswith("text/html"):
            resp.headers["Cache-Control"] = "no-store, must-revalidate"
            resp.headers["Pragma"] = "no-cache"
    except Exception:
        pass
    return resp


def build_app():
    app = web.Application(middlewares=[gate_auth_mw, infra_deny_mw, no_store_mw],client_max_size=4 * 1024 * 1024)
    app.router.add_get("/", h_index)
    app.router.add_get("/health", h_health)
    app.router.add_get("/download", h_download)
    app.router.add_get("/install.sh", h_install_sh)
    app.router.add_get("/dockerfile", h_dockerfile)
    app.router.add_get("/compose.yml", h_compose)
    app.router.add_get("/signup", h_signup_page)
    app.router.add_get("/magic", h_magic)
    app.router.add_get("/enter", h_enter)
    app.router.add_get("/login", h_login_page)
    app.router.add_get("/signin", h_signin)
    app.router.add_get("/totp", h_totp_page)
    app.router.add_get("/app", h_app)
    app.router.add_get("/logout", h_logout)
    app.router.add_get("/plan", h_plan)
    app.router.add_get("/activate", h_activate)
    app.router.add_get("/assist", h_assist)
    app.router.add_get("/free", h_free)
    app.router.add_get("/self-host", h_selfhost_page)
    app.router.add_get("/compare", h_compare)
    app.router.add_get("/robots.txt", h_robots)
    app.router.add_get("/blog", h_blog)
    app.router.add_get("/security", h_security)
    app.router.add_post("/admin/s33/selftest", h_s33_selftest)
    app.router.add_get("/blog/{slug}", h_blog_post)
    app.router.add_get("/{name:google[A-Za-z0-9_.-]*\\.html}", h_google_verify_file, name="gverify")
    app.router.add_post("/admin/verify-put", h_verify_put)
    app.router.add_get("/sitemap.xml", h_sitemap)
    app.router.add_get("/api/assist", api_assist)
    app.router.add_post("/api/assist", api_assist)
    app.router.add_get("/admin/assist", h_admin_assist)
    app.router.add_post("/admin/assist", h_admin_assist)
    app.router.add_post("/api/activate", api_activate)
    app.router.add_post("/admin/code", admin_codes)
    app.router.add_get("/checkout", h_checkout_pick)
    app.router.add_get("/checkout/new", h_checkout_new)
    app.router.add_get("/checkout/{ref}", h_invoice_page)
    app.router.add_get("/api/invoice/{ref}", api_invoice)
    app.router.add_get("/admin/invoices", admin_invoices)
    app.router.add_post("/admin/invoice/mark", admin_invoice_mark)
    app.router.add_get("/get", h_get)
    app.router.add_get("/install", h_get)
    app.router.add_route("*", "/upstream", h_upstream)
    app.router.add_get("/upstream/on", h_upstream_switch)
    app.router.add_get("/upstream/off", h_upstream_switch)
    app.router.add_route("*", "/api/upstream", api_upstream)
    app.router.add_post("/api/feedback", api_feedback)
    app.router.add_get("/feedback", h_feedback)
    app.router.add_get("/admin/feedback", h_admin_feedback)
    app.router.add_get("/pricing.json", h_pricing)
    app.router.add_get("/api/workspace", api_workspace)
    app.router.add_route("*", "/api/memory", api_memory)
    app.router.add_get("/authorise", h_authorise)
    app.router.add_get("/authorise/{act}", h_authorise)
    app.router.add_get("/manifest.json", h_manifest)
    app.router.add_get("/.well-known/assetlinks.json", h_assetlinks)
    app.router.add_post("/api/signup", api_signup)
    app.router.add_post("/api/login", api_login)
    app.router.add_post("/api/totp_confirm", api_totp_confirm)
    app.router.add_get("/api/me", api_me)
    app.router.add_post("/api/model", api_model)
    app.router.add_route("*", "/api/chats", api_chats)
    app.router.add_get("/api/chats/{cid}", api_chat_get)
    app.router.add_get("/api/chats/{cid}/since", api_chat_since)
    app.router.add_post("/api/chat", api_chat)
    app.router.add_route("*", "/api/keys", api_keys)
    app.router.add_delete("/api/keys/{prefix}", api_key_delete)
    app.router.add_get("/api/keys/{prefix}", api_key_get_denied)
    app.router.add_post("/api/perms", api_perms)
    app.router.add_post("/api/shell", api_shell)
    app.router.add_get("/api/usage", api_usage)
    app.router.add_post("/api/remember", api_remember)
    app.router.add_get("/api/version", api_version)
    app.router.add_get("/api/memory-info", api_memory_info)
    app.router.add_get("/api/verify", api_verify)
    app.router.add_get("/admin/usage", admin_usage)
    app.router.add_get("/admin/logins", h_admin_logins)
    app.router.add_post("/api/admin/genpass", api_admin_genpass)
    app.router.add_route("*", "/api/plugins", api_plugins)
    app.router.add_route("*", "/api/tasks", api_tasks)
    app.router.add_get("/api/search", api_search)
    app.router.add_route("*", "/api/files", api_files)
    app.router.add_post("/api/publish", api_publish)
    app.router.add_get("/p/{token}", h_published)
    app.router.add_post("/api/upload", api_upload)
    app.router.add_get("/api/workfiles", api_workfiles)
    app.router.add_get("/work/{name}", h_workfile)
    app.router.add_get("/files/{fid}", h_file)
    app.router.add_get("/api/qr", api_qr)
    app.router.add_get("/claim", h_claim)
    app.router.add_post("/api/claim", api_claim)
    app.router.add_post("/api/email_code", api_email_code)
    app.router.add_post("/api/signup_email", api_signup_email)
    app.router.add_post("/api/verify_code", api_verify_code)
    app.router.add_post("/api/login_email", api_login_email)
    app.router.add_post("/api/magic-request", api_magic_request)
    return app

if __name__ == "__main__":
    DBP.parent.mkdir(parents=True, exist_ok=True)
    db().close()
    if getattr(CLI, "new_key", ""):
        c = db()
        row = c.execute("select id,email from users where email=?", (CLI.new_key.strip().lower(),)).fetchone()
        c.close()
        if not row:
            print("no such user:", CLI.new_key); raise SystemExit(2)
        raw, prefix = new_api_key(row["id"], CLI.label)
        print("API KEY for", row["email"], "| label", CLI.label, "| prefix", prefix)
        print(raw)
        print("store it now — it is not recoverable")
        raise SystemExit(0)
    if getattr(CLI, "revoke_key", ""):
        c = db(); n = c.execute("update api_keys set revoked=1 where prefix=?", (CLI.revoke_key.strip(),)).rowcount
        c.commit(); c.close()
        print("revoked", n, "key(s) with prefix", CLI.revoke_key); raise SystemExit(0)
    print(f"{AGENT_NAME} · CHC HARNESS · http://{CLI.host}:{PORT} · db={DBP} · "
          f"model={LLM_MODEL} @ {LLM_URL} · rounds={MAX_ROUNDS}", flush=True)
    if CLI.purge_file_text > 0:
        cut = time.time() - CLI.purge_file_text * 86400
        c = db()
        rows = c.execute("select id, name, created from files where ftext is not null and ftext != ''").fetchall()
        gone = 0
        for r in rows:
            try:
                ts = datetime.datetime.fromisoformat(str(r["created"]).replace("Z", "+00:00")).timestamp()
            except Exception:
                continue
            if ts < cut:
                c.execute("update files set ftext='' where id=?", (r["id"],)); gone += 1
        c.commit(); c.close()
        print("purged text for %d file(s) older than %d day(s)" % (gone, CLI.purge_file_text))
        raise SystemExit(0)
    if CLI.make_user:
        email = CLI.make_user.strip().lower()
        c = db()
        row = c.execute("select id from users where lower(email)=?", (email,)).fetchone()
        if not row:
            salt = secrets.token_hex(8)
            c.execute("insert into users(email,handle,pw,salt,totp,plan,created,verified) values(?,?,?,?,?,?,?,1)",
                      (email, email.split("@")[0], pw_hash(secrets.token_hex(16), salt), salt,
                       secrets.token_hex(10), "free", now()))
            c.commit()
            row = c.execute("select id from users where lower(email)=?", (email,)).fetchone()
            print("created account:", email, flush=True)
        else:
            print("account exists:", email, flush=True)
        tok = secrets.token_urlsafe(24)
        c.execute("insert into magic(token, uid, exp, used) values(?,?,?,0)",
                  (tok, row["id"], int(time.time()) + max(60, CLI.magic_ttl)))
        c.commit(); c.close()
        base = CLI.public_url.rstrip("/") or ("http://%s:%d" % (CLI.host, PORT))
        print("%s/magic?t=%s" % (base, tok), flush=True)
        raise SystemExit(0)
    if CLI.set_password:
        c = db()
        em, pw = set_user_password(c, CLI.set_password, CLI.password)
        c.close()
        print("EMAIL=%s" % em, flush=True)
        print("PASSWORD=%s" % pw, flush=True)
        raise SystemExit(0)
    if CLI.magic_link:
        c = db()
        row = c.execute("select id from users where lower(email) = lower(?)", (CLI.magic_link,)).fetchone()
        if not row:
            print("no such user:", CLI.magic_link); raise SystemExit(2)
        tok = secrets.token_urlsafe(24)
        c.execute("insert into magic(token, uid, exp, used) values(?,?,?,0)",
                  (tok, row["id"], int(time.time()) + max(60, CLI.magic_ttl)))
        c.commit(); c.close()
        base = CLI.public_url.rstrip("/") or ("http://%s:%d" % (CLI.host, PORT))
        print("%s/magic?t=%s" % (base, tok), flush=True)
        raise SystemExit(0)
    _cost_check()   # internal: never sell a plan below what it costs us
    web.run_app(build_app(), host=CLI.host, port=PORT)
