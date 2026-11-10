#!/usr/bin/env python3
"""Full feature test of CHC HARNESS on this host, as user 5 (errrric). Mints a session cookie
from the app secret so every endpoint can be exercised exactly as the UI does."""
import base64, hashlib, hmac, json, pathlib, re, sqlite3, sys, urllib.request, urllib.error

BASE = "http://127.0.0.1:8895"
SECRET = pathlib.Path("/opt/chc-ai/secret").read_text().strip()
UID = 5
results = []

def sign(payload):
    mac = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(("%s|%s" % (payload, mac)).encode()).decode()

COOKIE = "chc_sess=" + sign("u:%d" % UID)

def req(path, method="GET", body=None, admin=None, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Cookie", COOKIE)
    if data: r.add_header("Content-Type", "application/json")
    if admin: r.add_header("Authorization", "Bearer " + admin)
    try:
        with urllib.request.urlopen(r, timeout=180) as f:
            return f.status, f.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()

def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS " if ok else "FAIL ") + name + ("  " + detail if detail else ""))

# 1 health
s, b = req("/health"); j = json.loads(b or b"{}")
check("health", s == 200 and j.get("ok"), "name=%s version=%s" % (j.get("name"), j.get("version")))

# 2 app page + shell button
s, b = req("/app"); html = (b or b"").decode("utf-8", "replace")
check("app page renders", s == 200 and "id=msgs" in html, "%d bytes" % len(html))
check("SHELL button in UI", "shellbtn" in html and "SHELL" in html)
check("FULL ACCESS chip in UI", "data-perm=full" in html)

# 3 chat create
s, b = req("/api/chats", "POST", {"title": "feature test"})
cid = (json.loads(b or b"{}") or {}).get("id")
check("create chat", s == 200 and bool(cid), str(cid))

# 4 perms full
s, b = req("/api/perms", "POST", {"chat": cid, "perms": "full"})
check("set FULL ACCESS", s == 200 and json.loads(b or b"{}").get("perms") == "full")

# 5 shell endpoint
s, b = req("/api/shell", "POST", {"chat": cid, "cmd": "whoami; id -u; echo CHC_OK"})
out = (json.loads(b or b"{}") or {}).get("out", "")
check("shell returns real output", s == 200 and "CHC_OK" in out, out.replace("\n", " / ")[:80])

# 6 agent chat with tools
s, b = req("/api/chat", "POST", {"chat": cid, "mode": "coding", "perms": "full",
                                 "message": "Run the shell command `whoami` and report exactly what it printed."})
txt = (b or b"").decode("utf-8", "replace")
check("agent chat streams", s == 200 and len(txt) > 0, "%d bytes" % len(txt))
check("agent used a tool", '"tool"' in txt or "tool_call" in txt or "whoami" in txt, txt[:60].replace("\n", " "))

# 7 API keys / billing
s, b = req("/api/keys", "POST", {"email": "errrric@gmail.com", "label": "feature-test"})
kj = json.loads(b or b"{}") or {}
key = kj.get("key") or ""
check("mint API key", s == 200 and key.startswith("chc_"), (kj.get("prefix") or "")[:12])

s, b = req("/api/keys"); kl = json.loads(b or b"{}") or {}
check("list API keys", s == 200 and len(kl.get("keys") or []) >= 1, "%d key(s)" % len(kl.get("keys") or []))

s, b = req("/api/usage"); uj = json.loads(b or b"{}") or {}
check("usage endpoint", s == 200 and ("messages_total" in uj or "keys" in uj), "keys=" + str(list(uj)[:5]))

if key.startswith("chc_"):
    s, b = req("/api/keys/" + key.split("_")[1][:8], "DELETE")
    check("revoke API key", s in (200, 204), "http %d" % s)

# 8 admin usage
adm = ""
try:
    conf = pathlib.Path("/etc/systemd/system/chc-ai.service.d/admin.conf")
    adm = re.search(r"CHC_AI_ADMIN_TOKEN=(\S+)", conf.read_text()).group(1)
except Exception:
    pass
if adm:
    s, b = req("/admin/usage?token=" + adm); check("admin usage page", s == 200, "%d bytes" % len(b or b""))
else:
    check("admin token configured", False, "no CHC_AI_ADMIN_TOKEN in unit file")

# 9 download
s, b = req("/download")
check("download package", s == 200 and (b or b"")[:2] == b"\x1f\x8b", "%d bytes" % len(b or b""))

# 10 plugins catalog honesty
s, b = req("/api/plugins"); pj = json.loads(b or b"{}") or {}
check("plugins catalog", s == 200, str(pj)[:90])


# 11. honesty pin: the attachment rules must keep the "never invent what OCR did not read" clause.
try:
    src = pathlib.Path("/opt/chc-ai/app.py").read_text()
    check("prompt honesty pin (no-pixels clause)", "never invent details OCR did not read" in src,
          "attachment rules still forbid inventing what OCR missed")
except Exception as e:
    check("prompt honesty pin (no-pixels clause)", False, type(e).__name__)

print("\n%d/%d PASS" % (sum(1 for _, ok, _ in results if ok), len(results)))
sys.exit(0 if all(ok for _, ok, _ in results) else 1)
