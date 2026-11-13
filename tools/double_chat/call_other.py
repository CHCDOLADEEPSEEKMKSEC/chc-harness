#!/usr/bin/env python3
"""call_other.py — DOUBLE CHAT: type a message into the other chat window and click send.
Usage: say_dg.py /path/to/message.txt
"""
import json, os, sys, time, urllib.request, pathlib, websocket

def tab(port=int(os.environ.get("CHC_CDP_PORT", "9241")), match=os.environ.get("CHC_TARGET", "127.0.0.1:8903")):
    tabs = json.loads(urllib.request.urlopen("http://127.0.0.1:%d/json/list" % port, timeout=10).read())
    for t in tabs:
        if t.get("type") == "page" and match in (t.get("url") or ""):
            return t
    raise SystemExit("no DADDY-G window open on %s" % match)

msg = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
t = tab()
ws = websocket.create_connection(t["webSocketDebuggerUrl"], timeout=20, suppress_origin=True)
def call(i, m, p):
    ws.send(json.dumps({"id": i, "method": m, "params": p}))
    while True:
        r = json.loads(ws.recv())
        if r.get("id") == i: return r

call(1, "Runtime.enable", {})
r = call(2, "Runtime.evaluate", {"expression":
    "(()=>{const t=document.getElementById('q'); if(!t) return 'no'; t.focus(); t.value=''; return 'ok';})()",
    "returnByValue": True})
if r["result"]["result"]["value"] != "ok":
    raise SystemExit("no composer in DADDY-G window")
ws.send(json.dumps({"id": 3, "method": "Input.insertText", "params": {"text": msg}}))
time.sleep(0.3)
call(4, "Runtime.evaluate", {"expression": "document.getElementById('send').click(); 'sent'", "returnByValue": True})
time.sleep(0.3)
ws.close()
print("sent to DADDY-G:", msg.splitlines()[0][:70])
