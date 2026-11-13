#!/usr/bin/env python3
"""call_chc.py — DOUBLE CHAT: type a message into another browser chat window and press Enter.

Used by DADDY-G to call CHC directly in the browser chat window.
  chc_say.py "message"
"""
import json, os, sys, time, urllib.request, websocket

def tab(port=int(os.environ.get("CHC_CDP_PORT", "9241")), match=os.environ.get("CHC_TARGET", "127.0.0.1:3080")):
    tabs = json.loads(urllib.request.urlopen("http://127.0.0.1:%d/json/list" % port, timeout=10).read())
    pages = [t for t in tabs if t.get("type") == "page"]
    for t in pages:
        if match in (t.get("url") or ""):
            return t
    raise SystemExit("no CHC window open (need a tab on %s)" % match)

def send(ws, mid, method, params=None):
    ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
    while True:
        m = json.loads(ws.recv())
        if m.get("id") == mid:
            return m

def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: chc_say.py "message"')
    text = " ".join(sys.argv[1:])
    t = tab()
    ws = websocket.create_connection(t["webSocketDebuggerUrl"], timeout=20, suppress_origin=True)
    send(ws, 1, "Runtime.enable")
    r = send(ws, 2, "Runtime.evaluate", {"expression":
        "(()=>{const ed=document.querySelector('div[contenteditable=true]'); if(!ed) return 'no-composer';"
        "ed.focus(); const s=window.getSelection(); s.removeAllRanges();"
        "const r=document.createRange(); r.selectNodeContents(ed); r.collapse(false); s.addRange(r);"
        "return 'ok';})()", "returnByValue": True})
    if r.get("result", {}).get("result", {}).get("value") != "ok":
        raise SystemExit("could not focus CHC composer")
    ws.send(json.dumps({"id": 3, "method": "Input.insertText", "params": {"text": text}}))
    time.sleep(0.25)
    for typ, codes in (("rawKeyDown", (13, "Enter")), ("keyUp", (13, "Enter"))):
        ws.send(json.dumps({"id": 4 if typ == "rawKeyDown" else 5, "method": "Input.dispatchKeyEvent",
                            "params": {"type": typ, "key": codes[1], "code": codes[1],
                                       "windowsVirtualKeyCode": codes[0], "nativeVirtualKeyCode": codes[0]}}))
        time.sleep(0.15)
    ws.close()
    print("said in CHC's window:", text[:80])

if __name__ == "__main__":
    main()
