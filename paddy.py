#!/usr/bin/env python3
"""paddy.py - browser operator capability probe for THIS host.

paddy drives a real Chrome over CDP (navigate/scroll/click/type with real input events).
No browser on this host means nothing to drive - this says so and exits 3 (honest DOWN),
never a fake OK.

    paddy.py profiles     # JSON capability report
    paddy.py --require    # exit 3 when unusable
"""
import json, sys, urllib.request

PORTS = [9241, 9222, 9333]


def cdp():
    for p in PORTS:
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/json/version" % p, timeout=1.5) as r:
                if r.status == 200:
                    return p, json.load(r).get("Browser", "")
        except Exception:
            pass
    return None, ""


def main():
    port, browser = cdp()
    ok = bool(port)
    print(json.dumps({
        "ok": ok,
        "cdp_port": port,
        "browser": browser,
        "profiles": [] if not ok else ["default"],
        "tools": {t: ok for t in ("navigate", "scroll", "click", "type", "tabs", "screenshot")},
        "reason": "" if ok else "no Chrome/CDP on this host - browser tools unavailable here",
    }, indent=1))
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())
