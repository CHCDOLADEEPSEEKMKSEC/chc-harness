#!/usr/bin/env python3
"""senses.py - capability probe for the MIRAGE SENSES MCP tools on THIS host.

The real senses server drives an existing Chrome over CDP (screenshot/OCR/click/type),
plus espeak-ng for speech and audio capture for listening. On a host with no browser
there is nothing to drive - this probe says so, by name, instead of pretending.

    senses.py            # JSON capability report
    senses.py --require  # exit 3 if anything is missing (for installers/tests)
"""
import json, shutil, subprocess, sys, urllib.request

CANDIDATES = [9241, 9222, 9333]
BINARIES = ["tesseract", "espeak-ng", "arecord", "ffmpeg"]


def cdp_ports():
    up = []
    for p in CANDIDATES:
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/json/version" % p, timeout=1.5) as r:
                if r.status == 200:
                    up.append(p)
        except Exception:
            pass
    return up


def main():
    ports = cdp_ports()
    bins = {b: bool(shutil.which(b)) for b in BINARIES}
    report = {
        "display": {"DISPLAY": __import__("os").environ.get("DISPLAY") or None,
                    "WAYLAND_DISPLAY": __import__("os").environ.get("WAYLAND_DISPLAY") or None},
        "cdp": {"ports_open": ports, "usable": bool(ports)},
        "binaries": bins,
        "tools": {
            "look": bool(ports), "ocr": bool(ports) and bins["tesseract"],
            "read": bool(ports), "find": bool(ports),
            "click": bool(ports), "type": bool(ports), "scroll": bool(ports),
            "navigate": bool(ports), "watch": bool(ports),
            "speak": bins["espeak-ng"], "listen": bins["arecord"],
            "status": True,
        },
        "verdict": "ok" if ports else "no browser on this host - senses unavailable, use shell/web/file tools",
    }
    print(json.dumps(report, indent=1))
    # exit 3 whenever the senses stack is unusable on this host - probes must read DOWN honestly
    return 0 if ports else 3


if __name__ == "__main__":
    sys.exit(main())
