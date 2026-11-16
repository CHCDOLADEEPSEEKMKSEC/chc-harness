#!/usr/bin/env python3
"""gpu_guard.py — the orphan police for our hired L40.

Why this exists: on 16 Nov a GPU cycle was started with `nohup` inside a wrapper shell. The wrapper
was reaped, the cycle died at "GPU up", and the instance kept running and billing (~8 min ≈ $0.10)
until a human noticed. A finally-block cannot save you if the process is killed.

Rule: an instance is legitimate only while a render process that owns it is alive. Anything older than
CHC_GPU_MAX_MIN minutes with no live owner gets deleted. Run from a timer every 5 minutes.
"""
import json, os, pathlib, subprocess, sys, time, urllib.request

KEY = pathlib.Path.home() / ".thunder.key"
API = "https://api.thundercompute.com:8443/v1"
MAX_MIN = float(os.environ.get("CHC_GPU_MAX_MIN", "30"))
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0 Safari/537.36 chc-gpu-guard/1.0")
LOG = pathlib.Path.home() / "chc-dev" / "gpu_guard.log"


def say(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with LOG.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def api(path, body=None):
    if not KEY.exists():
        say("no key file - nothing I can do")
        sys.exit(1)
    req = urllib.request.Request(API + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": "Bearer " + KEY.read_text().strip(),
                 "Content-Type": "application/json", "Accept": "application/json", "User-Agent": UA},
        method="POST" if body is not None else "GET")
    try:
        return json.load(urllib.request.urlopen(req, timeout=60))
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode()[:200], "code": e.code}
    except Exception as e:
        return {"transport": str(e)[:200]}


def owners_alive():
    """is any gpu_img.py / video_gpu.py process running right now?"""
    try:
        out = subprocess.run(["pgrep", "-fc", "gpu_img.py|video_gpu.py|mila_gpu_cycle.py|mila_video_test.py"],
                             capture_output=True, text=True).stdout.strip()
        return int(out or 0) > 0
    except Exception:
        return True          # if we cannot tell, do not delete


def main():
    live = api("/instances/list") or {}
    if not isinstance(live, dict) or "error" in live:
        say(f"list failed: {str(live)[:160]}")
        return
    if not live:
        return                      # nothing running, nothing to police
    owner = owners_alive()
    now = time.time()
    for k, v in live.items():
        age_min = 0.0
        try:
            ts = v.get("createdAt", "")
            age_min = (now - time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))) / 60.0
        except Exception:
            pass
        name = v.get("name")
        if age_min > MAX_MIN:
            say(f"DELETING {name} ({k}) - {age_min:.0f} min old, over the {MAX_MIN:.0f} min cap")
            say(f"  result: {api('/instances/%s/delete' % k, {})}")
        elif not owner:
            say(f"DELETING {name} ({k}) - {age_min:.0f} min old and NO render process owns it (orphan)")
            say(f"  result: {api('/instances/%s/delete' % k, {})}")
        else:
            say(f"keeping {name} ({k}) - {age_min:.1f} min old, owner alive")
    time.sleep(3)
    after = api("/instances/list") or {}
    say("after: " + ("EMPTY - nothing billing" if not after else "STILL RUNNING " + str(list(after.keys()))))


if __name__ == "__main__":
    main()
