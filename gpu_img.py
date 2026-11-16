#!/usr/bin/env python3
"""mila_gpu_cycle.py — end-to-end proof of the Mila Rose picture pipeline, unattended.

  create GPU  ->  boot ComfyUI  ->  ensure checkpoint  ->  render  ->  pull frames back
              ->  ALWAYS delete the instance (finally block)  ->  report time + cost

Run:      python3 tools/mila_gpu_cycle.py [--renders N] [--keep]
  --renders N   how many frames (default 3)
  --keep        do NOT delete the instance at the end (for debugging; bills by the hour!)

Everything it needs is local: Thunder token in ~/.thunder.key, SSH key ~/.ssh/id_ed25519,
Hugging Face token from the env files if a checkpoint download is needed.
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HOME = pathlib.Path.home()
KEY = HOME / ".thunder.key"
SSHKEY = HOME / ".ssh" / "id_ed25519"
OUTDIR = HOME / "Pictures" / "MILA_ROSE"
API = "https://api.thundercompute.com:8443/v1"
TUNNEL_PORT = 8788
CKPT = "RealVisXL_V4.0.safetensors"
CKPT_URL = ("https://huggingface.co/SG161222/RealVisXL_V4.0/resolve/main/"
            "RealVisXL_V4.0.safetensors")
RATE_PER_HOUR = 0.79  # L40 x1, as billed on 15 Nov
COMFY_DIR = "~/ComfyUI"
COMFY_PY = "~/ComfyUI/.venv/bin/python"  # template ships the venv; torch 2.12.1+cu130 lives there
NEG = ("(worst quality, low quality:1.4), blurry, deformed, extra limbs, bad hands, watermark, "
       "signature, text, plastic skin, cartoon, anime, doll-like, heavy makeup, child, minor")
IDENTITY = ("RAW photo of a 24 year old British woman, dark auburn hair messy past her jaw, green eyes, "
            "freckles, small silver nose ring, thin gold chain, natural skin texture, film grain, "
            "50mm f2 photograph")
LOOKS = ["black leather jacket, black cropped top, leaning in a doorway, red lipstick",
         "red slip dress, sitting on a record shelf, warm lamp light, cheeky smile",
         "oversized cream knit jumper, sitting on the edge of an unmade bed, dusk lamp"]

log_lines = []


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    log_lines.append(line)


def token():
    return (KEY.read_text()).strip().replace("\r", "").replace("\n", "")


def api(path, body=None, method=None):
    req = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": "Bearer " + token(), "Content-Type": "application/json",
                 "Accept": "application/json",
                 "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                               "(KHTML, like Gecko) Chrome/131.0 Safari/537.36 chc-mila-cycle/1.0"},
        method=method or ("POST" if body is not None else "GET"))
    last = None
    for attempt in range(4):
        try:
            return json.load(urllib.request.urlopen(req, timeout=60))
        except urllib.error.HTTPError as e:
            return {"error": e.read().decode()[:300], "code": e.code}
        except Exception as e:                      # connection resets / remote closed
            last = e
            time.sleep(4 * (attempt + 1))
    return {"error": f"transport: {last}"}


def ssh_opts(port):
    return ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "IdentitiesOnly=yes", "-i", str(SSHKEY), "-p", str(port)]


def sh(host, port, cmd, timeout=600):
    p = subprocess.run(["ssh", "-n", "-o", "BatchMode=yes"] + ssh_opts(port) + [f"ubuntu@{host}", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def wait_ssh(host, port, deadline):
    while time.time() < deadline:
        p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6"] + ssh_opts(port) +
                           [f"ubuntu@{host}", "echo ok"], capture_output=True, text=True)
        if p.returncode == 0 and "ok" in p.stdout:
            return True
        time.sleep(5)
    return False


def create_instance():
    pub = (SSHKEY.with_suffix(".pub")).read_text().strip()
    log("creating L40 instance (template comfy-ui)...")
    r = api("/instances/create", {"gpu_type": "l40", "num_gpus": 1, "cpu_cores": 8,
                                  "disk_size_gb": 100, "template": "comfy-ui", "public_key": pub})
    if "error" in r:
        raise SystemExit(f"create failed: {r}")
    log(f"create response: {json.dumps(r)[:200]}")
    deadline = time.time() + 600
    while time.time() < deadline:
        lst = api("/instances/list")
        if isinstance(lst, dict) and "error" in lst:
            log(f"  api error while polling: {lst}")
            time.sleep(10); continue
        if isinstance(lst, dict) and lst:
            k, v = list(lst.items())[0]
            log(f"  status={v.get('status')} ip={v.get('ip')} ssh_port={v.get('port')} key={k}")
            if v.get("status") == "RUNNING" and v.get("ip") and v.get("port"):
                return v["ip"], int(v["port"]), k
        elif isinstance(lst, dict):
            log("  instance list empty — waiting for provisioning...")
        time.sleep(10)
    raise SystemExit("instance never reached RUNNING")


def delete_instance():
    """Delete by the LIST KEY (uuid 404s: 'not supported for deletion')."""
    lst = api("/instances/list")
    if not isinstance(lst, dict) or not lst:
        log("no instance to delete")
        return False
    ok = False
    for k, v in list(lst.items()):
        r = api(f"/instances/{k}/delete", {})
        log(f"delete {k} ({v.get('uuid')}): {json.dumps(r)[:160]}")
        ok = ok or r.get("message") == "Success"
    after = api("/instances/list")
    log(f"instances after delete: {json.dumps(after)[:120]}")
    return ok and (not isinstance(after, dict) or not after)


def ensure_comfy(host, port):
    """Hold a live ssh session running ComfyUI in the foreground.

    Backgrounding it over ssh was unreliable (process died with the channel), and holding the
    session open costs nothing — the instance is deleted at the end anyway.
    """
    log("waiting for the template's ComfyUI tree...")
    for _ in range(60):
        rc, out, _ = sh(host, port, f'ls {COMFY_DIR}/main.py {COMFY_PY} 2>/dev/null | wc -l')
        if out.strip() == "2":
            break
        time.sleep(5)
    else:
        raise SystemExit("ComfyUI tree never appeared on the instance")

    log(f"starting ComfyUI in a held ssh session (interpreter {COMFY_PY})")
    proc = subprocess.Popen(
        ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=20"] + ssh_opts(port) +
        [f"ubuntu@{host}", f"cd {COMFY_DIR} && exec {COMFY_PY} main.py --listen 127.0.0.1 --port 8188"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 300
    while time.time() < deadline:
        rc, out, _ = sh(host, port, 'curl -s -o /dev/null -w "%{http_code}" -m 5 http://127.0.0.1:8188/system_stats')
        if out.strip().endswith("200"):
            log(f"  ComfyUI answering 200 after {int(time.time() - (deadline - 300))}s")
            return proc
        time.sleep(6)
    proc.terminate()
    rc, ver, _ = sh(host, port, "ls /tmp/comfy.log 2>/dev/null && tail -20 /tmp/comfy.log")
    log("diagnostics: " + ver)
    raise SystemExit("ComfyUI never came up")


def ensure_checkpoint(host, port):
    log(f"checking checkpoint {CKPT}...")
    rc, out, _ = sh(host, port, f'ls ~/ComfyUI/models/checkpoints | grep -c "{CKPT}" || true')
    if out.strip() not in ("", "0"):
        log("  present")
        return
    log("  missing — downloading from Hugging Face (~6.3 GB)")
    hf = ""
    for cand in [HOME / "chc-studio" / ".env.hf", HOME / ".hf_token",
                 pathlib.Path("/mnt/ledger/vault/keys/hf.env")]:
        if cand.exists():
            for line in cand.read_text().splitlines():
                if "HF" in line and "=" in line:
                    hf = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break
    if not hf:
        hf = os.environ.get("HF_TOKEN", "")
    hdr = f'-H "Authorization: Bearer {hf}"' if hf else ""
    sh(host, port,
       f'cd ~/ComfyUI/models/checkpoints && curl -L --retry 3 {hdr} -o "{CKPT}" "{CKPT_URL}"',
       timeout=1800)
    rc, out, _ = sh(host, port, f'ls -la ~/ComfyUI/models/checkpoints/{CKPT} | awk "{{print \\$5}}"')
    if int(out or 0) < 6_000_000_000:
        raise SystemExit(f"checkpoint download looks short: {out} bytes")
    log(f"  downloaded {int(out)/1e9:.2f} GB")


def start_tunnel(host, port):
    log(f"opening tunnel 127.0.0.1:{TUNNEL_PORT} -> {host}:8188")
    proc = subprocess.Popen(
        ["ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15"] +
        ssh_opts(port) + ["-L", f"{TUNNEL_PORT}:127.0.0.1:8188", f"ubuntu@{host}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{TUNNEL_PORT}/system_stats", timeout=4).read()
            log("  tunnel up")
            return proc
        except Exception:
            time.sleep(2)
    proc.terminate()
    raise SystemExit("tunnel did not come up")


OUT_PATH = None


def render(prompt, seed, base):
    wf = {
        "1": {"class_type": "CheckpointLoaderSimple", "inputs": {"ckpt_name": CKPT}},
        "2": {"class_type": "CLIPTextEncode", "inputs": {"text": prompt, "clip": ["1", 1]}},
        "3": {"class_type": "CLIPTextEncode", "inputs": {"text": NEG, "clip": ["1", 1]}},
        "4": {"class_type": "EmptyLatentImage", "inputs": {"width": 832, "height": 1216, "batch_size": 1}},
        "5": {"class_type": "KSampler", "inputs": {"seed": seed, "steps": 32, "cfg": 5.5,
              "sampler_name": "dpmpp_2m", "scheduler": "karras", "denoise": 1.0, "model": ["1", 0],
              "positive": ["2", 0], "negative": ["3", 0], "latent_image": ["4", 0]}},
        "6": {"class_type": "VAEDecode", "inputs": {"samples": ["5", 0], "vae": ["1", 2]}},
        "7": {"class_type": "SaveImage", "inputs": {"filename_prefix": "mila_cycle", "images": ["6", 0]}},
    }
    req = urllib.request.Request(base + "/prompt", data=json.dumps({"prompt": wf, "client_id": "cycle"}).encode(),
                                 headers={"Content-Type": "application/json"})
    pid = json.load(urllib.request.urlopen(req, timeout=60))["prompt_id"]
    for _ in range(120):
        h = json.load(urllib.request.urlopen(base + "/history/" + pid, timeout=60))
        if pid in h and h[pid].get("outputs"):
            img = h[pid]["outputs"]["7"]["images"][0]
            q = urllib.parse.urlencode({"filename": img["filename"],
                                        "subfolder": img.get("subfolder", ""), "type": "output"})
            data = urllib.request.urlopen(base + "/view?" + q, timeout=120).read()
            p = pathlib.Path(OUT_PATH) if OUT_PATH else (OUTDIR / f"007_cycle_{seed}.png")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            return p, len(data)
        time.sleep(2)
    raise TimeoutError("render timed out")


def stage(pct, text):
    print(f"STAGE {pct} {text}", flush=True)
    log(f"[{pct}%] {text}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--renders", type=int, default=3)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--prompt", default=None, help="render this prompt (default: the Mila look list)")
    ap.add_argument("--out", default=None, help="write the PNG here")
    a = ap.parse_args()
    global OUT_PATH
    OUT_PATH = a.out

    OUTDIR.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    host = port = key = None
    tunnel = None
    comfy = None
    created = False
    try:
        pre = api("/instances/list")
        if isinstance(pre, dict) and pre and "error" in pre:
            raise SystemExit(f"pre-flight failed: {json.dumps(pre)[:200]}")
        if isinstance(pre, dict) and pre:
            raise SystemExit(f"refusing to start: an instance is already running ({json.dumps(pre)[:120]})")
        stage(5, "booting a GPU")
        host, port, key = create_instance()
        stage(15, "GPU up")
        created = True
        if not wait_ssh(host, port, time.time() + 300):
            raise SystemExit("ssh never came up")
        log(f"ssh up on {host}:{port}")
        stage(25, "starting the renderer")
        comfy = ensure_comfy(host, port)
        stage(40, "renderer up")
        stage(45, "loading the model")
        ensure_checkpoint(host, port)
        stage(70, "model ready")
        tunnel = start_tunnel(host, port)
        base = f"http://127.0.0.1:{TUNNEL_PORT}"
        made = []
        if a.prompt:
            stage(80, "painting your image")
            seed = int(time.time()) % 900000 + 100000
            p, n = render(a.prompt.strip()[:900], seed, base)
            if a.out:
                dst = pathlib.Path(a.out); dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(p.read_bytes()); p = dst
            log(f"  -> {p} {n/1024:.0f} KB")
            made.append(str(p))
            stage(98, "saving")
        else:
            for i in range(a.renders):
                seed = 400000 + i * 7
                prompt = IDENTITY + ", " + LOOKS[i % len(LOOKS)]
                log(f"render {i+1}/{a.renders} seed={seed}")
                p, n = render(prompt, seed, base)
                log(f"  -> {p.name} {n/1024:.0f} KB")
                made.append(str(p))
        log(f"rendered {len(made)} frame(s)")
    finally:
        if tunnel:
            tunnel.terminate()
            log("tunnel closed")
        if comfy:
            comfy.terminate()
            log("comfy ssh session closed")
        if created and not a.keep:
            log("deleting the instance (money off)")
            delete_instance()
            stage(100, "done — GPU deleted")
        elif created:
            log("!! --keep given: INSTANCE LEFT RUNNING AND BILLING !!")
        mins = (time.time() - t0) / 60
        log(f"total wall time {mins:.1f} min -> approx ${mins/60*RATE_PER_HOUR:.2f} of GPU time")
        (OUTDIR / "cycle_last_run.log").write_text("\n".join(log_lines) + "\n")


if __name__ == "__main__":
    main()
