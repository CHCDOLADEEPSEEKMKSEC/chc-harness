#!/usr/bin/env python3
"""mila_video_test.py — can we make video? One cold GPU cycle, nothing left running.

Flow: create L40 -> boot ComfyUI (held ssh) -> ASK ComfyUI which video nodes exist
      -> fetch the model those nodes need -> animate an existing still -> pull the file
      -> always delete the instance.

Run:  python3 tools/mila_video_test.py [--still PATH] [--frames 14]
Default still: the newest render in ~/Pictures/MILA_ROSE/007_cycle_*.png
Output: ~/Pictures/MILA_ROSE/video_test_<timestamp>.(webp|mp4)
"""
import argparse
import json
import mimetypes
import os
import pathlib
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid

HOME = pathlib.Path.home()
KEY = HOME / ".thunder.key"
SSHKEY = HOME / ".ssh" / "id_ed25519"
OUTDIR = HOME / "Pictures" / "MILA_ROSE"
API = "https://api.thundercompute.com:8443/v1"
TUNNEL_PORT = 8798
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0 Safari/537.36 chc-mila-video/1.0")
RATE_PER_HOUR = 0.79
COMFY_DIR = "~/ComfyUI"
COMFY_PY = "~/ComfyUI/.venv/bin/python"
MODELS = "~/ComfyUI/models"

# image-to-video: one all-in-one checkpoint, no text encoder needed
SVD_CKPT = "svd_xt.safetensors"
# NB: the -xt-1-1 repo is gated (401). This one is open and serves 9.56 GB.
SVD_URL = ("https://huggingface.co/stabilityai/stable-video-diffusion-img2vid-xt/"
           "resolve/main/svd_xt.safetensors")

log_lines = []


def log(m):
    line = f"[{time.strftime('%H:%M:%S')}] {m}"
    print(line, flush=True)
    log_lines.append(line)


def token():
    return KEY.read_text().strip().replace("\r", "").replace("\n", "")


def api(path, body=None, method=None):
    req = urllib.request.Request(
        API + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": "Bearer " + token(), "Content-Type": "application/json",
                 "Accept": "application/json", "User-Agent": UA},
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


def create_instance():
    pub = (SSHKEY.with_suffix(".pub")).read_text().strip()
    log("creating L40 instance...")
    r = api("/instances/create", {"gpu_type": "l40", "num_gpus": 1, "cpu_cores": 8,
                                  "disk_size_gb": 100, "template": "comfy-ui", "public_key": pub})
    if "error" in r:
        raise SystemExit(f"create failed: {r}")
    log(f"create: {json.dumps(r)[:160]}")
    deadline = time.time() + 600
    while time.time() < deadline:
        lst = api("/instances/list")
        if isinstance(lst, dict) and "error" in lst:
            log(f"  api error: {lst}"); time.sleep(10); continue
        if isinstance(lst, dict) and lst:
            k, v = list(lst.items())[0]
            log(f"  status={v.get('status')} ip={v.get('ip')} port={v.get('port')} key={k}")
            if v.get("status") == "RUNNING" and v.get("ip") and v.get("port"):
                return v["ip"], int(v["port"])
        time.sleep(10)
    raise SystemExit("never reached RUNNING")


def delete_instance():
    lst = api("/instances/list")
    if not isinstance(lst, dict) or not lst:
        log("no instance to delete"); return True
    ok = False
    for k, v in list(lst.items()):
        r = api(f"/instances/{k}/delete", {})
        log(f"delete {k}: {json.dumps(r)[:120]}")
        ok = ok or r.get("message") == "Success"
    after = api("/instances/list")
    log(f"instances after delete: {json.dumps(after)[:80]}")
    return ok and (not isinstance(after, dict) or not after)


def wait_ssh(host, port, deadline):
    """Some nodes take minutes before sshd answers; keep trying and say why if we fail."""
    last = ""
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"] + ssh_opts(port) +
                           [f"ubuntu@{host}", "echo ok"], capture_output=True, text=True)
        if p.returncode == 0 and "ok" in p.stdout:
            log(f"  ssh ok after {attempt} attempt(s)")
            return True
        if p.stderr.strip():
            last = p.stderr.strip().splitlines()[-1][:160]
        if attempt % 6 == 0:
            log(f"  still waiting for ssh ({attempt} tries): {last}")
        time.sleep(8)
    log(f"ssh never answered: {last}")
    return False


def start_comfy(host, port):
    for _ in range(60):
        rc, out, _ = sh(host, port, f'ls {COMFY_DIR}/main.py {COMFY_PY} 2>/dev/null | wc -l')
        if out.strip() == "2":
            break
        time.sleep(5)
    log("starting ComfyUI in a held ssh session")
    proc = subprocess.Popen(
        ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=20"] + ssh_opts(port) +
        [f"ubuntu@{host}", f"cd {COMFY_DIR} && exec {COMFY_PY} main.py --listen 127.0.0.1 --port 8188"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 300
    while time.time() < deadline:
        rc, out, _ = sh(host, port, 'curl -s -o /dev/null -w "%{http_code}" -m 5 http://127.0.0.1:8188/system_stats')
        if out.strip().endswith("200"):
            log("  ComfyUI up")
            return proc
        time.sleep(6)
    proc.terminate()
    raise SystemExit("ComfyUI never came up")


def tunnel(host, port):
    log(f"tunnel :{TUNNEL_PORT} -> :8188")
    proc = subprocess.Popen(["ssh", "-N", "-o", "ExitOnForwardFailure=yes"] + ssh_opts(port) +
                            ["-L", f"{TUNNEL_PORT}:127.0.0.1:8188", f"ubuntu@{host}"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{TUNNEL_PORT}/system_stats", timeout=4).read()
            log("  tunnel up")
            return proc
        except Exception:
            time.sleep(2)
    proc.terminate()
    raise SystemExit("tunnel failed")


def comfy(path, obj=None):
    url = f"http://127.0.0.1:{TUNNEL_PORT}" + path
    if obj is None:
        return json.load(urllib.request.urlopen(url, timeout=60))
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=60))
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:1500]
        log(f"  ComfyUI rejected it ({e.code}): {body}")
        raise


def post_multipart(path, fields, filefield, filepath):
    boundary = "----chc" + uuid.uuid4().hex
    body = b""
    for k, v in fields.items():
        body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
    ctype = mimetypes.guess_type(str(filepath))[0] or "application/octet-stream"
    body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{filefield}\"; "
             f"filename=\"{pathlib.Path(filepath).name}\"\r\nContent-Type: {ctype}\r\n\r\n").encode()
    body += pathlib.Path(filepath).read_bytes() + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"http://127.0.0.1:{TUNNEL_PORT}{path}", data=body,
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    return json.load(urllib.request.urlopen(req, timeout=120))


def ensure_svd(host, port):
    log("checking for the image-to-video checkpoint")
    rc, out, _ = sh(host, port, f'ls {MODELS}/checkpoints/{SVD_CKPT} 2>/dev/null && stat -c %s {MODELS}/checkpoints/{SVD_CKPT}')
    if out:
        log(f"  present ({int(out.split()[-1])/1e9:.2f} GB)"); return
    hf = ""
    for cand in [HOME / "chc-studio" / ".env.hf", HOME / ".hf_token",
                 pathlib.Path("/mnt/ledger/vault/keys/hf.env")]:
        if cand.exists():
            for line in cand.read_text().splitlines():
                if "HF" in line and "=" in line:
                    hf = line.split("=", 1)[1].strip().strip('"').strip("'"); break
            if hf: break
    hdr = f'-H "Authorization: Bearer {hf}"' if hf else ""
    log("  downloading svd_xt (~9.56 GB, this is the slow bit)")
    sh(host, port, f'cd {MODELS}/checkpoints && curl -L --retry 3 -s {hdr} -o "{SVD_CKPT}" "{SVD_URL}"',
       timeout=2400)
    rc, out, _ = sh(host, port, f'stat -c %s {MODELS}/checkpoints/{SVD_CKPT} 2>/dev/null')
    size = int(out or 0)
    log(f"  downloaded {size/1e9:.2f} GB")
    if size < 4_000_000_000:
        raise SystemExit("video checkpoint looks short/failed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--still", default=None)
    ap.add_argument("--frames", type=int, default=14)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()

    stills = sorted((HOME / "Pictures" / "MILA_ROSE").glob("007_cycle_*.png"))
    still = pathlib.Path(a.still) if a.still else (stills[-1] if stills else None)
    if not still or not still.exists():
        raise SystemExit("no still to animate — run tools/mila_gpu_cycle.py first")

    OUTDIR.mkdir(parents=True, exist_ok=True)
    t0 = time.time(); host = port = None; comfy_proc = tun = None; created = False
    try:
        pre = api("/instances/list")
        if isinstance(pre, dict) and "error" in pre:
            raise SystemExit(f"pre-flight failed: {pre}")
        if isinstance(pre, dict) and pre:
            raise SystemExit("an instance is already running — refusing")
        host, port = create_instance(); created = True
        if not wait_ssh(host, port, time.time() + 720):
            raise SystemExit("ssh never came up")
        log(f"ssh up {host}:{port}")
        comfy_proc = start_comfy(host, port)
        tun = tunnel(host, port)

        obj = comfy("/object_info")
        names = list(obj.keys())
        log(f"ComfyUI reports {len(names)} node types")
        video = sorted([n for n in names if any(k in n for k in
                       ("SVD", "Video", "Animate", "Wan", "LTX", "SaveAnimated", "SaveWEBM", "SaveVideo"))])
        log("video-capable nodes: " + (", ".join(video) if video else "NONE FOUND"))

        need = ["ImageOnlyCheckpointLoader", "SVD_img2vid_Conditioning", "VideoLinearCFGGuidance", "KSampler"]
        missing = [n for n in need if n not in names]
        if missing:
            log("MISSING core nodes: " + ", ".join(missing))
            raise SystemExit("this ComfyUI build cannot do SVD img2vid")
        log("SVD img2vid node stack present")

        ensure_svd(host, port)

        log(f"uploading still: {still.name}")
        up = post_multipart("/upload/image", {"overwrite": "true", "type": "input"}, "image", still)
        img_name = up.get("name") or still.name
        log(f"  uploaded as {img_name}")

        saver = next((n for n in ("SaveAnimatedWEBP", "SaveAnimatedPNG", "SaveWEBM", "SaveVideo") if n in names), None)
        if not saver:
            raise SystemExit("no animation-saving node available")
        log(f"saver: {saver}")
        prefix = "mila_video_" + time.strftime("%H%M%S")
        saver_inputs = {"filename_prefix": prefix}
        if saver == "SaveAnimatedWEBP":
            saver_inputs.update({"fps": 6, "lossless": False, "quality": 85, "method": "default"})
        elif saver in ("SaveWEBM", "SaveVideo"):
            saver_inputs.update({"fps": 6, "codec": "vp9"})
        saver_inputs["images"] = ["10", 0]

        wf = {
            "1": {"class_type": "ImageOnlyCheckpointLoader", "inputs": {"ckpt_name": SVD_CKPT}},
            "2": {"class_type": "LoadImage", "inputs": {"image": img_name, "upload": "image"}},
            "3": {"class_type": "SVD_img2vid_Conditioning",
                  "inputs": {"width": 576, "height": 1024, "video_frames": a.frames,
                             "motion_bucket_id": 127, "fps": 6, "augmentation_level": 0.0,
                             "clip_vision": ["1", 1], "init_image": ["2", 0], "vae": ["1", 2]}},
            "4": {"class_type": "VideoLinearCFGGuidance", "inputs": {"min_cfg": 1.0, "model": ["1", 0]}},
            "5": {"class_type": "KSampler",
                  "inputs": {"seed": 4242, "steps": 20, "cfg": 2.5, "sampler_name": "euler",
                             "scheduler": "karras", "denoise": 1.0, "model": ["4", 0],
                             "positive": ["3", 0], "negative": ["3", 1], "latent_image": ["3", 2]}},
            "6": {"class_type": "VAEDecode", "inputs": {"samples": ["5", 0], "vae": ["1", 2]}},
            "7": {"class_type": saver, "inputs": {**saver_inputs, "images": ["6", 0]}},
        }
        log("queueing img2vid")
        pid = comfy("/prompt", {"prompt": wf, "client_id": "mila-video"})["prompt_id"]
        out_file = None
        deadline = time.time() + 600
        while time.time() < deadline:
            h = comfy("/history/" + pid)
            if pid in h:
                entry = h[pid]
                if entry.get("status", {}).get("status_str") == "error":
                    log("WORKFLOW ERROR: " + json.dumps(entry.get("status"))[:600])
                    break
                outs = entry.get("outputs") or {}
                if outs:
                    for node, payload in outs.items():
                        for key in ("images", "gifs", "videos"):
                            for item in payload.get(key, []) or []:
                                q = urllib.parse.urlencode({"filename": item["filename"],
                                                            "subfolder": item.get("subfolder", ""),
                                                            "type": item.get("type", "output")})
                                data = urllib.request.urlopen(
                                    f"http://127.0.0.1:{TUNNEL_PORT}/view?" + q, timeout=120).read()
                                ext = pathlib.Path(item["filename"]).suffix or ".webp"
                                out_file = OUTDIR / f"video_test_{time.strftime('%H%M%S')}{ext}"
                                out_file.write_bytes(data)
                                break
                            if out_file: break
                        if out_file: break
                    break
            time.sleep(3)
        if out_file:
            log(f"VIDEO OK -> {out_file} ({out_file.stat().st_size/1024:.0f} KB)")
        else:
            log("no video produced")
    finally:
        if tun: tun.terminate()
        if comfy_proc: comfy_proc.terminate()
        if created and not a.keep:
            log("deleting the instance (money off)")
            delete_instance()
        mins = (time.time() - t0) / 60
        log(f"total {mins:.1f} min ≈ ${mins/60*RATE_PER_HOUR:.2f}")
        (OUTDIR / "video_test_last.log").write_text("\n".join(log_lines) + "\n")


if __name__ == "__main__":
    main()
