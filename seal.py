#!/usr/bin/env python3
"""SEAL — Signed Evidence & Audit Ledger (CHCFLASH33 · CYBER SECURITY UNIT)
Append-only, hash-chained, Ed25519-signed receipts for things that matter:
bet slips, deploys, audit findings, operator decisions.

  seal.py init                                  create keypair + genesis
  seal.py append --kind KIND --subject TEXT [--data JSON]
  seal.py verify [--chain PATH]                 walk chain: continuity + signatures
  seal.py list [--limit N]
  seal.py root                                  merkle root of current chain
  seal.py export [--out PATH]
"""
import argparse, base64, hashlib, json, os, sys, time, datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

ROOT = os.environ.get("CHC_SEAL_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHAIN = os.path.join(ROOT, "receipts", "chain.jsonl")
KEYS = os.path.join(ROOT, "keys")
KEY = os.path.join(KEYS, "seal_ed25519.key")
PUB = os.path.join(KEYS, "seal_ed25519.pub")
ANCHORS = os.path.join(ROOT, "receipts", "anchors.jsonl")

def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def sha(b): return hashlib.sha256(b).hexdigest()

def init():
    os.makedirs(os.path.dirname(CHAIN), exist_ok=True)
    if os.path.exists(KEY) and os.path.exists(CHAIN):
        print("already initialised"); return
    sk = Ed25519PrivateKey.generate()
    open(KEY, "wb").write(sk.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(KEY, 0o600)
    open(PUB, "wb").write(sk.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    open(CHAIN, "w").close()
    append("genesis", "SEAL chain created", {"division": "RND:WORKSHOP:CYBER:SECURITY:AUDITandSECURE",
                                             "pubkey": pub_hex()})
    print(f"initialised · pubkey {pub_hex()}")

def pub_hex():
    if not os.path.exists(PUB): return None
    p = serialization.load_pem_public_key(open(PUB, "rb").read())
    return p.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

def last():
    if not os.path.exists(CHAIN): return None
    lastr = None
    for line in open(CHAIN):
        line = line.strip()
        if line:
            try: lastr = json.loads(line)
            except Exception: pass
    return lastr

def append(kind, subject, data=None):
    r = last()
    seq = (r["seq"] + 1) if r else 0
    prev = sha(canon(r)) if r else "0" * 64
    body = {"seq": seq, "ts": int(time.time()),
            "ts_iso": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "kind": kind, "subject": subject,
            "payload_sha256": sha(canon(data or {})),
            "data": data or {}, "prev": prev}
    rbody = {k: body[k] for k in ("seq","ts","kind","subject","payload_sha256","prev")}
    sk = serialization.load_pem_private_key(open(KEY, "rb").read(), password=None)
    sig = sk.sign(canon(rbody)).hex()
    body["sig"] = sig
    with open(CHAIN, "a") as f: f.write(json.dumps(body, sort_keys=True) + "\n")
    return body

def chain():
    out = []
    if os.path.exists(CHAIN):
        for line in open(CHAIN):
            line = line.strip()
            if line:
                try: out.append(json.loads(line))
                except Exception: pass
    return out

def verify():
    if not os.path.exists(CHAIN):
        print("❌ NO CHAIN at %s — nothing was read (wrong directory? point --root at the vault)" % CHAIN)
        return 2
    rows = chain()
    if not rows:
        print("❌ CHAIN IS EMPTY at %s (file exists, zero receipts)" % CHAIN)
        return 2
    if not os.path.exists(PUB):
        print("❌ NO PUBLIC KEY at %s — cannot verify signatures" % PUB)
        return 2
    pub = serialization.load_pem_public_key(open(PUB, "rb").read())
    prev = "0" * 64
    for i, r in enumerate(rows):
        rbody = {k: r[k] for k in ("seq","ts","kind","subject","payload_sha256","prev")}
        if r["seq"] != i: print(f"❌ seq break at {i} (got {r['seq']})"); return 1
        if r["prev"] != prev: print(f"❌ prev-hash break at {i}"); return 1
        try: pub.verify(bytes.fromhex(r["sig"]), canon(rbody))
        except Exception: print(f"❌ bad signature at {i}"); return 1
        prev = sha(canon(r))
    print(f"✅ chain VERIFIED — {len(rows)} receipts · head {prev[:32]}… · merkle {merkle_root()[:32]}…")
    print("   (head = sha256 of last receipt; merkle = tree root over all receipts)")
    return 0

def _leaf(r): return sha(canon(r))

def _build_layers():
    leaves = [_leaf(r) for r in chain()]
    layers = [leaves]
    while len(layers[-1]) > 1:
        cur = layers[-1]
        if len(cur) % 2: cur = cur + [cur[-1]]
        layers.append([sha(bytes.fromhex(cur[i]) + bytes.fromhex(cur[i+1])) for i in range(0, len(cur), 2)])
    return layers

def proof(seq):
    layers = _build_layers()
    if not layers[0]: return None
    if seq < 0 or seq >= len(layers[0]): return None
    path = []
    idx = seq
    for layer in layers[:-1]:
        if idx % 2: sibling = idx - 1
        else: sibling = idx + 1 if idx + 1 < len(layer) else idx
        path.append({"pos": "left" if idx % 2 else "right", "hash": layer[sibling]})
        idx //= 2
    return {"seq": seq, "leaf": layers[0][seq], "root": layers[-1][0], "path": path,
            "count": len(layers[0]), "pubkey": pub_hex()}

def verify_proof(p):
    h = p["leaf"]
    for step in p["path"]:
        sib = bytes.fromhex(step["hash"])
        if step["pos"] == "left":
            h = sha(sib + bytes.fromhex(h))
        else:
            h = sha(bytes.fromhex(h) + sib)
    return h == p["root"]

def merkle_root():
    rows = chain()
    if not rows: return "0"*64
    layer = [sha(canon(r)) for r in rows]
    while len(layer) > 1:
        if len(layer) % 2: layer.append(layer[-1])
        layer = [sha(bytes.fromhex(layer[i]) + bytes.fromhex(layer[i+1])) for i in range(0, len(layer), 2)]
    return layer[0]

def anchor(tsa="freetsa"):
    """RFC3161 timestamp of the current Merkle root (third-party proof of existence)."""
    import subprocess, tempfile
    root = merkle_root(); rows = chain()
    ts = int(time.time())
    base = os.path.join(ROOT, "receipts", "anchors")
    os.makedirs(base, exist_ok=True)
    q = os.path.join(base, f"{ts}.tsq"); r = os.path.join(base, f"{ts}.tsr")
    payload = os.path.join(base, f"{ts}.txt")
    open(payload, "w").write(f"{root}\ncount={len(rows)}\nts={ts}\n")
    subprocess.run(["openssl","ts","-query","-data",payload,"-sha256","-cert","-out",q], check=True, capture_output=True)
    url = "https://freetsa.org/tsr" if tsa == "freetsa" else "https://freetsa.org/tsr"
    cp = subprocess.run(["curl","-s","--data-binary","@"+q,"-H","Content-Type: application/timestamp-query",
                         "--max-time","30",url,"-o",r], capture_output=True)
    if cp.returncode != 0 or not os.path.exists(r) or os.path.getsize(r) == 0:
        print("❌ TSA request failed:", cp.stderr[:200]); return 1
    cacert = os.path.join(base, "freetsa.cacert.pem")
    v = subprocess.run(["openssl","ts","-verify","-in",r,"-queryfile",q,"-CAfile",cacert,"-untrusted",cacert],
                       capture_output=True, text=True)
    ok = (v.returncode == 0)
    rec = {"ts": ts, "root": root, "count": len(rows), "tsa": tsa,
           "tsq": os.path.basename(q), "tsr": os.path.basename(r), "verified": ok,
           "tsa_output": (v.stdout or v.stderr)[:300]}
    with open(os.path.join(ROOT, "receipts", "anchors.jsonl"), "a") as f:
        f.write(json.dumps(rec) + "\n")
    print(("✅ anchored" if ok else "⚠️ anchored but verify failed") + f" · {tsa} · root {root[:24]}… · {len(rows)} receipts")
    return 0

def anchors():
    p = os.path.join(ROOT, "receipts", "anchors.jsonl")
    if not os.path.exists(p): return []
    out = []
    for line in open(p):
        line = line.strip()
        if line:
            try:
                r = json.loads(line)
                r.setdefault("tsa", "legacy")
                r.setdefault("verified", None)
                out.append(r)
            except Exception: pass
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["init","append","verify","list","root","export","anchor","anchors","prove","verify-proof"])
    ap.add_argument("--kind", default="note"); ap.add_argument("--subject", default="")
    ap.add_argument("--data", default="{}"); ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--out", default=None); ap.add_argument("--seq", type=int, default=0); ap.add_argument("--file", default=None)
    a = ap.parse_args()
    if a.cmd == "init": init()
    elif a.cmd == "append":
        data = json.loads(a.data) if a.data else {}
        r = append(a.kind, a.subject or "(no subject)", data)
        print(json.dumps({k: r[k] for k in ("seq","kind","subject","sig")}, indent=1))
        # AUTO-PUBLISH: a sealed receipt is pushed to every unit copy + the public verifier at once.
        # Runs only where the house vault lives; quiet; never blocks the seal if it fails.
        if os.path.exists(os.path.join(ROOT, "tools", "publish_chain.sh")):
            # A swallowed fanout failure is worse than a failed fanout: the receipt is safe on disk
            # but the world's copies silently drift. Surface it loudly and exit nonzero.
            import subprocess as _sp
            _pub = _sp.run(["bash", os.path.join(ROOT, "tools", "publish_chain.sh")],
                           capture_output=True, text=True, timeout=180)
            if _pub.returncode != 0:
                print(f"\n!! PUBLISH FAILED (exit {_pub.returncode}) — receipt is on disk locally, "
                      f"but the published copies did NOT update.", file=sys.stderr)
                for line in (_pub.stderr or _pub.stdout or "").strip().splitlines()[-6:]:
                    print(f"   publish: {line}", file=sys.stderr)
                print("   check: master/CHAIN_PUBLISH_LOG.md and tools/publish_chain.sh", file=sys.stderr)
                raise SystemExit(3)
    elif a.cmd == "verify": sys.exit(verify())
    elif a.cmd == "root":
        print(merkle_root())   # read-only (fixed 10 Nov 2026, DADDY audit); anchoring lives in `anchor`
    elif a.cmd == "list":
        for r in chain()[-a.limit:]:
            print(f"[{r['seq']}] {r['ts_iso'][:19]} {r['kind']:<12} {r['subject'][:80]}")
    elif a.cmd == "anchor":
        sys.exit(anchor(a.kind if a.kind != "note" else "freetsa"))
    elif a.cmd == "anchors":
        for x in anchors(): print(f"[{x['ts']}] {x.get('tsa','?')} root {x.get('root','')[:24]}… count {x.get('count','?')} verified={x.get('verified')}")
    elif a.cmd == "prove":
        p = proof(a.seq)
        if not p: print("no such receipt"); sys.exit(1)
        out = a.out or os.path.join(ROOT, "receipts", f"proof_{a.seq}.json")
        json.dump(p, open(out, "w"), indent=1)
        print(("✅ proof valid" if verify_proof(p) else "❌ proof invalid") + f" · seq {a.seq} · written {out}")
    elif a.cmd == "verify-proof":
        p = json.load(open(a.file or a.out))
        print("✅ inclusion proof VERIFIED" if verify_proof(p) else "❌ proof INVALID")
    elif a.cmd == "export":
        out = a.out or os.path.join(ROOT, "receipts", "export.json")
        rows = []
        for r in chain():
            rr = dict(r); rr["hash"] = sha(canon(r))
            rows.append(rr)
        json.dump({"pubkey": pub_hex(), "chain": rows, "root": merkle_root(), "anchors": anchors(),
                   "hash_formula": "sha256(canonical_json(receipt)) — canonical = json.dumps(sort_keys=True, separators=(',',':'))",
                   "prev_rule": "receipt[i].prev == receipt[i-1].hash ; genesis prev = 64 zeros",
                   "exported": int(time.time())},
                  open(out, "w"), indent=1)
        print("exported:", out)

if __name__ == "__main__": main()
