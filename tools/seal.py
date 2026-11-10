#!/usr/bin/env python3
"""seal.py - append-only, hash-linked, ed25519-signed receipts (canonical CHC format).

Fields: seq, ts (unix), ts_iso, kind, subject, payload_sha256, data, prev, sig
  prev = sha256(canon(previous receipt)); genesis prev = 64 zeros
  sig  = ed25519( canon({seq,ts,kind,subject,payload_sha256,prev}) )

Usage:
  seal.py append --kind note|finding|correction|milestone --subject "..." [--data '<json>']
  seal.py verify
  seal.py pubkey
"""
import argparse, base64, datetime, hashlib, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHAIN = ROOT / "receipts" / "chain.jsonl"
KEYF = ROOT / "keys" / "vault.key"
PUBF = ROOT / "keys" / "vault.pub"


import hashlib
b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
def H(m): return hashlib.sha512(m).digest()
def inv(x): return pow(x, q - 2, q)
d = -121665 * inv(121666) % q
I = pow(2, (q - 1) // 4, q)
def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0: x = (x * I) % q
    if x % 2 != 0: x = q - x
    return x
By = 4 * inv(5) % q
Bx = xrecover(By)
B = (Bx % q, By % q, 1, (Bx * By) % q)
def edwards_add(P, Q):
    x1, y1, z1, t1 = P; x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % q; b = (y1 + x1) * (y2 + x2) % q
    c = t1 * 2 * d * t2 % q; dd = z1 * 2 * z2 % q
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % q, g * h % q, f * g % q, e * h % q)
def scalarmult(P, e):
    if e == 0: return (0, 1, 1, 0)
    Q = scalarmult(P, e // 2); Q = edwards_add(Q, Q)
    if e & 1: Q = edwards_add(Q, P)
    return Q
def encodepoint(P):
    x, y, z, t = P
    zi = inv(z); x = x * zi % q; y = y * zi % q
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))
def decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << (b - 1)) - 1)
    x = xrecover(y)
    if x & 1 != (s[b // 8 - 1] >> 7) & 1: x = q - x
    P = (x, y, 1, x * y % q)
    return P
def Hint(m):
    h = H(m); return int.from_bytes(h, "little")
def publickey(sk):
    h = H(sk); a = 2**(b - 2) + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, b - 2))
    return encodepoint(scalarmult(B, a))
def sign(m, sk, pk):
    h = H(sk); a = 2**(b - 2) + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, b - 2))
    r = Hint(h[b // 8: b // 4] + m)
    R = encodepoint(scalarmult(B, r))
    S = (r + Hint(R + pk + m) * a) % l
    return R + S.to_bytes(b // 8, "little")
def check_vk(vk_pub, msg, sig):
    if len(sig) != 64: return False
    R = decodepoint(sig[:b // 8])
    S = int.from_bytes(sig[b // 8:], "little")
    if S >= l: return False
    A = decodepoint(vk_pub)
    h = Hint(sig[:b // 8] + vk_pub + msg)
    return encodepoint(scalarmult(B, S)) == encodepoint(edwards_add(R, scalarmult(A, h)))

def sha(b): return hashlib.sha256(b).hexdigest()
def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def seed_b(): return base64.b64decode(KEYF.read_text().strip())
def pub_hex():
    """Public key: from vault.pub if present, else derived from the seed (so `pubkey` works first)."""
    try:
        if PUBF.exists() and PUBF.read_text().strip():
            return PUBF.read_text().strip()
    except Exception:
        pass
    return publickey(seed_b()).hex()


def last():
    if not CHAIN.exists():
        return None
    r = None
    for line in CHAIN.read_text().splitlines():
        if line.strip():
            try:
                r = json.loads(line)
            except Exception:
                pass
    return r


def last_all():
    rows = []
    if CHAIN.exists():
        for line in CHAIN.read_text().splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    return rows


def append(kind, subject, data=None):
    r = last()
    seq = (r["seq"] + 1) if r else 0
    prev = sha(canon(r)) if r else "0" * 64
    body = {"seq": seq, "ts": int(datetime.datetime.now().timestamp()),
            "ts_iso": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "kind": kind, "subject": subject,
            "payload_sha256": sha(canon(data or {})),
            "data": data or {}, "prev": prev}
    rbody = {k: body[k] for k in ("seq", "ts", "kind", "subject", "payload_sha256", "prev")}
    body["sig"] = sign(canon(rbody), seed_b(), bytes.fromhex(pub_hex())).hex()
    CHAIN.parent.mkdir(parents=True, exist_ok=True)
    with CHAIN.open("a") as f:
        f.write(json.dumps(body, sort_keys=True) + "\n")
    return body


def verify():
    rows = []
    if CHAIN.exists():
        for line in CHAIN.read_text().splitlines():
            if line.strip():
                rows.append(json.loads(line))
    if not rows:
        print("empty chain")
        return 1
    pk = bytes.fromhex(pub_hex())
    prev = "0" * 64
    for i, r in enumerate(rows):
        rbody = {k: r[k] for k in ("seq", "ts", "kind", "subject", "payload_sha256", "prev")}
        if r["seq"] != i:
            print("FAIL seq break at %d" % i); return 2
        if r["prev"] != prev:
            print("FAIL prev-link at %d" % i); return 2
        if r["payload_sha256"] != sha(canon(r["data"])):
            print("FAIL payload hash at %d" % i); return 2
        if not check_vk(pk, canon(rbody), bytes.fromhex(r["sig"])):
            print("FAIL signature at %d" % i); return 2
        prev = sha(canon(r))
    print("OK - %d receipts verified - root %s..." % (len(rows), prev[:32]))
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("append")
    a.add_argument("--kind", required=True)
    a.add_argument("--subject", required=True)
    a.add_argument("--data", default="{}")
    v = sub.add_parser("verify")
    v.add_argument("--quiet", action="store_true")
    sub.add_parser("pubkey")
    ex = sub.add_parser("export")
    ex.add_argument("--seq", type=int, required=True)
    vp = sub.add_parser("verify_proof")
    vp.add_argument("--file", required=True, help="receipt JSON (from `export`)")
    vp.add_argument("--pub", required=True, help="signer public key, hex")
    x = ap.parse_args()
    if x.cmd == "append":
        append(x.kind, x.subject, json.loads(x.data))
    elif x.cmd == "verify":
        sys.exit(verify())
    elif x.cmd == "pubkey":
        print(pub_hex())
    elif x.cmd == "export":
        r = [y for y in (last_all()) if y.get("seq") == x.seq]
        if not r:
            print("no receipt with that seq"); sys.exit(2)
        print(json.dumps(r[0], indent=1, sort_keys=True))
    elif x.cmd == "verify_proof":
        rec = json.loads(pathlib.Path(x.file).read_text())
        rbody = {k: rec[k] for k in ("seq", "ts", "kind", "subject", "payload_sha256", "prev")}
        okp = rec["payload_sha256"] == sha(canon(rec["data"]))
        oks = check_vk(bytes.fromhex(x.pub.strip()), canon(rbody), bytes.fromhex(rec["sig"]))
        print("payload %s | signature %s | receipt #%s %s" %
              ("OK" if okp else "FAIL", "OK" if oks else "FAIL", rec.get("seq"), rec.get("subject", "")[:60]))
        sys.exit(0 if (okp and oks) else 2)
