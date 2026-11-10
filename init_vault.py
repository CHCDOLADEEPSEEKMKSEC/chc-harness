#!/usr/bin/env python3
"""init_vault.py - create YOUR OWN private vault for CHC HARNESS.

    python3 init_vault.py --dir ~/my-vault --owner "your name"

Creates a canonical vault: receipts/chain.jsonl (ed25519-signed), tools/seal.py,
keys/ (0600 seed + public key), master/README.md, datasets/.
Nothing comes from the vendor: your data, your key, your chain.
"""
import argparse, base64, json, pathlib, secrets, shutil, stat, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
SEAL_SRC = HERE / "seal.py"

README = """# YOUR VAULT

Yours: your receipts, your key, your data. The vendor never sees it.

## Layout
- `receipts/chain.jsonl` - append-only receipts: seq, ts, ts_iso, kind, subject,
  payload_sha256, data, prev, sig. Each receipt pins the previous one's hash, so nothing
  can be edited or re-ordered silently.
- `tools/seal.py` - append / verify / pubkey. No dependencies (pure-python ed25519).
- `keys/vault.key` - 32-byte seed, base64, mode 0600. Never share.
- `keys/vault.pub` - your public key (hex). Share it if someone must verify your chain.
- `datasets/` - your data.   `master/` - your written record.

## Use
    python3 tools/seal.py append --kind note --subject "first entry" --data '{"hello":"world"}'
    python3 tools/seal.py verify
    python3 tools/seal.py pubkey

## Rules that make a record worth something
1. Seal decisions, not vibes: subject = what happened, data = the numbers.
2. Corrections are corrections - never edit an old receipt.
3. A stale number is a lie by omission; re-stamp when you quote one.
4. Secrets and costs: locations only, never values.
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="vault")
    ap.add_argument("--owner", default="")
    a = ap.parse_args()
    root = pathlib.Path(a.dir).expanduser().resolve()
    for d in ("receipts", "master", "tools", "keys", "datasets"):
        (root / d).mkdir(parents=True, exist_ok=True)

    seal = root / "tools" / "seal.py"
    if not seal.exists():
        if not SEAL_SRC.exists():
            print("seal.py not found next to init_vault.py - keep them in the same directory")
            return 2
        shutil.copyfile(SEAL_SRC, seal)
    seal.chmod(0o755)

    keyf, pubf = root / "keys" / "vault.key", root / "keys" / "vault.pub"
    if not keyf.exists():
        keyf.write_text(base64.b64encode(secrets.token_bytes(32)).decode())
        keyf.chmod(stat.S_IRUSR | stat.S_IWUSR)
    if not pubf.exists() or not pubf.read_text().strip():
        out = subprocess.run([sys.executable, str(seal), "pubkey"], capture_output=True, text=True)
        pubf.write_text((out.stdout or "").strip())

    rm = root / "master" / "README.md"
    if not rm.exists():
        title = ("# YOUR VAULT - " + a.owner) if a.owner else "# YOUR VAULT"
        rm.write_text(README.replace("# YOUR VAULT", title))

    chain = root / "receipts" / "chain.jsonl"
    if not chain.exists() or not chain.read_text().strip():
        sub = "vault initialised" + ((" for " + a.owner) if a.owner else "")
        subprocess.run([sys.executable, str(seal), "append", "--kind", "milestone",
                        "--subject", sub,
                        "--data", json.dumps({"init": "init_vault.py", "format": "canonical-ed25519"})])

    ver = root / "verify.sh"
    ver.write_text("""#!/usr/bin/env bash
# Verify THIS vault's chain. Read-only: never signs, never appends.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${CHC_PY:-$HERE/../venv/bin/python}"; [ -x "$PY" ] || PY=python3
exec "$PY" "$HERE/tools/seal.py" verify "$@"
""")
    ver.chmod(0o755)

    print("vault ready: " + str(root))
    print("  chain: " + str(chain))
    print("  key  : " + str(keyf) + " (0600)")
    print("  pub  : " + str(pubf))
    return subprocess.run([sys.executable, str(seal), "verify"]).returncode


if __name__ == "__main__":
    sys.exit(main())
