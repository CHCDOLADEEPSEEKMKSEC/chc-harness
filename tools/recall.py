#!/usr/bin/env python3
"""recall.py - ask the record first (read-only search over this vault's chain).

    recall.py "query"            # substring match on subject + data
    recall.py --kind finding     # only findings
    recall.py --since 2026-11-09 # only newer receipts
    recall.py "q" --limit 20 --json
"""
import argparse, datetime, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHAIN = ROOT / "receipts" / "chain.jsonl"


def load():
    if not CHAIN.exists():
        return []
    out = []
    for line in CHAIN.read_text().splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="?", default="")
    ap.add_argument("--kind", default="")
    ap.add_argument("--since", default="")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    rows = load()
    q = a.query.lower().strip()
    since = a.since.strip()
    hits = []
    for r in rows:
        if a.kind and r.get("kind") != a.kind:
            continue
        if since and str(r.get("ts_iso", ""))[:10] < since:
            continue
        hay = (str(r.get("subject", "")) + " " + json.dumps(r.get("data") or {}, sort_keys=True)).lower()
        if q and q not in hay:
            continue
        hits.append(r)
    hits = hits[-a.limit:]

    if a.json:
        print(json.dumps(hits, indent=1))
        return 0
    if not hits:
        print("no receipts match")
        return 0
    for r in hits:
        when = str(r.get("ts_iso", ""))[:19].replace("T", " ")
        print("#%-4s %s %-10s %s" % (r.get("seq"), when, r.get("kind"), r.get("subject")))
        d = r.get("data") or {}
        if d:
            line = json.dumps(d, sort_keys=True)
            print("      " + (line[:300] + ("..." if len(line) > 300 else "")))
    print("-- %d match(es) of %d receipts" % (len(hits), len(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
