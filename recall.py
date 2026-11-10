#!/usr/bin/env python3
"""recall.py — ask the record instead of guessing.

The vault already knows. master/ holds the rules, the diary and the logs; chat_archive/ holds
every conversation; the docs hold the answers we keep re-deriving. This indexes them into one
full-text table so "check the docs / check the logs" is ONE command, not a manual dig.

usage:
  recall.py --build              # (re)index master/ ad/ bafoune-net/ forensic docs + chat_archive
  recall.py "vps ovh canada"     # ranked hits with file:line and a snippet
  recall.py "paddy browser" -n 5
  recall.py --stats

Index: index/recall.db (sqlite FTS5). Rebuild after big doc changes; it is cheap.
"""
import argparse, pathlib, re, sqlite3, sys, time

VAULT = pathlib.Path(__file__).resolve().parents[1]
DB = VAULT / "index" / "recall.db"

INCLUDE = [
    ("master/*.md", "master"),
    ("master/**/*.md", "master"),
    ("ad/*.md", "ad"),
    ("docs/*.txt", "docs"),
    ("docs/**/*.md", "docs"),
    ("docs/*.md", "docs"),
    ("docs/*.odt", "docs"),
    ("bafoune-net/**/*.md", "bafoune-net"),
    ("docs/**/*.md", "docs"),
    ("*.md", "root"),
    ("chat_archive/messages.jsonl", "chat"),
    ("chat_archive/daily/**/*.jsonl", "chat"),
    ("books/*.json", "books"),
]
SKIP_DIR = {"node_modules", ".git", "__pycache__"}
MAX_LINE = 600


def sources():
    seen = set()
    for pat, tag in INCLUDE:
        for p in VAULT.glob(pat):
            if not p.is_file() or any(s in p.parts for s in SKIP_DIR):
                continue
            if p in seen:
                continue
            seen.add(p)
            yield p, tag


def iter_lines(p):
    try:
        if p.suffix == ".jsonl":
            import json
            for line in p.open(encoding="utf-8", errors="replace"):
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                ts = str(o.get("timestamp") or o.get("ts") or "")
                role = str(o.get("role") or o.get("type") or "")
                txt = o.get("text") or o.get("content") or o.get("message") or ""
                if isinstance(txt, list):
                    txt = " ".join(str(x.get("text", x)) if isinstance(x, dict) else str(x) for x in txt)
                txt = str(txt).replace("\n", " ")
                for chunk in re.split(r"(?<=[.!?])\s+", txt):
                    if chunk.strip():
                        yield f"{ts} {role}".strip(), chunk.strip()
        else:
            for i, line in enumerate(p.open(encoding="utf-8", errors="replace"), 1):
                if line.strip():
                    yield str(i), line.rstrip()
    except Exception:
        return


def build():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB)
    con.executescript("""
      DROP TABLE IF EXISTS docs;
      CREATE VIRTUAL TABLE docs USING fts5(path, tag, loc, text, tokenize='porter unicode61');
    """)
    n = files = 0
    t0 = time.time()
    for p, tag in sources():
        rows = []
        for loc, text in iter_lines(p):
            rows.append((str(p.relative_to(VAULT)), tag, loc, text[:MAX_LINE]))
        if rows:
            con.executemany("INSERT INTO docs VALUES (?,?,?,?)", rows)
            files += 1
            n += len(rows)
    con.commit()
    con.execute("INSERT INTO docs(docs) VALUES('optimize')")
    con.commit()
    print(f"indexed {n:,} lines from {files} files into {DB} in {time.time()-t0:.1f}s")


def search(q, n=12):
    con = sqlite3.connect(DB)
    terms = [t for t in re.split(r"\W+", q) if len(t) > 1]
    if not terms:
        print("give me something to look for"); return 1
    match = " OR ".join(f'"{t}"' for t in terms)
    try:
        rows = con.execute("""
          SELECT path, tag, loc, snippet(docs, 3, '»', '«', '…', 24) AS snip, bm25(docs) AS score
          FROM docs WHERE docs MATCH ? ORDER BY score LIMIT ?""", (match, n)).fetchall()
    except Exception as e:
        print("search failed:", e); return 1
    if not rows:
        print(f"no hits for {q!r} — run --build if this is a new area"); return 1
    by_file = {}
    for path, tag, loc, snip, score in rows:
        by_file.setdefault(path, []).append((loc, snip, score))
    print(f"{len(rows)} hits in {len(by_file)} files for {q!r}\n")
    for path, hits in by_file.items():
        print(f"── {path}")
        for loc, snip, _ in hits[:3]:
            print(f"   [{loc}] {snip[:220]}")
        print()
    return 0


def stats():
    con = sqlite3.connect(DB)
    n = con.execute("SELECT COUNT(*) FROM docs").fetchone()[0]
    files = con.execute("SELECT COUNT(DISTINCT path) FROM docs").fetchone()[0]
    size = DB.stat().st_size / 1e6
    print(f"{n:,} lines · {files} files · {size:.1f} MB · {DB}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="*")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("-n", type=int, default=12)
    a = ap.parse_args()
    if a.build:
        build(); sys.exit(0)
    if a.stats:
        sys.exit(stats())
    sys.exit(search(" ".join(a.query), a.n))
