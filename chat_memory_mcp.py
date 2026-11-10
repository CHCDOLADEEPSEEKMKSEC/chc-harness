#!/usr/bin/env python3
"""chat_memory_mcp.py - MCP stdio server: search YOUR OWN past chats (read-only).

Talks to the harness SQLite database directly, scoped to one uid, and exposes:
  search_chats(query, limit)   - substring match over your messages
  recent_chats(limit)          - your last chats with first line of each

Point it at the db with CHC_DB (default /opt/chc-ai/chc.db) and CHC_UID (default 5).
"""
import json, os, sqlite3, sys

DB = os.environ.get("CHC_DB", "/opt/chc-ai/chc.db")
UID = int(os.environ.get("CHC_UID", "5"))

TOOLS = [
    {"name": "search_chats", "description": "Search your own past chat messages",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"},
                                                      "limit": {"type": "integer"}},
                     "required": ["query"]}},
    {"name": "recent_chats", "description": "List your most recent chats",
     "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}}},
]


def db():
    c = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
    c.row_factory = sqlite3.Row
    return c


def search(query, limit=10):
    c = db()
    rows = c.execute("""select c.id, c.title, m.role, m.content, m.created
                          from messages m join chats c on c.id = m.chat
                         where c.uid = ? and m.content like ?
                         order by m.created desc limit ?""",
                     (UID, "%" + query + "%", limit)).fetchall()
    c.close()
    return [{"chat": r["id"], "title": r["title"], "role": r["role"],
             "when": r["created"], "snippet": (r["content"] or "")[:400]} for r in rows]


def recent(limit=10):
    c = db()
    rows = c.execute("select id, title, updated from chats where uid=? order by updated desc limit ?",
                     (UID, limit)).fetchall()
    c.close()
    return [{"chat": r["id"], "title": r["title"], "updated": r["updated"]} for r in rows]


def call(name, args):
    if name == "search_chats":
        return {"results": search(str(args.get("query") or ""), int(args.get("limit") or 10))}
    if name == "recent_chats":
        return {"results": recent(int(args.get("limit") or 10))}
    return {"error": "unknown tool"}


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        mid = msg.get("id")
        method = msg.get("method")
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                "serverInfo": {"name": "CHC-CHAT-MEMORY", "version": "1.0.0"}}})
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            p = msg.get("params") or {}
            try:
                out = call(p.get("name"), p.get("arguments") or {})
                send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text",
                      "text": json.dumps(out, indent=1)}]}})
            except Exception as e:
                send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32000, "message": str(e)}})
        elif mid is not None:
            send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "unknown method"}})


if __name__ == "__main__":
    main()
