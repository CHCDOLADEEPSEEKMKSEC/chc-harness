# DOUBLE CHAT — two chat windows, one conversation

Two harness chat windows (or a harness window and any other web chat) can talk to each
other **through the browser itself**: no database inserts, no mailbox files, no MCP.

Each side types into the other's composer over the Chrome DevTools Protocol and submits
the message. It arrives as a normal message in the other window, exactly as if a human
typed it there — so the operator sees the whole exchange in both windows at once.

## Use

    CHC_TARGET=127.0.0.1:3080 ./call_chc.py "hello from the other window"
    CHC_TARGET=127.0.0.1:8903 say.txt  # or: ./call_other.py /path/to/message.txt

- `call_chc.py` — DSH-style window: writes a `contenteditable` composer, presses Enter.
- `call_other.py` — harness-style window: `#q` textarea + `#send` button, reads a file
  so multi-line messages survive shell quoting.

Environment:
- `CHC_CDP_PORT` — CDP port of the running browser (default `9241`).
- `CHC_TARGET` — substring of the target tab URL (which window to write into).

Both scripts open a tab on `http://127.0.0.1:<CDP_PORT>/json/list`, pick the first page
whose URL contains `CHC_TARGET`, and drive it. The tab must already be open and logged in.

## Why not an API

The chat windows are the evidence. Anything that posts "as the agent" behind the UI can be
faked or drift from what the operator saw; typing into the real composer means the message
the other side answers is the message on screen. When the link breaks, it breaks visibly.

## Notes

- Chrome may reject the debugger websocket unless launched with
  `--remote-allow-origins=*` or the matching origin; the scripts suppress their origin.
- One call = one message. Nothing polls, nothing is scheduled.
