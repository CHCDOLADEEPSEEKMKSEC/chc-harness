#!/usr/bin/env bash
# CHC HARNESS installer — Linux (systemd). Customer runs this on THEIR OWN machine.
# Nothing here talks to CHCFLASH33 infrastructure: the server is yours, the model endpoint is yours.
set -euo pipefail

PORT="${CHC_PORT:-8895}"
HOST="${CHC_HOST:-127.0.0.1}"
PREFIX="${CHC_PREFIX:-/opt/chc-harness}"
# find the model server that is actually running (ports differ per box: ollama 11434, proxy 11436)
if [ -z "${CHC_LLM_URL:-}" ]; then
  for p in 11434 11436 11435 8000 8080; do
    if curl -sf -m 2 "http://127.0.0.1:$p/v1/models" >/dev/null 2>&1; then
      LLM_URL="http://127.0.0.1:$p/v1/chat/completions"; break
    fi
  done
fi
LLM_URL="${CHC_LLM_URL:-${LLM_URL:-http://127.0.0.1:11434/v1/chat/completions}}"
# pick a real model id from that server unless told otherwise
if [ -z "${CHC_MODEL:-}" ] && curl -sf -m 3 "${LLM_URL%/chat/completions}/models" >/tmp/_m.json 2>/dev/null; then
  MODEL="$(python3 -c 'import json,sys;d=json.load(open("/tmp/_m.json")).get("data",[]);
ids=[m.get("id","") for m in d];
pick=next((i for i in ids if "qwen2.5:3b" in i),None) or next((i for i in ids if "qwen" in i.lower()),None) or (ids[0] if ids else "");
print(pick)' 2>/dev/null)"
fi
CHC_MODEL_PICK="${CHC_MODEL:-${MODEL:-local}}"
MODEL="${CHC_MODEL:-local}"
SERVICE_USER="${CHC_USER:-$(id -un)}"

say() { printf '\033[1;36m[chc]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[chc]\033[0m %s\n' "$*" >&2; exit 1; }

# self-fetch: when this is run as `curl -fsSL .../install.sh | bash` there are no local files,
# so pull the package from the house and unpack it here.
if [ ! -f app.py ]; then
  CBASE="${CHC_BASE:-https://ai.94-237-56-140.sslip.io}"
  TMPD="$(mktemp -d)"
  trap 'rm -rf "$TMPD"' EXIT
  say "no local package found, fetching from $CBASE"
  curl -fsSL "$CBASE/download" -o "$TMPD/pkg.tar.gz" || die "could not download the package from $CBASE"
  tar xzf "$TMPD/pkg.tar.gz" -C "$TMPD" || die "could not unpack the package"
  cd "$TMPD"
fi

command -v python3 >/dev/null || die "python3 is required"
python3 - <<'PY' || die "python3 >= 3.8 required"
import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)
PY
command -v systemctl >/dev/null || die "systemd is required (use --user mode manually if not)"

say "installing into $PREFIX (service user: $SERVICE_USER)"
sudo mkdir -p "$PREFIX"/{files,work}
sudo cp app.py "$PREFIX/app.py"
[ -f VERSION ] && sudo cp VERSION "$PREFIX/VERSION"
sudo cp init_vault.py "$PREFIX/init_vault.py"
sudo cp seal.py "$PREFIX/seal.py"
sudo cp recall.py "$PREFIX/recall.py"
sudo cp senses.py "$PREFIX/senses.py"
sudo cp paddy.py "$PREFIX/paddy.py"
sudo cp chat_memory_mcp.py "$PREFIX/chat_memory_mcp.py"
sudo python3 -m venv "$PREFIX/venv" 2>/dev/null || true
sudo "$PREFIX/venv/bin/pip" -q install --upgrade pip aiohttp || die "pip install aiohttp failed"

# secrets: session secret + admin token for the billing report, generated locally, never shared
[ -f "$PREFIX/secret" ] || (head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c 48 | sudo tee "$PREFIX/secret" >/dev/null)
[ -f "$PREFIX/admin.token" ] || (head -c 36 /dev/urandom | base64 | tr -d '/+=' | head -c 36 | sudo tee "$PREFIX/admin.token" >/dev/null)
sudo chmod 600 "$PREFIX/secret" "$PREFIX/admin.token"
sudo chown -R "$SERVICE_USER" "$PREFIX"

ADMIN_TOKEN="$(sudo cat "$PREFIX/admin.token")"
sudo tee "/etc/systemd/system/chc-harness.service" >/dev/null <<UNIT
[Unit]
Description=CHC HARNESS (self-hosted AI harness)
After=network-online.target
[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$PREFIX
ExecStart=$PREFIX/venv/bin/python $PREFIX/app.py --host $HOST --port $PORT \\
  --db $PREFIX/chc.db --secret-file $PREFIX/secret --files $PREFIX/files --work $PREFIX/work \\
  --llm-url $LLM_URL --model $CHC_MODEL_PICK --admin-token $ADMIN_TOKEN \\
  --max-rounds 0 --max-tool-calls 0
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable chc-harness.service
sudo systemctl restart chc-harness.service   # install = restart: a running unit keeps the OLD code in memory
sleep 2
say "service: $(systemctl is-active chc-harness.service)"
say "vault:   $(sudo "$PREFIX/venv/bin/python" "$PREFIX/init_vault.py" --dir "$PREFIX/vault" --owner "$SERVICE_USER" | head -1)"
# WHO OWNS THIS INSTALL — recorded so /enter signs in THEIR account, not "whoever is in the db".
printf '%s' "$OWNER_EMAIL" | sudo tee "$PREFIX/owner" >/dev/null
sudo chmod 644 "$PREFIX/owner"
say "owner:   $OWNER_EMAIL   (recorded in $PREFIX/owner)"
OWNER_LOGIN="$(sudo "$PREFIX/venv/bin/python" "$PREFIX/app.py" --db "$PREFIX/chc.db" \
  --public-url "http://$HOST:$PORT" --make-user "$OWNER_EMAIL" 2>/dev/null | tail -1)"
[ -n "$OWNER_LOGIN" ] && say "login:   $OWNER_LOGIN   (one-time, 15 min)"
sudo mkdir -p "$PREFIX/vault/plugins/paddy"
sudo cp paddy.py "$PREFIX/vault/plugins/paddy/paddy.py"
sudo cp chat_memory_mcp.py "$PREFIX/vault/tools/chat_memory_mcp.py"
say "open:    http://$HOST:$PORT/  (sign up, then set up 2FA)"
say "billing: create a key in Settings or:  python3 $PREFIX/app.py --db $PREFIX/chc.db --new-key you@example.com"
say ""
say "── COPY-PASTE LINKS (full, with the real token) ──────────────"
say "  admin:  http://$HOST:$PORT/admin/usage?token=$ADMIN_TOKEN"
LOGIN="$(sudo "$PREFIX/venv/bin/python" "$PREFIX/app.py" --db "$PREFIX/chc.db" --public-url "http://$HOST:$PORT" --make-user "$OWNER_EMAIL" 2>/dev/null | tail -1)"
[ -n "$LOGIN" ] && say "  enter:  http://127.0.0.1:$PORT/enter?t=$ADMIN_TOKEN   (PERMANENT - bookmark this)"
say "  login:  $LOGIN"
say "  (login link is single-use, valid 15 min; make another: $PREFIX/venv/bin/python $PREFIX/app.py --db $PREFIX/chc.db --make-user you@example.com)"
say "─────────────────────────────────────────────────────────────"
say "tool calls and continuation rounds are UNLIMITED by default (--max-rounds 0 --max-tool-calls 0)"
