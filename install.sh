#!/usr/bin/env bash
# CHC HARNESS installer — Linux (systemd). Customer runs this on THEIR OWN machine.
# Nothing here talks to CHCFLASH33 infrastructure: the server is yours, the model endpoint is yours.
set -euo pipefail

PORT="${CHC_PORT:-8895}"
HOST="${CHC_HOST:-127.0.0.1}"
PREFIX="${CHC_PREFIX:-/opt/chc-harness}"
LLM_URL="${CHC_LLM_URL:-http://127.0.0.1:11434/v1/chat/completions}"
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
  --llm-url $LLM_URL --model $MODEL --admin-token \$(cat $PREFIX/admin.token) \\
  --max-rounds 0 --max-tool-calls 0
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now chc-harness.service
sleep 2
say "service: $(systemctl is-active chc-harness.service)"
say "vault:   $(sudo "$PREFIX/venv/bin/python" "$PREFIX/init_vault.py" --dir "$PREFIX/vault" --owner "$SERVICE_USER" | head -1)"
sudo mkdir -p "$PREFIX/vault/plugins/paddy"
sudo cp paddy.py "$PREFIX/vault/plugins/paddy/paddy.py"
sudo cp chat_memory_mcp.py "$PREFIX/vault/tools/chat_memory_mcp.py"
say "open:    http://$HOST:$PORT/  (sign up, then set up 2FA)"
say "billing: create a key in Settings or:  python3 $PREFIX/app.py --db $PREFIX/chc.db --new-key you@example.com"
say "admin:   http://$HOST:$PORT/admin/usage?token=\$(sudo cat $PREFIX/admin.token)"
say "tool calls and continuation rounds are UNLIMITED by default (--max-rounds 0 --max-tool-calls 0)"
