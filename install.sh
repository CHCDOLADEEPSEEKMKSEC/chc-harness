#!/usr/bin/env bash
# CHC HARNESS installer — Linux (systemd). Customer runs this on THEIR OWN machine.
# Nothing here talks to CHCFLASH33 infrastructure: the server is yours, the model endpoint is yours.
set -euo pipefail

PORT="${CHC_PORT:-8895}"
HOST="${CHC_HOST:-127.0.0.1}"
PREFIX="${CHC_PREFIX:-/opt/chc-harness}"
UNIT_NAME="${CHC_UNIT:-chc-harness}"
OWNER_EMAIL="${CHC_OWNER:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --dir)   PREFIX="$2"; shift 2 ;;
    --port)  PORT="$2"; shift 2 ;;
    --user)  SERVICE_USER="$2"; shift 2 ;;
    --owner|--owner-email|--email) OWNER_EMAIL="$2"; shift 2 ;;
    --unit)  UNIT_NAME="$2"; shift 2 ;;
    -h|--help)
      cat <<'USAGE'
CHC HARNESS installer
  --dir PATH     install here            (default /opt/chc-harness)
  --port N       listen port             (default 8895)
  --user NAME    service user            (default: you)
  --owner EMAIL  owner account email      (default: asked, or first account)
  --unit NAME    systemd unit name       (default chc-harness)
or set CHC_PREFIX / CHC_PORT / CHC_USER / CHC_OWNER / CHC_UNIT.
USAGE
      exit 0 ;;
    *) die "unknown argument: $1 (use --help)" ;;
  esac
done
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
SERVICE_USER="${SERVICE_USER:-${CHC_USER:-$(id -un)}}"

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

# a bare Ubuntu/Debian image has python3 but NOT venv/pip — the harness needs both, so install them
if ! python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then
  say "installing python3-venv + python3-pip (one time)"
  sudo apt-get update -qq >/dev/null 2>&1 || true
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1 \
    || die "could not install python3-venv (run manually: sudo apt install python3-venv python3-pip)"
fi

say "installing into $PREFIX (service user: $SERVICE_USER)"
sudo mkdir -p "$PREFIX"/{files,work}
[ -f app.py ] || die "app.py missing from the package"
for f in app.py VERSION init_vault.py seal.py recall.py senses.py paddy.py chat_memory_mcp.py smoke_test.py; do
  if [ -f "$f" ]; then sudo cp "$f" "$PREFIX/$f"; else say "optional file not in package: $f (skipped)"; fi
done
sudo python3 -m venv "$PREFIX/venv" || die "could not create the Python venv at $PREFIX/venv"
sudo "$PREFIX/venv/bin/pip" -q install --upgrade pip aiohttp cryptography || die "pip install aiohttp cryptography failed"

# secrets: session secret + admin token for the billing report, generated locally, never shared
[ -f "$PREFIX/secret" ] || (head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c 48 | sudo tee "$PREFIX/secret" >/dev/null)
[ -f "$PREFIX/admin.token" ] || (head -c 36 /dev/urandom | base64 | tr -d '/+=' | head -c 36 | sudo tee "$PREFIX/admin.token" >/dev/null)
sudo chmod 600 "$PREFIX/secret" "$PREFIX/admin.token"
sudo chown -R "$SERVICE_USER" "$PREFIX"

ADMIN_TOKEN="$(sudo cat "$PREFIX/admin.token")"
sudo tee "/etc/systemd/system/$UNIT_NAME.service" >/dev/null <<UNIT
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
sudo systemctl enable "$UNIT_NAME.service"
sudo systemctl restart "$UNIT_NAME.service"   # install = restart: a running unit keeps the OLD code in memory
sleep 2
say "service: $(systemctl is-active "$UNIT_NAME.service")"

# customer vault: own keypair, own chain, own verify.sh — the house chain is never involved
sudo mkdir -p "$PREFIX/vault"/{receipts,keys,tools,master,datasets}
sudo cp seal.py "$PREFIX/vault/tools/seal.py"
sudo chmod 755 "$PREFIX/vault/tools/seal.py"
if [ ! -s "$PREFIX/vault/receipts/chain.jsonl" ]; then
  sudo env CHC_SEAL_ROOT="$PREFIX/vault" "$PREFIX/venv/bin/python" "$PREFIX/vault/tools/seal.py" init >/dev/null 2>&1 || die "vault key/chain init failed"
  sudo env CHC_SEAL_ROOT="$PREFIX/vault" "$PREFIX/venv/bin/python" "$PREFIX/vault/tools/seal.py" \
       append --kind milestone --subject "vault initialised" --data '{"owner":"'"${OWNER_EMAIL:-unset}"'"}' >/dev/null 2>&1 || true
fi
printf '#!/usr/bin/env bash
cd "%s" && CHC_SEAL_ROOT="%s" ./venv/bin/python vault/tools/seal.py verify\n' "$PREFIX" "$PREFIX/vault" | sudo tee "$PREFIX/vault/verify.sh" >/dev/null
sudo chmod 755 "$PREFIX/vault/verify.sh"
VAULT_LINE="$(sudo env CHC_SEAL_ROOT="$PREFIX/vault" "$PREFIX/venv/bin/python" "$PREFIX/vault/tools/seal.py" verify 2>&1 | head -1)"
say "vault:   $VAULT_LINE"
# WHO OWNS THIS INSTALL — recorded so /enter signs in THEIR account, not "whoever is in the db".
if [ -z "$OWNER_EMAIL" ]; then
  if [ -t 0 ]; then read -r -p "[chc] owner email (who signs in with /enter): " OWNER_EMAIL || true; fi
fi
if [ -z "$OWNER_EMAIL" ]; then
  OWNER_EMAIL="$(sudo "$PREFIX/venv/bin/python" - "$PREFIX/chc.db" <<'PY2' 2>/dev/null || true
import sqlite3,sys
try:
    c=sqlite3.connect(sys.argv[1]); r=c.execute("select email from users order by id limit 1").fetchone()
    print(r[0] if r else "")
except Exception: print("")
PY2
)"
fi
if [ -n "$OWNER_EMAIL" ]; then printf '%s' "$OWNER_EMAIL" | sudo tee "$PREFIX/owner" >/dev/null; else say "owner: not set yet (run: echo you@example.com | sudo tee $PREFIX/owner)"; fi
sudo chmod 644 "$PREFIX/owner"
say "owner:   $OWNER_EMAIL   (recorded in $PREFIX/owner)"

# login is EMAIL + generated PASSWORD on /signin — no magic links, no "anyone with the email" entry
PW_LINE="$(sudo "$PREFIX/venv/bin/python" "$PREFIX/app.py" --db "$PREFIX/chc.db" --set-password "$OWNER_EMAIL" 2>/dev/null | tr '\n' ' ')"
OWNER_PW="$(printf '%s' "$PW_LINE" | sed -n 's/.*PASSWORD=\([^ ]*\).*/\1/p')"
say "login:   http://$HOST:$PORT/signin"
say "email:   $OWNER_EMAIL"
if [ -n "$OWNER_PW" ]; then say "password: $OWNER_PW   (generated once - save it now; press GENERATE NEW PASSWORD on $HOST:$PORT/admin/usage to make another)"; fi
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
