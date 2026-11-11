#!/usr/bin/env bash
# CHC HARNESS installer — Linux (systemd). Customer runs this on THEIR OWN machine.
# Nothing here talks to CHCFLASH33 infrastructure: the server is yours, the model endpoint is yours.
set -euo pipefail

PORT="${CHC_PORT:-8895}"
HOST="${CHC_HOST:-127.0.0.1}"
PREFIX="${CHC_PREFIX:-/opt/chc-harness}"
UNIT_NAME="${CHC_UNIT:-chc-harness}"
OWNER_EMAIL="${CHC_OWNER:-}"
PUBLIC_URL="${CHC_PUBLIC_URL:-}"
BREVO_KEY="${CHC_BREVO_KEY:-}"
SMTP_CRED="${CHC_SMTP:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --dir)   PREFIX="$2"; shift 2 ;;
    --port)  PORT="$2"; shift 2 ;;
    --user)  SERVICE_USER="$2"; shift 2 ;;
    --owner|--owner-email|--email) OWNER_EMAIL="$2"; shift 2 ;;
    --unit)  UNIT_NAME="$2"; shift 2 ;;
    --brevo) BREVO_KEY="$2"; shift 2 ;;
    --public-url) PUBLIC_URL="$2"; shift 2 ;;
    --smtp)  SMTP_CRED="$2"; shift 2 ;;
    -h|--help)
      cat <<'USAGE'
CHC HARNESS installer
  --dir PATH     install here            (default /opt/chc-harness)
  --port N       listen port             (default 8895)
  --user NAME    service user            (default: you)
  --owner EMAIL  owner account email      (default: asked, or first account)
  --unit NAME    systemd unit name       (default chc-harness)
  --brevo KEY    Brevo API key   (sends the 2FA code by email)
  --smtp  U:P    Gmail address + app password (alternative to --brevo)
or set CHC_PREFIX / CHC_PORT / CHC_USER / CHC_OWNER / CHC_UNIT / CHC_BREVO_KEY / CHC_SMTP / CHC_PUBLIC_URL.
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
Environment=CHC_SELF_HOST=1
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
  # `curl ... | bash` leaves stdin as the script, so ask the TERMINAL instead of stdin
  if [ -r /dev/tty ]; then
    printf "[chc] owner email (who signs in with /enter): " > /dev/tty 2>/dev/null || true
    read -r OWNER_EMAIL < /dev/tty 2>/dev/null || true
  fi
fi
if [ -z "$OWNER_EMAIL" ]; then
  OWNER_EMAIL="owner@$(hostname -s 2>/dev/null || echo localhost).local"
  say "no owner email given - using $OWNER_EMAIL (change it: echo you@example.com | sudo tee $PREFIX/owner)"
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
# MAIL — 2FA needs a way to send the code. Reuse a config already on this box, else
# honour --brevo/--smtp, else ask. THIS BLOCK MUST NEVER ABORT THE INSTALL (set -e is on).
set +e
if [ -z "$BREVO_KEY" ] && [ -z "$SMTP_CRED" ]; then
  for c in "$HOME/chc-harness/mailapi.env" "$HOME/chc-harness/smtp.env" \
           /opt/chc-ai/mailapi.env /opt/chc-ai/smtp.env; do
    if [ -r "$c" ]; then
      b="$(basename "$c")"
      if sudo cp "$c" "$PREFIX/$b" 2>/dev/null; then
        sudo chmod 600 "$PREFIX/$b" 2>/dev/null || true
        say "mail:    reused the mail config already on this box ($c)"
        if [ "$b" = "smtp.env" ]; then
          SMTP_CRED="$(sudo "$PREFIX/venv/bin/python" -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["email"]+":"+d["password"])' "$PREFIX/$b" 2>/dev/null)"
        fi
        break
      fi
    fi
  done
fi
if [ -z "$BREVO_KEY" ] && [ -z "$SMTP_CRED" ] && [ -r /dev/tty ]; then
  printf "[chc] Brevo API key for the 2FA email (starts xkeysib-) - press ENTER to skip: " > /dev/tty 2>/dev/null || true
  read -r BREVO_KEY < /dev/tty 2>/dev/null || true
fi
case "$BREVO_KEY" in
  "") : ;;
  xkeysib-*) : ;;
  *) say "mail:    that is not a Brevo key (a key starts xkeysib-) - ignoring it; the email goes in --owner-email"
     BREVO_KEY="" ;;
esac
MAIL_LINE="not set"
if [ -n "$BREVO_KEY" ]; then
  printf '{"provider":"brevo","key":"%s","from":"CHC HARNESS <%s>"}\n' "$BREVO_KEY" "$OWNER_EMAIL" | sudo tee "$PREFIX/mailapi.env" >/dev/null
  sudo chmod 600 "$PREFIX/mailapi.env"
  MAIL_LINE="$(sudo "$PREFIX/venv/bin/python" - "$PREFIX/mailapi.env" "$OWNER_EMAIL" <<'PYM' 2>&1 | tail -1
import json,sys,urllib.request
cfg=json.load(open(sys.argv[1])); to=sys.argv[2]
try:
    body=json.dumps({"sender":{"email":cfg["from"].split("<")[-1].rstrip(">"),"name":"CHC HARNESS"},
                     "to":[{"email":to}],"subject":"CHC HARNESS test","textContent":"2FA mail test from your new install"}).encode()
    req=urllib.request.Request("https://api.brevo.com/v3/smtp/email",data=body,
        headers={"api-key":cfg["key"],"Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=25) as r: print("MAIL OK" if 200<=r.status<300 else "MAIL FAIL")
except Exception as e: print("MAIL FAIL "+type(e).__name__)
PYM
)"
elif [ -r "$PREFIX/mailapi.env" ]; then
  MAIL_LINE="MAIL OK (existing config reused)"
elif [ -n "$SMTP_CRED" ]; then
  U="${SMTP_CRED%%:*}"; P="${SMTP_CRED#*:}"
  printf '{"email":"%s","password":"%s"}\n' "$U" "$P" | sudo tee "$PREFIX/smtp.env" >/dev/null
  sudo chmod 600 "$PREFIX/smtp.env"
  MAIL_LINE="MAIL OK (smtp saved)"
else
  MAIL_LINE="NOT SET - the 6-digit code cannot be emailed; the password still works on this machine"
fi
set -e
say "mail:    $MAIL_LINE"

sudo "$PREFIX/venv/bin/python" "$PREFIX/app.py" --db "$PREFIX/chc.db" --make-user "$OWNER_EMAIL" >/dev/null 2>&1 || true
PW_LINE="$(sudo "$PREFIX/venv/bin/python" "$PREFIX/app.py" --db "$PREFIX/chc.db" --set-password "$OWNER_EMAIL" 2>/dev/null | tr '\n' ' ')"
OWNER_PW="$(printf '%s' "$PW_LINE" | sed -n 's/.*PASSWORD=\([^ ]*\).*/\1/p')"
say "LINK:    http://$HOST:$PORT/login           (permanent - this one link is the login, every time)"
say "email:   $OWNER_EMAIL"
if [ -n "$OWNER_PW" ]; then
  say "password: $OWNER_PW   (generated once - save it now; press GENERATE NEW PASSWORD on $HOST:$PORT/admin/usage to make another)"
  printf 'LINK=http://%s:%s/enter\nEMAIL=%s\nPASSWORD=%s\n' "$HOST" "$PORT" "$OWNER_EMAIL" "$OWNER_PW" | sudo tee "$PREFIX/.creds" >/dev/null
  sudo chmod 600 "$PREFIX/.creds"
  # THE FIRST LOGIN: email the link and the 6-digit code to the owner address.
say "login:   emailing the link + 6-digit code to $OWNER_EMAIL ..."
FLINE="$(sudo "$PREFIX/venv/bin/python" "$PREFIX/app.py" --db "$PREFIX/chc.db" \
        --host 127.0.0.1 --port "$PORT" ${PUBLIC_URL:+--public-url "$PUBLIC_URL"} \
        --first-login "$OWNER_EMAIL" 2>&1 | tail -1)"
case "$FLINE" in
  FIRST_LOGIN\ OK*) say "login:   ✅ SENT - open http://127.0.0.1:$PORT/login and type the 6-digit code from the email" ;;
  *)                say "login:   ⚠️  email not sent ($FLINE) - use the password above, or set --brevo/--smtp" ;;
esac
say "saved:   .creds next to the install (chmod 600)"
fi
OWNER_LOGIN="$(sudo "$PREFIX/venv/bin/python" "$PREFIX/app.py" --db "$PREFIX/chc.db" \
  --public-url "http://$HOST:$PORT" --make-user "$OWNER_EMAIL" 2>/dev/null | tail -1)"
[ -n "$OWNER_LOGIN" ] && say "login:   $OWNER_LOGIN   (one-time, 15 min)"
sudo mkdir -p "$PREFIX/vault/plugins/paddy"
sudo cp paddy.py "$PREFIX/vault/plugins/paddy/paddy.py"
sudo cp chat_memory_mcp.py "$PREFIX/vault/tools/chat_memory_mcp.py"
say ""
say "  admin:  http://$HOST:$PORT/admin/usage?token=$ADMIN_TOKEN"
LOGIN="$(sudo "$PREFIX/venv/bin/python" "$PREFIX/app.py" --db "$PREFIX/chc.db" --public-url "http://$HOST:$PORT" --make-user "$OWNER_EMAIL" 2>/dev/null | tail -1)"
[ -n "$LOGIN" ] && say "  enter:  http://127.0.0.1:$PORT/enter?t=$ADMIN_TOKEN   (PERMANENT - bookmark this)"
say "  login:  $LOGIN"
say "─────────────────────────────────────────────────────────────"
