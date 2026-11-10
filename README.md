# CHC HARNESS

**A self-hostable AI workspace that keeps its own receipts.**

Single-file Python app (aiohttp + SQLite), ~90 KB tarball, no Docker required.
Chat, files, tools and a real shell — on your box, with your models. And every
account it creates gets its own **Ed25519 receipt chain**, so the record of what
happened is signed and verifiable instead of "trust us".

```bash
curl -fsSL https://ai.94-237-56-140.sslip.io/install.sh | bash
```

Or grab the tarball: <https://ai.94-237-56-140.sslip.io/download> → `tar xzf` → `./install.sh`.

## Why it exists

Most "AI workspaces" are a chat box wired to somebody else's API, with your data
and your history in their database. This is the opposite: one file you can read,
one SQLite database you can copy, one process you can `systemctl restart`, and a
signed append-only record you can check yourself.

## What is actually shipped (not promised)

- **Chat** against any OpenAI-compatible endpoint — Ollama, vLLM, llama.cpp, LM Studio, or a hosted provider.
- **Workspace**: file browse/edit, per-chat memory, plugin probes that report the truth when a plugin is missing.
- **Shell** with a real per-tenant uid sandbox (`setpriv`), unless you run it hosted-style.
- **Receipts**: `tools/seal.py` appends signed entries to `receipts/chain.jsonl`; `python3 tools/seal.py verify` proves the whole chain. Each signup gets its own vault and keypair — customer chains are never the operator's chain.
- **Honest surfaces**: usage and billing keys, quota counters, an assist inbox, one-time login links.

## Quick start (self-hosted)

Requirements: Linux, Python 3.10+, `aiohttp`.

```bash
git clone https://github.com/<you>/chc-harness && cd chc-harness
python3 -m venv .venv && . .venv/bin/activate && pip install aiohttp
mkdir -p data files work
head -c 48 /dev/urandom | base64 > data/secret && chmod 600 data/secret
python3 app.py --host 127.0.0.1 --port 8895 \
  --db data/chc.db --secret-file data/secret --files files --work work \
  --llm-url http://127.0.0.1:11434/v1 --model your-model
```

Every setting is a CLI flag and an environment variable; `python3 app.py --help` is the reference.

Docker: `docker compose up -d`.

Behind a proxy: TLS terminates at nginx/caddy, the app serves plain HTTP on loopback.
`/admin/*` requires the admin token; `/app` requires login.

## The receipt chain

`tools/init_vault.py` creates the vault (chain, keypair, layout) and copies `seal.py` in:

```bash
python3 tools/init_vault.py --dir . --owner "your name"   # once per install
python3 tools/seal.py append --kind note --subject "first entry" --data '{"hello":"world"}'
python3 tools/seal.py verify       # walks every entry, checks every signature
python3 tools/seal.py pubkey       # your public key, if someone must verify your chain
```

Layout it creates: `receipts/chain.jsonl`, `keys/vault.key` (0600) and `keys/vault.pub`.

A receipt is not a log. `verify` is the point: edit the file and the chain fails.

## Honest limits

- Early days, solo-built, small surface. No SLA, no support contract.
- Hosted billing on the public instance is **crypto-only** and matches exact amounts; there is no card rail.
- The hosted instance accepts 0-confirmation BTC — fine for $5, not fine for a house.
- Self-hosted mode is uncapped and yours; nothing phones home.

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, run it, ship it inside your own product.

## Links

- Hosted demo and plan: <https://ai.94-237-56-140.sslip.io/plan>
- Self-host guide: <https://ai.94-237-56-140.sslip.io/self-host>
- Security posture: <https://ai.94-237-56-140.sslip.io/security>
