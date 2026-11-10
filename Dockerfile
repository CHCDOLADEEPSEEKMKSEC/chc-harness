# CHC HARNESS — self-host in one command
#   docker build -t chc-harness . && docker run -d -p 8895:8895 -v chc:/data --name chc chc-harness
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      tesseract-ocr ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir aiohttp
WORKDIR /app
COPY app.py seal.py init_vault.py recall.py senses.py paddy.py chat_memory_mcp.py smoke_test.py install.sh ./
ENV CHC_VAULT=/data/vault CHC_AI_SHOW_LINKS=1
RUN python3 init_vault.py --dir /data/vault --owner chc >/dev/null
EXPOSE 8895
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS http://127.0.0.1:8895/health || exit 1
CMD ["python3", "app.py", "--host", "0.0.0.0", "--port", "8895", \
     "--db", "/data/chc.db", "--secret-file", "/data/secret", \
     "--files", "/data/files", "--work", "/data/work", "--llm-url", "http://host.docker.internal:11434/v1/chat/completions"]
