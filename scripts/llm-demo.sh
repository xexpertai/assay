#!/usr/bin/env bash
# Start a temporary llama-server (any llama.cpp build + GGUF model), write LLM briefings for the
# sample scans, then stop the server. Usage: LLAMA_SERVER=... MODEL=... scripts/llm-demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=${PORT:-8091}
"$LLAMA_SERVER" -m "$MODEL" --host 127.0.0.1 --port "$PORT" -c 2048 -t 4 --jinja --reasoning off --no-webui \
  > runs/llama-$PORT.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for _ in $(seq 1 90); do curl -sf "http://127.0.0.1:$PORT/health" >/dev/null && break; sleep 2; done
for t in terragoat kubernetes-goat; do
  python3 -m assay scan "samples/$t" --out "runs/$t-llm" --llm --llm-url "http://127.0.0.1:$PORT"
done
