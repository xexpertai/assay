#!/usr/bin/env bash
# LLM planner demo, $0: start a temporary local llama-server (heavy-job rules: one at a time, 3 GB memory cap),
# scan the fictional DataOps demo data with --llm-plan and a lab allowlist, then stop the server.
# Usage: LLAMA_SERVER=... MODEL=... scripts/llm-plan-demo.sh   (defaults point at the outside-hour copies)
set -euo pipefail
cd "$(dirname "$0")/.."
export LLAMA_SERVER=${LLAMA_SERVER:-$HOME/workspace/dev-hacktoberfest/outside-hour/.tools/llama/llama-b11555/llama-server}
export MODEL=${MODEL:-$HOME/workspace/dev-hacktoberfest/outside-hour/models/gemma-4-E2B-it-Q4_0.gguf}
export PORT=${PORT:-8091}
if [ "${INSIDE_LOCK:-}" != "1" ]; then
  exec env INSIDE_LOCK=1 flock "$HOME/workspace/.heavy.lock" systemd-run --user --scope -q -p MemoryMax=3G -p MemorySwapMax=256M "$0" "$@"
fi
D=runs/llm-plan; rm -rf "$D" && mkdir -p "$D/scope"
export ASSAY_KEYSTORE="$PWD/$D/keys"
EXP=$(python3 -c "import datetime;print(datetime.date.today()+datetime.timedelta(days=7))")
echo "{\"name\": \"demo-lab (documentation range)\", \"authorised_by\": \"Demo Lab Owner\", \"expires\": \"$EXP\", \"hosts\": [\"10.10.0.5\"]}" > "$D/lab.json"
"$LLAMA_SERVER" -m "$MODEL" --host 127.0.0.1 --port "$PORT" -c 4096 -t 4 --jinja --reasoning off --no-webui > "$D/llama.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; wait $SRV 2>/dev/null || true; echo "llama-server stopped"' EXIT
for _ in $(seq 1 90); do curl -sf "http://127.0.0.1:$PORT/health" >/dev/null && break; sleep 2; done
cp -r eval/demo-data/dataops "$D/scope/data"
.venv/bin/python -m assay scan "$D/scope" --lab "$D/lab.json" --out "$D/run" --llm-plan --llm-url "http://127.0.0.1:$PORT"
python3 - <<PY
import json
d = json.load(open("$D/run/findings.json"))
for x in d["decisions"]:
    if x["action"].startswith(("llm", "run")) and x["stage"] in ("plan", "act"):
        print(f"  [{x['stage']}] {x['action']}: {x['reason']}")
print("proposed steps:", d["proposed_steps"])
PY
.venv/bin/python -m assay verify-log "$D/run"
