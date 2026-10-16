#!/usr/bin/env bash
# One-minute end-to-end demo on a bundled fixture copy: refusal -> scan -> explain -> approve -> apply -> verify-log.
# Nothing here touches the network. Output goes to runs/demo/. Usage: scripts/demo.sh [--pause]
set -euo pipefail
cd "$(dirname "$0")/.."
PAUSE=${1:-}
step() { printf '\n\033[1m$ %s\033[0m\n' "$*"; [ "$PAUSE" = "--pause" ] && read -r; "$@" || true; }
rm -rf runs/demo && mkdir -p runs/demo
cp -r eval/fixtures/evidence_nmap_confirmed runs/demo/repo && rm -f runs/demo/repo/expected.json
cp eval/fixtures/tf_ebs_kms/main.tf runs/demo/repo/storage.tf
echo "Demo repo: runs/demo/repo (Terraform + an nmap evidence file; all values are documentation examples)"

step uv run assay scan https://example.com --out runs/demo/never            # 1. safety: network targets are refused
step uv run assay scan runs/demo/repo --out runs/demo/run                   # 2. assess local files (read-only)
CHAIN=$(python3 -c "import json;print(json.load(open('runs/demo/run/findings.json'))['chains'][0]['id'])")
step uv run assay explain runs/demo/run "$CHAIN"                            # 3. how the agent built the top chain
ACTION=$(python3 -c "import json;print(json.load(open('runs/demo/run/plan.json'))['actions'][0]['id'])")
step uv run assay apply runs/demo/run                                       # 4. apply without approval is refused
step uv run assay approve runs/demo/run "$ACTION" --by "Demo Approver"      # 5. a named person approves one action
step uv run assay apply runs/demo/run                                       # 6. only that action is applied
step uv run assay verify-log runs/demo/run                                  # 7. keyed, hash-chained audit log
step scripts/demo-dataops.sh                                                # 8. event logs + DataOps configs: kill chain, Airflow/Kafka/SQL chains, pending step
echo; echo "Reports: runs/demo/run/report.html (open in a browser), report.md, report.sarif, findings.json"
