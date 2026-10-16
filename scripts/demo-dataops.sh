#!/usr/bin/env bash
# Event-log and DataOps demo on fictional data (eval/demo-data/dataops): CloudTrail intrusion, sshd brute force,
# Airflow / Kafka / SQL configs and an IAM user, all in one read-only scan. Usage: scripts/demo-dataops.sh [--pause]
set -euo pipefail
cd "$(dirname "$0")/.."
PAUSE=${1:-}
step() { printf '\n\033[1m$ %s\033[0m\n' "$*"; [ "$PAUSE" = "--pause" ] && read -r; "$@" || true; }
rm -rf runs/demo-dataops && mkdir -p runs/demo-dataops
echo "Fictional data (labelled in eval/demo-data/dataops/README.md): no real log, host or credential."
step uv run assay scan eval/demo-data/dataops --out runs/demo-dataops/run
python3 - <<'PY'
import json
d = json.load(open("runs/demo-dataops/run/findings.json"))
print("\nChains found:")
for c in d["chains"]:
    print(f"  [{c['severity']}] {c['title']}")
PY
CHAIN=$(python3 -c "import json;d=json.load(open('runs/demo-dataops/run/findings.json'));print(next(c['id'] for c in d['chains'] if c['title'].startswith('Brute force')))")
step uv run assay explain runs/demo-dataops/run "$CHAIN"
step uv run assay verify-log runs/demo-dataops/run
# a planned (not approved) active step, so the page's "Pending approvals" tab has something to show
EXP=$(python3 -c "import datetime;print(datetime.date.today()+datetime.timedelta(days=7))")
echo "{\"name\": \"demo-lab (documentation range)\", \"authorised_by\": \"Demo Lab Owner\", \"expires\": \"$EXP\", \"networks\": [\"10.10.0.0/24\"]}" > runs/demo-dataops/lab.json
mkdir -p runs/demo-dataops/scope
step uv run assay step plan runs/demo-dataops/run --scope runs/demo-dataops/scope --lab runs/demo-dataops/lab.json --tool nmap-top-ports --host 10.10.0.5 --requested-by "planner agent"
echo; echo "Open the read-only page:  uv run assay ui runs/demo-dataops/run   (http://127.0.0.1:8765)"
