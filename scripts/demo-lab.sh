#!/usr/bin/env bash
# Offline demo of the approval-gated ACTIVE step flow. A fake `nmap` (a 3-line shell script that writes
# documentation-example XML) is put first on PATH, so nothing touches a network and no real scanner is needed.
# Flow: plan (runs nothing) -> run without approval is refused -> approve -> run -> second run refused (single
# use) -> the evidence file is scanned like any other file -> audit log verified. Usage: scripts/demo-lab.sh [--pause]
set -euo pipefail
cd "$(dirname "$0")/.."
PAUSE=${1:-}
step() { printf '\n\033[1m$ %s\033[0m\n' "$*"; [ "$PAUSE" = "--pause" ] && read -r; "$@" || true; }
D=runs/demo-lab
rm -rf "$D" && mkdir -p "$D/scope" "$D/bin"
export ASSAY_KEYSTORE="$PWD/$D/keys"          # demo-only audit key, never the user's real keystore
cat > "$D/bin/nmap" <<'EOF'
#!/bin/sh
while [ "$#" -gt 1 ]; do if [ "$1" = "-oX" ]; then out="$2"; fi; shift; done
printf '<?xml version="1.0"?><nmaprun><host><address addr="%s" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>' "$1" > "$out"
EOF
chmod +x "$D/bin/nmap"
export PATH="$PWD/$D/bin:$PATH"
EXP=$(python3 -c "import datetime;print(datetime.date.today()+datetime.timedelta(days=7))")
cat > "$D/lab.json" <<EOF
{"name": "demo-lab (documentation range)", "authorised_by": "Demo Lab Owner", "expires": "$EXP", "networks": ["10.10.0.0/24"]}
EOF
echo "Lab allowlist: 10.10.0.0/24 only, owner and expiry stated. Fake nmap on PATH; no network is used."

step uv run assay step plan "$D/run" --scope "$D/scope" --lab "$D/lab.json" --tool nmap-top-ports --host 203.0.113.9   # 1. outside the lab: refused
step uv run assay step plan "$D/run" --scope "$D/scope" --lab "$D/lab.json" --tool nmap-top-ports --host 10.10.0.5 --out nmap.xml --requested-by "planner agent"
SID=$(python3 -c "import os;print(sorted(os.listdir('$D/run/steps'))[0])")
step uv run assay step run "$D/run" "$SID"                                   # 2. no approval: refused and logged
step uv run assay step approve "$D/run" "$SID" --by "Demo Approver"          # 3. a named person approves THIS command
step uv run assay step run "$D/run" "$SID"                                   # 4. runs once
step uv run assay step run "$D/run" "$SID"                                   # 5. single use: refused
step uv run assay scan "$D/scope" --lab "$D/lab.json" --out "$D/scan"        # 6. evidence is analysed like any file
step uv run assay verify-log "$D/run"                                        # 7. every step is in the keyed audit log
echo; echo "Audit log: $D/run/audit.jsonl   Evidence: $D/scope/evidence/nmap.xml   Report: $D/scan/report.html"
