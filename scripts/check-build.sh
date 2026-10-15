#!/usr/bin/env bash
# Build the wheel and sdist, install the wheel into a throwaway venv and run a smoke scan from it.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf dist && uv build -q 2>/dev/null || uv build >/dev/null
WHL=$(ls dist/*.whl)
TMP=$(mktemp -d)
uv venv -q "$TMP/venv" && uv pip install -q --python "$TMP/venv/bin/python" "$WHL"
"$TMP/venv/bin/assay" scan eval/fixtures/tf_ebs_kms --out "$TMP/run" >/dev/null
"$TMP/venv/bin/assay" verify-log "$TMP/run"
echo "wheel OK: $WHL ($(du -h "$WHL" | cut -f1))"
rm -rf "$TMP" dist
