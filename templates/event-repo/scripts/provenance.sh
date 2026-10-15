#!/usr/bin/env bash
# Print the origin of every source file: the pinned `assay` dependency (tag + commit date) or this repo (first commit).
# Usage: scripts/provenance.sh > PROVENANCE.txt   (run from the event repo root; needs uv and git)
set -euo pipefail
cd "$(dirname "$0")/.."
ASSAY_DIR=$(uv run python -c "import assay, pathlib; print(pathlib.Path(assay.__file__).parent)")
ASSAY_VER=$(uv run python -c "import assay; print(assay.__version__)")
echo "# Provenance generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# Dependency: assay $ASSAY_VER from $ASSAY_DIR (pinned in pyproject.toml / uv.lock)"
echo
printf '%-60s %-12s %s\n' "FILE" "ORIGIN" "FIRST COMMIT / TAG"
find "$ASSAY_DIR" -name '*.py' | sort | while read -r f; do
  printf '%-60s %-12s %s\n' "assay/${f#"$ASSAY_DIR"/}" "dependency" "assay v$ASSAY_VER"
done
git ls-files | grep -E '\.(py|sh|toml|md|json|yaml|yml)$' | sort | while read -r f; do
  first=$(git log --diff-filter=A --follow --format='%ad' --date=iso-strict -- "$f" | tail -1)
  printf '%-60s %-12s %s\n' "$f" "event-repo" "$first"
done
