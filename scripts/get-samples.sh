#!/usr/bin/env bash
# Fetch the public, intentionally vulnerable sample repositories used in the evaluation,
# pinned to the exact commits that were evaluated. They are only read as text, never deployed or run.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p samples
if [ ! -d samples/terragoat ]; then
  git clone -q https://github.com/bridgecrewio/terragoat.git samples/terragoat   # Apache-2.0
  git -C samples/terragoat checkout -q 729f8da62c6a85ce4af5ad3d123de97776d954c4
fi
if [ ! -d samples/kubernetes-goat ]; then
  git clone -q --filter=blob:none --sparse https://github.com/madhuakula/kubernetes-goat.git samples/kubernetes-goat  # MIT
  git -C samples/kubernetes-goat sparse-checkout set scenarios infrastructure
  git -C samples/kubernetes-goat checkout -q 723a0db478f050d173d23b4ce5044b65bce0bdd0
fi
echo "samples ready: $(ls samples)"
