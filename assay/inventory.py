"""Stage 1 (recon): build an inventory of what is in scope and classify each file."""
from __future__ import annotations

import re
from pathlib import Path

from .models import Artifact
from .scope import Scope

K8S_RE = re.compile(r"^\s*apiVersion:\s*\S+", re.M)
K8S_KIND_RE = re.compile(r"^\s*kind:\s*\S+", re.M)


def classify(path: Path, head: str) -> str:
    name = path.name.lower()
    parts = [p.lower() for p in path.parts]
    if name.endswith(".tf"):
        return "terraform"
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return "dockerfile"
    if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return "compose"
    if name.endswith((".yml", ".yaml")):
        if ".github" in parts and "workflows" in parts:
            return "gha"
        if K8S_RE.search(head) and K8S_KIND_RE.search(head) and "{{" not in head:
            return "kubernetes"
        return "yaml"
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return "env"
    if name in {"requirements.txt", "package.json"}:
        return "requirements"
    return "other"


def build_inventory(scope: Scope) -> list[Artifact]:
    out: list[Artifact] = []
    for p in scope.files():
        try:
            head = p.read_text(encoding="utf-8", errors="ignore")[:4000]
        except OSError:
            continue
        out.append(Artifact(scope.rel(p), classify(p, head), p.stat().st_size))
    return out
