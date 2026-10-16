"""Stage 1 (recon): build an inventory of what is in scope and classify each file."""
from __future__ import annotations

import re
from pathlib import Path

from .models import Artifact
from .rules.dataops import kind_of as dataops_kind
from .rules.events import kind_of as event_kind, looks_like_unparsed_events
from .rules.toolout import kind_of as tool_kind
from .fileio import Unreadable, inner_name, is_other_compressed, read_text
from .scope import Scope

K8S_RE = re.compile(r"^\s*apiVersion:\s*\S+", re.M)
K8S_KIND_RE = re.compile(r"^\s*kind:\s*\S+", re.M)


def classify(path: Path, head: str, full: str | None = None) -> str:
    name = inner_name(path.name.lower())
    parts = [p.lower() for p in path.parts]
    tool = tool_kind(name, head) or event_kind(name, head, full) or dataops_kind(name, head)
    if tool:
        return tool
    if looks_like_unparsed_events(name, head):
        return "eventlog-unparsed"
    if name.endswith(".tf"):
        return "terraform"
    if name.endswith(".tfvars"):
        return "tfvars"
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


def build_inventory(scope: Scope, skipped: list | None = None) -> list[Artifact]:
    out: list[Artifact] = []
    for p in scope.files(skipped=skipped):
        if is_other_compressed(p.name):
            out.append(Artifact(scope.rel(p), "compressed-skipped", p.stat().st_size))
            continue
        try:
            full = read_text(p, scope.cap_for(p.name), errors="ignore")
        except Unreadable as e:
            if skipped is not None:
                skipped.append((scope.rel(p), str(e)))
            continue
        except OSError:
            continue
        kind = classify(p, full[:4000], full)
        if p.name.lower().endswith(".gz") and kind == "other":
            kind = "compressed-skipped"  # a gzip file that is not an event log: not understood, logged by the agent
        out.append(Artifact(scope.rel(p), kind, p.stat().st_size))
    return out
