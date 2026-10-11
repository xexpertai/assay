"""The assessment agent: scope -> recon -> plan -> analyse -> correlate -> prioritise -> propose -> report.

Each stage records its decisions (what it chose to run or skip and why) so the
reasoning behind the report can be audited.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .actions import AuditLog, plan_hash, propose
from .correlate import Facts, correlate, prioritise
from .hcl import references
from .inventory import build_inventory
from .models import Chain, Decision, Finding
from .narrate import narrate
from .rules import kubernetes, misc, secrets, terraform
from .scope import Scope

TEXT_KINDS = {"terraform", "kubernetes", "dockerfile", "compose", "gha", "env", "requirements", "yaml", "other"}
TEXT_SUFFIXES = {".tf", ".yml", ".yaml", ".json", ".env", ".sh", ".py", ".js", ".ts", ".txt", ".cfg", ".ini",
                 ".conf", ".properties", ".toml", ".xml", ".pem", ".key", ".php", ".go", ".rb", ".java", ""}


@dataclass
class Result:
    scope_root: str
    inventory: list
    decisions: list[Decision]
    findings: list[Finding]
    chains: list[Chain]
    actions: list
    narrative: dict
    counts: dict
    timings: dict = field(default_factory=dict)


def run(target: str, out_dir: Path | None = None, use_llm: bool = False, llm_url: str | None = None,
        max_files: int = 5000) -> Result:
    t0 = time.perf_counter()
    decisions: list[Decision] = []
    scope = Scope.from_target(target)  # raises on network targets
    log = None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        log = AuditLog(out_dir / "audit.jsonl")
        log.write("scope", "scope_accepted", root=str(scope.root), network_access=False)
    decisions.append(Decision("scope", f"accepted local directory {scope.root.name}",
                              "target is a local directory; no network targets, no symlinks leaving the root"))

    inv = build_inventory(scope)
    if len(inv) > max_files:
        decisions.append(Decision("recon", f"truncated inventory to {max_files} files", "file budget reached"))
        inv = inv[:max_files]
    kinds = Counter(a.kind for a in inv)
    decisions.append(Decision("recon", f"inventoried {len(inv)} files",
                              ", ".join(f"{k}: {v}" for k, v in sorted(kinds.items()))))
    if log:
        log.write("recon", "inventory", files=len(inv), kinds=dict(kinds))

    # ---- plan: pick analysers from what recon found
    plan = []
    for kind, analyser in (("terraform", "Terraform rules (AWS + GCP)"), ("kubernetes", "Kubernetes rules"),
                           ("compose", "docker-compose rules"), ("dockerfile", "Dockerfile rules"),
                           ("gha", "GitHub Actions rules"), ("requirements", "dependency-manifest rules")):
        if kinds.get(kind):
            plan.append(kind)
            decisions.append(Decision("plan", f"run {analyser}", f"{kinds[kind]} {kind} file(s) in scope"))
        else:
            decisions.append(Decision("plan", f"skip {analyser}", f"no {kind} files found"))
    decisions.append(Decision("plan", "run secret scan on all text files",
                              "credentials can hide in any file type"))

    texts: dict[str, str] = {}
    for a in inv:
        p = scope.root / a.path
        if a.kind in TEXT_KINDS and (a.kind != "other" or p.suffix.lower() in TEXT_SUFFIXES):
            try:
                texts[a.path] = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue

    # ---- analyse
    findings: list[Finding] = []
    facts = Facts()
    tf_files = [(a.path, texts[a.path]) for a in inv if a.kind == "terraform" and a.path in texts]
    # Terraform references are resolved per directory (one Terraform module)
    by_dir: dict[str, list[tuple[str, str]]] = {}
    for rel, txt in tf_files:
        by_dir.setdefault(str(Path(rel).parent), []).append((rel, txt))
    for _, files in by_dir.items():
        blocks = terraform.parse_all(files)
        for _, b in blocks:
            if b.type == "resource":
                facts.tf_refs[b.address] = references(b)
        for rel, txt in files:
            findings += terraform.analyse_file(rel, txt, blocks)
    for a in inv:
        txt = texts.get(a.path)
        if txt is None:
            continue
        if a.kind == "kubernetes":
            findings += kubernetes.analyse_file(a.path, txt)
            for doc in kubernetes.load_docs(txt):
                spec = kubernetes._pod_spec(doc)
                name = (doc.get("metadata") or {}).get("name")
                if isinstance(spec, dict):
                    facts.k8s_sa[f"{doc.get('kind')}/{name}"] = spec.get("serviceAccountName") or \
                        spec.get("serviceAccount") or "default"
                if doc.get("kind") in ("ClusterRoleBinding", "RoleBinding") and \
                        (doc.get("roleRef") or {}).get("name") == "cluster-admin":
                    for s in doc.get("subjects") or []:
                        if isinstance(s, dict) and s.get("kind") == "ServiceAccount":
                            facts.admin_sas.add(s.get("name"))
        elif a.kind == "compose":
            findings += kubernetes.analyse_compose(a.path, txt)
        elif a.kind == "dockerfile":
            findings += misc.analyse_dockerfile(a.path, txt)
        elif a.kind == "gha":
            findings += misc.analyse_workflow(a.path, txt)
        elif a.kind == "requirements":
            findings += misc.analyse_requirements(a.path, txt)
    # generic secret scan, skipping lines a specific rule already reported
    specific_secret_lines = {(f.file, f.line) for f in findings if "secret" in f.tags}
    for rel, txt in texts.items():
        skip = {ln for (fl, ln) in specific_secret_lines if fl == rel}
        findings += secrets.secret_findings(rel, txt, skip)
    # de-duplicate by id
    findings = list({f.id: f for f in findings}.values())
    decisions.append(Decision("analyse", f"{len(findings)} findings from {len(plan) + 1} analysers",
                              "rule results with evidence, rationale and remediation"))

    # ---- correlate + prioritise
    chains = correlate(findings, facts)
    chains.sort(key=lambda c: ("critical", "high", "medium", "low").index(c.severity))
    decisions.append(Decision("correlate", f"built {len(chains)} attack chain(s)",
                              "followed resource references, service-account bindings and secret fingerprints"))
    findings = prioritise(findings, chains)
    decisions.append(Decision("prioritise", "ranked findings by explained score",
                              "severity x confidence, +1 if internet-exposed, +1.5 if part of a chain"))

    # ---- propose (never apply)
    actions = propose(findings, scope)
    decisions.append(Decision("act", f"proposed {len(actions)} mechanical patch(es); applied 0",
                              "changes require explicit human approval of specific action IDs"))

    counts = {"files": len(inv), "findings": len(findings), "chains": len(chains),
              "by_severity": dict(Counter(f.severity for f in findings))}
    narrative = narrate(findings, chains, counts, use_llm, llm_url)
    decisions.append(Decision("report", f"briefing written by {narrative['author']}",
                              "; ".join(narrative["validation"]) or "passed grounding checks"))

    res = Result(str(scope.root), [a.__dict__ for a in inv], decisions, findings, chains, actions, narrative,
                 counts, {"total_s": round(time.perf_counter() - t0, 2)})
    if out_dir:
        write_outputs(res, out_dir, log)
    return res


def write_outputs(res: Result, out_dir: Path, log: AuditLog) -> None:
    from .report import to_markdown, to_sarif

    fix_by_id = {f.id: f.fix for f in res.findings}
    plan = {"scope_root": res.scope_root, "assay_version": __version__,
            "actions": [{**a.to_dict(), "fix": fix_by_id[a.finding_id]} for a in res.actions]}
    (out_dir / "plan.json").write_text(json.dumps(plan, indent=2))
    data = {"assay_version": __version__, "scope_root": res.scope_root, "counts": res.counts,
            "decisions": [d.to_dict() for d in res.decisions], "chains": [c.to_dict() for c in res.chains],
            "findings": [f.to_dict() for f in res.findings], "narrative": res.narrative,
            "plan_sha256": plan_hash(plan), "timings": res.timings}
    (out_dir / "findings.json").write_text(json.dumps(data, indent=2))
    (out_dir / "report.md").write_text(to_markdown(res))
    (out_dir / "report.sarif").write_text(json.dumps(to_sarif(res), indent=2))
    for d in res.decisions:
        log.write(d.stage, "decision", action=d.action, reason=d.reason)
    log.write("report", "outputs_written", plan_sha256=plan_hash(plan), findings=len(res.findings),
              chains=len(res.chains), actions=len(res.actions))
