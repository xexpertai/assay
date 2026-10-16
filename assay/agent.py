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
from .inventory import build_inventory
from .models import Chain, Decision, Finding
from .narrate import narrate
from .plugins import ALL_TEXT, plan as make_plan, registry
from .scope import Scope, ScopePolicy

TEXT_KINDS = {"terraform", "tfvars", "kubernetes", "dockerfile", "compose", "gha", "env", "requirements", "yaml", "other",
              "nmap", "nuclei", "trivy", "eventlog", "eventlog-unparsed", "airflow-config", "airflow-dag", "dbt-profile", "sql", "kafka"}
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
    policy: dict = field(default_factory=dict)
    plan_entries: list = field(default_factory=list)
    diff: dict | None = None  # baseline comparison, when --baseline was given


def run(target: str, out_dir: Path | None = None, use_llm: bool = False, llm_url: str | None = None,
        max_files: int = 5000, policy: ScopePolicy | None = None, baseline: Path | None = None) -> Result:
    from .baseline import diff as diff_findings, load_baseline
    t0 = time.perf_counter()
    base_data = load_baseline(baseline) if baseline else None  # fail early, before any work
    decisions: list[Decision] = []
    scope = Scope.from_target(target)  # raises on network targets
    policy = policy or ScopePolicy.files_only()
    log = None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        log = AuditLog(out_dir / "audit.jsonl")
        log.write("scope", "scope_accepted", root=str(scope.root), network_access=False, policy=policy.to_dict())
    decisions.append(Decision("scope", f"accepted local directory {scope.root.name}",
                              "target is a local directory; no network targets, no symlinks leaving the root"))
    if policy.mode == "lab-allowlist":
        decisions.append(Decision("scope", f"lab allowlist '{policy.name}' active ({len(policy.hosts)} hosts, "
                                  f"{len(policy.networks)} networks)",
                                  f"authorised by {policy.authorised_by} until {policy.expires}; evidence about other "
                                  f"hosts is dropped; file sha256 {policy.source_sha256[:12]}"))
    else:
        decisions.append(Decision("scope", "policy files-only", "no host is in scope; tool output files are read as "
                                  "local evidence only; no active step can be authorised"))

    oversize: list[tuple[str, str]] = []
    inv = build_inventory(scope, oversize)
    for rel, why in oversize:
        decisions.append(Decision("recon", f"skipped {rel}", why))
    if len(inv) > max_files:
        decisions.append(Decision("recon", f"truncated inventory to {max_files} files", "file budget reached"))
        inv = inv[:max_files]
    kinds = Counter(a.kind for a in inv)
    for a in inv:
        if a.kind == "eventlog-unparsed":
            decisions.append(Decision("recon", f"skipped {a.path}: looks like an event log but could not be parsed",
                                      "the name and vocabulary suggest CloudTrail/auth events, but no record with a time "
                                      "and an action field could be read; supply a field mapping or convert to JSONL/CSV"))
    decisions.append(Decision("recon", f"inventoried {len(inv)} files",
                              ", ".join(f"{k}: {v}" for k, v in sorted(kinds.items()))))
    if log:
        log.write("recon", "inventory", files=len(inv), kinds=dict(kinds))

    # ---- plan: pick analysers from what recon found (every run and skip has a reason)
    analysers = registry()
    plan_entries = make_plan(analysers, kinds)
    for e in plan_entries:
        decisions.append(Decision("plan", f"{'run' if e.run else 'skip'} {e.analyser}", e.reason
                                  + ("" if e.origin == "built-in" else f" [{e.origin}]")))

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
    facts = Facts(policy=policy)
    by_kind: dict[str, list[tuple[str, str]]] = {}
    for a in inv:
        if a.path in texts:
            by_kind.setdefault(a.kind, []).append((a.path, texts[a.path]))
    ran = 0
    for an, e in zip(analysers, plan_entries):
        if not e.run:
            continue
        if ALL_TEXT in an.kinds:  # the secret scan runs last and skips lines a specific rule already reported
            facts.specific_secret_lines = {(f.file, f.line) for f in findings if "secret" in f.tags}
            files = sorted(texts.items())
        else:
            files = [fx for k in sorted(an.kinds) for fx in by_kind.get(k, [])]
        findings += an.analyse(files, facts)
        ran += 1
    for rel, host, why in facts.dropped:
        decisions.append(Decision("analyse", f"ignored evidence about {host} in {rel}", why))
    for rel, why in facts.skipped:
        decisions.append(Decision("analyse", f"skipped part of {rel}", why))
    # de-duplicate by id
    findings = list({f.id: f for f in findings}.values())
    decisions.append(Decision("analyse", f"{len(findings)} findings from {ran} analysers",
                              "rule results with evidence, rationale and remediation"))

    # ---- correlate + prioritise
    chains = correlate(findings, facts)
    chains.sort(key=lambda c: (("critical", "high", "medium", "low").index(c.severity), -len(c.finding_ids), c.id))
    decisions.append(Decision("correlate", f"built {len(chains)} attack chain(s)",
                              "followed resource references, service-account bindings, secret fingerprints and "
                              "observed ports from tool output"))
    findings = prioritise(findings, chains)
    decisions.append(Decision("prioritise", "ranked findings by explained score",
                              "severity x confidence, +1 if internet-exposed, +1.5 if part of a chain"))

    # ---- propose (never apply)
    actions = propose(findings, scope)
    decisions.append(Decision("act", f"proposed {len(actions)} mechanical patch(es); applied 0",
                              "changes require explicit human approval of specific action IDs"))

    counts = {"files": len(inv), "findings": len(findings), "chains": len(chains),
              "by_severity": dict(Counter(f.severity for f in findings))}
    diff_result = None
    if base_data is not None:
        diff_result = diff_findings(findings, base_data, baseline)
        decisions.append(Decision("compare", f"{len(diff_result['new'])} new, {len(diff_result['fixed'])} fixed, "
                                  f"{diff_result['unchanged']} unchanged, {diff_result['moved']} moved",
                                  f"compared with baseline {baseline} ({diff_result['baseline_findings']} findings, "
                                  f"sha256 {diff_result['baseline_sha256'][:12]}); matched by id, then by "
                                  "line-independent fingerprint"))
    narrative = narrate(findings, chains, counts, use_llm, llm_url)
    decisions.append(Decision("report", f"briefing written by {narrative['author']}",
                              "; ".join(narrative["validation"]) or "passed grounding checks"))

    res = Result(str(scope.root), [a.__dict__ for a in inv], decisions, findings, chains, actions, narrative,
                 counts, {"total_s": round(time.perf_counter() - t0, 2)}, policy.to_dict(),
                 [e.__dict__ for e in plan_entries], diff_result)
    if out_dir:
        write_outputs(res, out_dir, log)
    return res


def write_outputs(res: Result, out_dir: Path, log: AuditLog) -> None:
    from .html import to_html
    from .report import to_markdown, to_sarif

    fix_by_id = {f.id: f.fix for f in res.findings}
    plan = {"scope_root": res.scope_root, "assay_version": __version__,
            "actions": [{**a.to_dict(), "fix": fix_by_id[a.finding_id]} for a in res.actions]}
    (out_dir / "plan.json").write_text(json.dumps(plan, indent=2))
    data = {"assay_version": __version__, "scope_root": res.scope_root, "policy": res.policy,
            "plan": res.plan_entries, "counts": res.counts, "diff": res.diff,
            "decisions": [d.to_dict() for d in res.decisions], "chains": [c.to_dict() for c in res.chains],
            "findings": [f.to_dict() for f in res.findings], "narrative": res.narrative,
            "plan_sha256": plan_hash(plan), "timings": res.timings}
    (out_dir / "findings.json").write_text(json.dumps(data, indent=2))
    (out_dir / "report.md").write_text(to_markdown(res))
    (out_dir / "report.sarif").write_text(json.dumps(to_sarif(res), indent=2))
    (out_dir / "report.html").write_text(to_html(res))
    for d in res.decisions:
        log.write(d.stage, "decision", action=d.action, reason=d.reason)
    log.write("report", "outputs_written", plan_sha256=plan_hash(plan), findings=len(res.findings),
              chains=len(res.chains), actions=len(res.actions))
