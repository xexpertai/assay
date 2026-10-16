"""Analyser plugin interface and registry.

An analyser declares which inventory kinds it consumes and turns those files into findings,
optionally adding relationships to the shared `Facts` used by correlation. Built-in analysers
cover Terraform, Kubernetes, compose, Dockerfiles, GitHub Actions, dependency manifests,
secrets and security-tool output files (nmap XML, nuclei JSONL, trivy JSON). Third-party
analysers register through the `assay.analysers` entry-point group and are listed in the
plan with their origin, so a report always says which code produced each decision.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

from .correlate import Facts
from .models import Finding

ALL_TEXT = "*"  # pseudo-kind: every readable text file


@runtime_checkable
class Analyser(Protocol):
    name: str  # shown in the plan and the audit log
    kinds: frozenset[str]  # inventory kinds consumed; {ALL_TEXT} means every text file

    def analyse(self, files: list[tuple[str, str]], facts: Facts) -> list[Finding]:
        """files: (relative path, text) for every in-scope file of a matching kind."""
        ...


@dataclass
class FunctionAnalyser:
    """Wrap a plain function as an analyser."""

    name: str
    kinds: frozenset[str]
    fn: Callable[[list[tuple[str, str]], Facts], list[Finding]]
    origin: str = "built-in"

    def analyse(self, files: list[tuple[str, str]], facts: Facts) -> list[Finding]:
        return self.fn(files, facts)


@dataclass
class PlanEntry:
    analyser: str
    run: bool
    reason: str
    origin: str = "built-in"
    files: int = 0


def _per_file(fn: Callable[[str, str], list[Finding]]):
    def inner(files: list[tuple[str, str]], facts: Facts) -> list[Finding]:
        out: list[Finding] = []
        for rel, txt in files:
            out += fn(rel, txt)
        return out
    return inner


def _terraform(files: list[tuple[str, str]], facts: Facts) -> list[Finding]:
    from .hcl import references, unquote
    from .rules import terraform
    out: list[Finding] = []
    by_dir: dict[str, list[tuple[str, str]]] = {}
    for rel, txt in files:  # references and variables are resolved per directory (one Terraform module)
        d = str(Path(rel).parent).replace("\\", "/")
        by_dir.setdefault("" if d == "." else d, []).append((rel, txt))
    called = terraform.module_sources(files)  # directories used as module sources
    parsed = {d: terraform.parse_all(g, apply_defaults=(d not in called)) for d, g in by_dir.items()}
    # one level of module arguments: literals a caller passes become the called module's variable values
    calls: dict[str, list[tuple[str, object]]] = {}
    for d, blocks in parsed.items():
        for rel, b in blocks:
            if b.type == "module":
                tgt = terraform.module_target(rel, unquote(b.get("source")))
                if tgt in by_dir and tgt != d:
                    calls.setdefault(tgt, []).append((rel, b))
    for tgt, cs in calls.items():
        declared = {b.labels[0] for _, b in parsed[tgt] if b.type == "variable" and b.labels}
        ov, notes = terraform.module_overrides(cs, declared)
        facts.skipped.extend(notes)
        parsed[tgt] = terraform.parse_all(by_dir[tgt], apply_defaults=True, overrides=ov)
    for d, group in by_dir.items():
        blocks = parsed[d]
        group = [(rel, txt) for rel, txt in group if rel.endswith(".tf")]
        for _, b in blocks:
            if b.type == "resource":  # union: the same address may appear in several module directories
                facts.tf_refs.setdefault(b.address, set()).update(references(b))
                if b.labels[0] in ("aws_iam_user", "aws_iam_role") and b.get("name"):
                    facts.iam_names[b.address] = b.get("name").strip('"')
        for rel, txt in group:
            out += terraform.analyse_file(rel, txt, blocks)
    return out


def _kubernetes(files: list[tuple[str, str]], facts: Facts) -> list[Finding]:
    from .rules import kubernetes
    out: list[Finding] = []
    for rel, txt in files:
        out += kubernetes.analyse_file(rel, txt)
        docs = kubernetes.load_docs(txt)
        skipped = kubernetes.unanalysed_kinds(docs)
        if skipped:
            facts.skipped.append((rel, f"no rules for kind(s) {', '.join(skipped)}"))
        for doc in docs:
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
    return out


def _secrets(files: list[tuple[str, str]], facts: Facts) -> list[Finding]:
    """Generic secret scan over every text file; runs last and skips lines a specific rule reported."""
    from .rules import secrets
    out: list[Finding] = []
    for rel, txt in files:
        skip = {ln for (fl, ln) in facts.specific_secret_lines if fl == rel}
        out += secrets.secret_findings(rel, txt, skip)
    return out


def builtin() -> list[FunctionAnalyser]:
    from .rules import dataops, events, kubernetes, misc, toolout
    return [
        FunctionAnalyser("Terraform rules (AWS + GCP)", frozenset({"terraform", "tfvars"}), _terraform),
        FunctionAnalyser("Kubernetes rules", frozenset({"kubernetes"}), _kubernetes),
        FunctionAnalyser("docker-compose rules", frozenset({"compose"}), _per_file(kubernetes.analyse_compose)),
        FunctionAnalyser("Dockerfile rules", frozenset({"dockerfile"}), _per_file(misc.analyse_dockerfile)),
        FunctionAnalyser("GitHub Actions rules", frozenset({"gha"}), _per_file(misc.analyse_workflow)),
        FunctionAnalyser("dependency-manifest rules", frozenset({"requirements"}),
                         _per_file(misc.analyse_requirements)),
        FunctionAnalyser("tool-output ingestion (nmap XML, nuclei JSONL, trivy JSON)",
                         frozenset({"nmap", "nuclei", "trivy"}), toolout.analyse),
        FunctionAnalyser("event-log rules (CloudTrail-style JSON/JSONL/CSV)", frozenset({"eventlog"}), events.analyse),
        FunctionAnalyser("DataOps config rules (Airflow, dbt, SQL grants, Kafka)",
                         frozenset({"airflow-config", "airflow-dag", "dbt-profile", "sql", "kafka"}), dataops.analyse),
        FunctionAnalyser("secret scan (all text files)", frozenset({ALL_TEXT}), _secrets),
    ]


def external() -> list[FunctionAnalyser]:
    """Analysers installed by other packages (entry-point group `assay.analysers`)."""
    out = []
    for ep in entry_points(group="assay.analysers"):
        try:
            obj = ep.load()
            obj = obj() if callable(obj) and not isinstance(obj, Analyser) else obj
            if isinstance(obj, Analyser):
                out.append(FunctionAnalyser(obj.name, frozenset(obj.kinds), obj.analyse, origin=f"plugin {ep.value}"))
        except Exception:  # a broken plugin must not break the assessment; it is reported as skipped
            out.append(FunctionAnalyser(f"{ep.name} (failed to load)", frozenset(), lambda f, x: [],
                                        origin=f"plugin {ep.value}"))
    return out


def registry() -> list[FunctionAnalyser]:
    return builtin() + external()


def plan(analysers: list[FunctionAnalyser], kinds: Counter) -> list[PlanEntry]:
    """Decide which analysers run, with a reason for every run and every skip."""
    out = []
    for a in analysers:
        if ALL_TEXT in a.kinds:
            out.append(PlanEntry(a.name, True, "credentials can hide in any file type", a.origin, sum(kinds.values())))
            continue
        n = sum(kinds.get(k, 0) for k in a.kinds)
        if not a.kinds:
            out.append(PlanEntry(a.name, False, "plugin could not be loaded", a.origin))
        elif n:
            out.append(PlanEntry(a.name, True, f"{n} {'/'.join(sorted(a.kinds))} file(s) in scope", a.origin, n))
        else:
            out.append(PlanEntry(a.name, False, f"no {'/'.join(sorted(a.kinds))} files found", a.origin))
    return out
