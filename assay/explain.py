"""`assay explain RUN ID`: one screen that shows how the agent reached a finding, chain or action.

Everything comes from the run directory (findings.json, plan.json, approval.json, audit.jsonl);
nothing is recomputed, so the explanation matches the report that was delivered.
"""
from __future__ import annotations

import json
from pathlib import Path

PREFIX_TO_ANALYSER = {
    "TF-": "Terraform rules (AWS + GCP)", "K8S-": "Kubernetes rules", "COMPOSE-": "docker-compose rules",
    "DF-": "Dockerfile rules", "GHA-": "GitHub Actions rules", "DEP-": "dependency-manifest rules",
    "NMAP-": "tool-output ingestion", "NUCLEI-": "tool-output ingestion", "TRIVY-": "tool-output ingestion",
    "SECRET-": "secret scan",
}


class ExplainError(ValueError):
    pass


def _load(run_dir: Path) -> dict:
    fj = run_dir / "findings.json"
    if not fj.exists():
        raise ExplainError(f"no findings.json in {run_dir}; run `assay scan` first")
    data = json.loads(fj.read_text())
    plan = json.loads((run_dir / "plan.json").read_text()) if (run_dir / "plan.json").exists() else {"actions": []}
    appr = json.loads((run_dir / "approval.json").read_text()) if (run_dir / "approval.json").exists() else None
    audit = []
    if (run_dir / "audit.jsonl").exists():
        audit = [json.loads(ln) for ln in (run_dir / "audit.jsonl").read_text().splitlines() if ln.strip()]
    return {"data": data, "plan": plan, "approval": appr, "audit": audit}


def _analyser_for(rule_id: str) -> str:
    for pre, name in PREFIX_TO_ANALYSER.items():
        if rule_id.startswith(pre):
            return name
    return "unknown analyser"


def _plan_decision(data: dict, rule_id: str) -> str:
    name = _analyser_for(rule_id)
    for d in data.get("decisions", []):
        if d["stage"] == "plan" and name.split(" (")[0] in d["action"]:
            return f"{d['action']}: {d['reason']}"
    return f"ran {name}"


def _finding_lines(f: dict, data: dict, plan: dict, verbose: bool = True) -> list[str]:
    L = [f"FINDING {f['id']}  [{f['severity']} / confidence {f['confidence']}]  {f['title']}",
         f"  rule        {f['rule_id']}" + (f" ({f['cwe']})" if f.get("cwe") else ""),
         f"  where       {f['file']}:{f['line']}  resource {f['resource']}",
         f"  evidence    {f['evidence']}"]
    if not verbose:
        return L
    L += [f"  why         {f['rationale']}", f"  fix         {f['remediation']}",
          f"  score       {f['score']}  =  " + "  ".join(f["score_factors"]),
          f"  decided by  {_plan_decision(data, f['rule_id'])}"]
    chains = [c for c in data.get("chains", []) if f["id"] in c["finding_ids"]]
    if chains:
        for c in chains:
            others = [x for x in c["finding_ids"] if x != f["id"]]
            L.append(f"  chain       {c['id']} [{c['severity']}] {c['title']}")
            by_id = {x["id"]: x for x in data["findings"]}
            for o in others:
                g = by_id.get(o)
                L.append(f"              with {o}: {g['title'] if g else '?'}" + (f" ({g['file']}:{g['line']})" if g else ""))
    else:
        L.append("  chain       none (this finding stands alone)")
    acts = [a for a in plan.get("actions", []) if a["finding_id"] == f["id"]]
    if acts:
        for a in acts:
            L.append(f"  patch       {a['id']}: {a['description']} (proposed, not applied)")
            L += ["              " + ln for ln in a["diff"].rstrip().splitlines()]
    else:
        L.append("  patch       none proposed; fix by hand as described above")
    if f.get("meta"):
        shown = {k: v for k, v in f["meta"].items() if k != "key"}
        if shown:
            L.append(f"  facts       {json.dumps(shown, sort_keys=True)}")
    return L


def explain(run_dir: Path, ident: str) -> str:
    st = _load(run_dir)
    data, plan = st["data"], st["plan"]
    by_id = {f["id"]: f for f in data["findings"]}
    L: list[str] = []
    if ident.startswith("F-"):
        f = by_id.get(ident)
        if not f:
            raise ExplainError(f"unknown finding {ident}")
        L += _finding_lines(f, data, plan)
    elif ident.startswith("C-"):
        c = next((c for c in data.get("chains", []) if c["id"] == ident), None)
        if not c:
            raise ExplainError(f"unknown chain {ident}")
        L += [f"CHAIN {c['id']}  [{c['severity']}]  {c['title']}", f"  narrative   {c['narrative']}",
              f"  resources   {', '.join(c['resources'])}",
              "  built from  (deterministic correlation; every member is a finding you can check)"]
        for fid in c["finding_ids"]:
            f = by_id.get(fid)
            if f:
                L += ["    " + ln for ln in _finding_lines(f, data, plan, verbose=False)]
        d = next((d for d in data.get("decisions", []) if d["stage"] == "correlate"), None)
        if d:
            L.append(f"  decided by  {d['action']}: {d['reason']}")
    elif ident.startswith("A-"):
        a = next((a for a in plan.get("actions", []) if a["id"] == ident), None)
        if not a:
            raise ExplainError(f"unknown action {ident}")
        appr = st["approval"]
        status = "NOT approved"
        if appr and ident in appr["approved"]:
            status = f"approved by {appr['approver']} at {appr['ts']} (plan {appr['plan_sha256'][:12]})"
        applied = [r for r in st["audit"] if r.get("event") == "action_applied" and r["data"].get("action") == ident]
        L += [f"ACTION {a['id']}  {a['description']}", f"  file        {a['file']} (sha256 {a['file_sha256'][:12]} at scan time)",
              f"  status      {status}; " + (f"applied at {applied[0]['ts']}" if applied else "not applied"),
              "  diff"]
        L += ["    " + ln for ln in a["diff"].rstrip().splitlines()]
        f = by_id.get(a["finding_id"])
        if f:
            L.append("  fixes")
            L += ["    " + ln for ln in _finding_lines(f, data, plan, verbose=False)]
        L.append("  gate        apply refuses unless approval.json matches the plan hash and the file is unchanged")
    else:
        raise ExplainError("give a finding (F-…), chain (C-…) or action (A-…) id")
    return "\n".join(L)
