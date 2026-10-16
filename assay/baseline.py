"""Baseline / diff mode: compare a run with a previous run's findings.json.

Findings are matched by id first (rule | file | resource | line | key). A finding whose line moved
because the file was edited above it keeps a line-independent fingerprint (rule | file | resource |
key | evidence) and is reported as unchanged (moved), not as new. Findings in the baseline that are
absent now are reported as fixed. The result feeds the reports, the SARIF `baselineState` field and
the CI exit code (`assay scan --baseline previous/findings.json --fail-on new`).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import SEVERITIES, Finding


class BaselineError(ValueError):
    pass


def fingerprint(f: dict | Finding) -> str:
    d = f if isinstance(f, dict) else f.to_dict()
    key = f"{d['rule_id']}|{d['file']}|{d['resource']}|{(d.get('meta') or {}).get('key', '')}|{d['evidence']}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def load_baseline(path: Path) -> dict:
    if not path.is_file():
        raise BaselineError(f"refused: baseline '{path}' not found (expected a previous run's findings.json)")
    try:
        d = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise BaselineError(f"refused: baseline is not valid JSON ({e.msg})")
    if not isinstance(d, dict) or not isinstance(d.get("findings"), list):
        raise BaselineError("refused: baseline has no 'findings' list; use a findings.json written by assay scan")
    return d


def diff(current: list[Finding], baseline: dict, path: Path) -> dict:
    """{'new': [...], 'fixed': [...], 'unchanged': n, 'moved': n, 'state': {id: new|unchanged|updated}}."""
    base = {b["id"]: b for b in baseline["findings"] if isinstance(b, dict) and "id" in b}
    base_fp = {}
    for b in base.values():
        base_fp.setdefault(fingerprint(b), []).append(b["id"])
    state: dict[str, str] = {}
    matched: set[str] = set()
    for f in current:
        if f.id in base:
            state[f.id] = "unchanged"
            matched.add(f.id)
            continue
        cands = [i for i in base_fp.get(fingerprint(f), []) if i not in matched]
        if cands:
            state[f.id] = "updated"  # same weakness, different line
            matched.add(cands[0])
        else:
            state[f.id] = "new"
    fixed = [{"id": i, "rule_id": b.get("rule_id"), "title": b.get("title"), "severity": b.get("severity"),
              "file": b.get("file"), "line": b.get("line"), "resource": b.get("resource")}
             for i, b in base.items() if i not in matched]
    brief = lambda f: {"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity, "file": f.file,
                       "line": f.line}
    return {"baseline": str(path), "baseline_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "baseline_assay_version": baseline.get("assay_version"), "baseline_findings": len(base),
            "new": [brief(f) for f in current if state[f.id] == "new"],
            "fixed": sorted(fixed, key=lambda x: (x["file"] or "", x["line"] or 0)),
            "unchanged": sum(1 for s in state.values() if s == "unchanged"),
            "moved": sum(1 for s in state.values() if s == "updated"), "state": state}


def should_fail(findings: list[Finding], diff_result: dict | None, fail_on: str, min_severity: str) -> list[Finding]:
    """Findings that trip the CI gate: `fail_on` is none | new | any; `min_severity` is the lowest level counted."""
    if fail_on == "none":
        return []
    cutoff = SEVERITIES.index(min_severity)
    pool = findings
    if fail_on == "new":
        new_ids = {n["id"] for n in (diff_result or {}).get("new", [])} if diff_result else {f.id for f in findings}
        pool = [f for f in findings if f.id in new_ids]
    return [f for f in pool if SEVERITIES.index(f.severity) <= cutoff]
