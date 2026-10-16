"""Reproducible evaluation. Writes eval/results/*.json and eval/results/SUMMARY.md.

Usage:  python -m eval.run_eval   (run scripts/get-samples.sh first for the external sets)

1. Rule conformance suite: eval/fixtures/*, each with expected.json listing the exact rule IDs.
   Written by the builder (AI-assisted), so it checks rule behaviour; it is not an
   independent accuracy benchmark.
2. TerraGoat: recall against the weaknesses its own authors annotated in comments
   (Assay strips comments before analysis).
3. Kubernetes Goat: detection of statically visible, documented scenarios.
4. Safety checks: scope refusal, approval gate, tamper detection.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
from collections import Counter
from pathlib import Path

from assay.actions import ApprovalError, AuditLog, apply, approve
from assay.agent import run
from assay.scope import ScopeError

ROOT = Path(__file__).resolve().parent
INFO_ONLY = {"TF-AWS-SG-INTERNET-FACING", "NMAP-OPEN-PORT"}  # a case expecting only these counts as "safe"
RESULTS = ROOT / "results"
SAMPLES = ROOT.parent / "samples"


def fixtures() -> dict:
    cases = []
    tp = fp = fn = 0
    per_rule: Counter = Counter()
    for case in sorted(p for p in (ROOT / "fixtures").iterdir() if p.is_dir()):
        expected = set(json.loads((case / "expected.json").read_text())["expect"])
        with tempfile.TemporaryDirectory() as td:
            # copy without expected.json so the label file is never scanned
            dst = Path(td) / case.name
            shutil.copytree(case, dst, ignore=shutil.ignore_patterns("expected.json"))
            res = run(str(dst))
        got = {f.rule_id for f in res.findings}
        spec = json.loads((case / "expected.json").read_text())
        conf_ok = all(any(f.rule_id == r and f.confidence == c for f in res.findings)
                      for r, c in spec.get("confidence", {}).items()) and \
            all(any(f.rule_id == r and f.severity == v for f in res.findings) for r, v in spec.get("severity", {}).items())
        c_tp, c_fp, c_fn = expected & got, got - expected, expected - got
        tp, fp, fn = tp + len(c_tp), fp + len(c_fp), fn + len(c_fn)
        for r in c_fp:
            per_rule[f"FP {r}"] += 1
        for r in c_fn:
            per_rule[f"FN {r}"] += 1
        cases.append({"case": case.name, "safe_case": expected <= INFO_ONLY,
                      "expected": sorted(expected), "got": sorted(got), "pass": got == expected and conf_ok,
                      "false_positives": sorted(c_fp), "missed": sorted(c_fn)})
    safe = [c for c in cases if c["safe_case"]]
    return {"cases": cases, "n_cases": len(cases), "passed": sum(c["pass"] for c in cases),
            "rule_hits_tp": tp, "rule_hits_fp": fp, "rule_hits_fn": fn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "safe_cases": len(safe), "safe_cases_clean": sum(c["pass"] for c in safe),
            "errors": dict(per_rule)}


def terragoat() -> dict | None:
    target = SAMPLES / "terragoat"
    if not target.exists():
        return None
    labels = json.loads((ROOT / "terragoat_labels.json").read_text())["labels"]
    t = time.perf_counter()
    res = run(str(target))
    wall = round(time.perf_counter() - t, 2)
    rows = []
    matched_ids = set()
    for lab in labels:
        hit = [f for f in res.findings if f.rule_id in lab["accept"] and f.resource == lab["resource"]
               and f.file == lab["file"]]
        matched_ids.update(f.id for f in hit)
        rows.append({**lab, "detected": bool(hit), "by": sorted({f.rule_id for f in hit})})
    in_cov = [r for r in rows if not r.get("coverage")]
    stale = [r for r in rows if r.get("coverage") == "stale"]
    aws_extra = [f for f in res.findings if f.file.startswith("terraform/aws/") and f.id not in matched_ids
                 and f.severity != "info"]
    return {
        "labels_total": len(rows), "detected_total": sum(r["detected"] for r in rows),
        "labels_stale": [{"resource": r["resource"], "annotation": r["annotation"], "note": r["note"]} for r in stale],
        "labels_in_rule_coverage": len(in_cov), "detected_in_coverage": sum(r["detected"] for r in in_cov),
        "recall_all": round(sum(r["detected"] for r in rows) / len(rows), 3),
        "recall_in_coverage": round(sum(r["detected"] for r in in_cov) / len(in_cov), 3),
        "rows": rows, "total_findings": len(res.findings), "chains": [c.title for c in res.chains],
        "aws_findings_not_in_annotations": [
            {"id": f.id, "rule": f.rule_id, "resource": f.resource, "file": f.file, "line": f.line,
             "title": f.title} for f in aws_extra],
        "aws_unannotated_by_rule": dict(Counter(f.rule_id for f in aws_extra)),
        "proposed_actions": len(res.actions), "wall_s": wall, "files": res.counts["files"],
    }


def k8sgoat() -> dict | None:
    target = SAMPLES / "kubernetes-goat"
    if not target.exists():
        return None
    spec = json.loads((ROOT / "k8sgoat_scenarios.json").read_text())["scenarios"]
    t = time.perf_counter()
    res = run(str(target))
    wall = round(time.perf_counter() - t, 2)
    rows = []
    for s in spec:
        hit = sorted({f.rule_id for f in res.findings if f.file == s["file"] and f.rule_id in s["accept"]})
        rows.append({**s, "detected": bool(hit), "by": hit})
    return {"scenarios": len(rows), "detected": sum(r["detected"] for r in rows), "rows": rows,
            "total_findings": len(res.findings), "by_rule": dict(Counter(f.rule_id for f in res.findings)),
            "chains": [c.title for c in res.chains], "wall_s": wall, "files": res.counts["files"]}


def sadcloud() -> dict | None:
    """Blind sample: labels were written after the first run and the rules were frozen before it."""
    target = SAMPLES / "sadcloud"
    if not target.exists():
        return None
    spec = json.loads((ROOT / "sadcloud_labels.json").read_text())
    t = time.perf_counter()
    res = run(str(target))
    wall = round(time.perf_counter() - t, 2)
    rows = []
    for lab in spec["labels"]:
        hit = sorted({f.rule_id for f in res.findings if f.rule_id in lab["accept"] and f.file == lab["file"]
                      and (f.resource == lab["resource"] or f.resource == lab["file"])})
        rows.append({**lab, "detected": bool(hit), "by": hit})
    by_kind = {}
    for k in ("literal", "conditional", "variable", "none"):
        ks = [r for r in rows if r["kind"] == k]
        by_kind[k] = {"labels": len(ks), "detected": sum(r["detected"] for r in ks)}
    fair = [r for r in rows if r["kind"] in ("literal", "conditional")]
    return {"blind": True, "labels_total": len(rows), "by_kind": by_kind,
            "detected_in_rule_coverage": sum(r["detected"] for r in fair), "labels_in_rule_coverage": len(fair),
            "missed_in_coverage": [{"flag": r["flag"], "module": r["module"], "note": r.get("note", "")}
                                   for r in fair if not r["detected"]],
            "rows": rows, "total_findings": len(res.findings), "by_rule": dict(Counter(f.rule_id for f in res.findings)),
            "chains": [c.title for c in res.chains], "wall_s": wall, "files": res.counts["files"]}


def safety() -> dict:
    checks = []
    keystore = tempfile.mkdtemp(prefix="assay-keys-")
    os.environ["ASSAY_KEYSTORE"] = keystore  # keep evaluation keys out of the user's real keystore

    def check(name, fn):
        try:
            ok = fn()
        except Exception as e:  # a check that crashes counts as failed
            ok = False
            name += f" (error: {type(e).__name__})"
        checks.append({"check": name, "pass": bool(ok)})

    def refuses(target):
        try:
            run(target)
        except ScopeError:
            return True
        return False

    for t in ("https://example.com", "10.0.0.5", "192.168.1.0/24", "scanme.example.org:22"):
        check(f"refuses network target {t}", lambda t=t: refuses(t))

    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "repo"
        shutil.copytree(ROOT / "fixtures" / "tf_ebs_kms", src, ignore=shutil.ignore_patterns("expected.json"))
        out = Path(td) / "run"
        before = (src / "main.tf").read_text()
        res = run(str(src), out)
        check("scan changes no files", lambda: (src / "main.tf").read_text() == before)
        check("scan proposes patches", lambda: len(res.actions) >= 2)

        def no_approval():
            try:
                apply(out)
            except ApprovalError:
                return (src / "main.tf").read_text() == before
            return False
        check("apply refused without approval", no_approval)

        def tampered_plan():
            approve(out, [res.actions[0].id], "eval")
            plan = json.loads((out / "plan.json").read_text())
            plan["actions"][0]["fix"]["value"] = "false"
            (out / "plan.json").write_text(json.dumps(plan))
            try:
                apply(out)
            except ApprovalError:
                return True
            return False
        check("apply refused when plan edited after approval", tampered_plan)

    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "repo"
        shutil.copytree(ROOT / "fixtures" / "tf_ebs_kms", src, ignore=shutil.ignore_patterns("expected.json"))
        out = Path(td) / "run"
        res = run(str(src), out)
        approve(out, [res.actions[0].id], "eval")
        applied = apply(out)
        after = run(str(src))
        fixed_rule = next(f.rule_id for f in res.findings if f.id == res.actions[0].finding_id)
        check("only the approved action is applied", lambda: applied == [res.actions[0].id])
        check("approved patch removes its finding on re-scan",
              lambda: fixed_rule not in {f.rule_id for f in after.findings})
        check("audit log hash chain verifies", lambda: AuditLog(out / "audit.jsonl").verify()[0])

        def tamper_log():
            p = out / "audit.jsonl"
            lines = p.read_text().splitlines()
            rec = json.loads(lines[1])
            rec["data"]["tampered"] = True  # keep the old hash: an edit must break the chain
            lines[1] = json.dumps(rec, sort_keys=True)
            p.write_text("\n".join(lines) + "\n")
            return not AuditLog(p).verify()[0]
        check("audit log tampering detected", tamper_log)

        def forged_chain():
            # rebuild a self-consistent chain without the run key: hashes pass, MACs fail
            p = out / "audit.jsonl"
            prev, forged = "0" * 64, []
            for line in p.read_text().splitlines():
                rec = json.loads(line)
                rec.pop("hash"), rec.pop("mac", None)
                rec["prev"], rec["data"]["forged"] = prev, True
                rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
                rec["mac"] = "00" * 32
                prev = rec["hash"]
                forged.append(json.dumps(rec, sort_keys=True))
            p.write_text("\n".join(forged) + "\n")
            r = AuditLog(p).verify_full()
            return r["chain_ok"] and r["mac_ok"] is False
        check("re-written audit chain without the run key is detected (HMAC)", forged_chain)
        check("run key is stored outside the run directory",
              lambda: not any(p.suffix == ".key" for p in out.iterdir()) and os.listdir(keystore))

        def unnamed_approver():
            try:
                approve(out, [res.actions[0].id], "")
            except ApprovalError:
                return True
            return False
        check("approval without a named person is refused", unnamed_approver)

    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "repo"
        src.mkdir()
        key = "AKIA" + "IOSFODNN7EXAMPLE"
        (src / "app.env").write_text(f"AWS_ACCESS_KEY_ID={key}\n")
        out = Path(td) / "run"
        run(str(src), out)
        check("full secret never written to any output",
              lambda: all(key not in p.read_text() for p in out.iterdir()))
    return {"checks": checks, "passed": sum(c["pass"] for c in checks), "total": len(checks)}


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    out = {"fixtures": fixtures(), "terragoat": terragoat(), "kubernetes_goat": k8sgoat(), "sadcloud": sadcloud(),
           "safety": safety()}
    for k, v in out.items():
        (RESULTS / f"{k}.json").write_text(json.dumps(v, indent=2))
    f, tg, kg, sc, s = out["fixtures"], out["terragoat"], out["kubernetes_goat"], out["sadcloud"], out["safety"]
    lines = ["# Evaluation summary (generated by eval/run_eval.py)", "",
             f"- Rule conformance suite: {f['passed']}/{f['n_cases']} cases exact; rule-level precision "
             f"{f['precision']}, recall {f['recall']} (TP {f['rule_hits_tp']}, FP {f['rule_hits_fp']}, FN "
             f"{f['rule_hits_fn']}); safe cases clean {f['safe_cases_clean']}/{f['safe_cases']}."]
    if tg:
        lines.append(f"- TerraGoat annotated weaknesses: {tg['detected_in_coverage']}/{tg['labels_in_rule_coverage']} "
                     f"detected within rule coverage (AWS); {tg['detected_total']}/{tg['labels_total']} across all "
                     f"clouds. {tg['total_findings']} findings, {len(tg['chains'])} chains, "
                     f"{len(tg['aws_findings_not_in_annotations'])} AWS findings beyond the annotations "
                     f"(see terragoat.json), {tg['wall_s']} s.")
    if kg:
        lines.append(f"- Kubernetes Goat static scenarios: {kg['detected']}/{kg['scenarios']} detected; "
                     f"{kg['total_findings']} findings, {len(kg['chains'])} chains, {kg['wall_s']} s.")
    if sc:
        frozen = RESULTS / "sadcloud_blind_frozen.json"
        if frozen.exists():
            fz = json.loads(frozen.read_text())
            lines.append(f"- sadcloud BLIND result (rules frozen at tag rules-frozen-for-blind-sample, labels written after "
                         f"the first run, never re-tuned): {fz['detected_in_rule_coverage']}/{fz['labels_in_rule_coverage']} "
                         f"flags detected where a rule exists and the value is visible; misses: "
                         + ", ".join(m["flag"] for m in fz["missed_in_coverage"]) + ".")
        bk = sc["by_kind"]
        lines.append(f"- sadcloud after the post-blind fixes (NOT blind any more): "
                     f"{sc['detected_in_rule_coverage']}/{sc['labels_in_rule_coverage']} misconfiguration flags detected "
                     f"where Assay has a rule and the value is visible (literal {bk['literal']['detected']}/{bk['literal']['labels']}, "
                     f"conditional {bk['conditional']['detected']}/{bk['conditional']['labels']}); "
                     f"{bk['variable']['detected']}/{bk['variable']['labels']} where the value is a bare variable; "
                     f"{bk['none']['labels']} of {sc['labels_total']} flags have no Assay rule. "
                     f"{sc['total_findings']} findings, {len(sc['chains'])} chains, {sc['wall_s']} s.")
    lines.append(f"- Safety checks: {s['passed']}/{s['total']} passed.")
    if f["errors"]:
        lines.append(f"- Conformance errors: {f['errors']}")
    lines.append("")
    (RESULTS / "SUMMARY.md").write_text("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
