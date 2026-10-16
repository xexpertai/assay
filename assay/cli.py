"""Command line: assay scan | explain | approve | apply | step plan/approve/run | verify-log."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .actions import ApprovalError, AuditLog, apply, approve
from .baseline import BaselineError, should_fail
from .explain import ExplainError
from .scope import PolicyError, ScopeError, ScopePolicy
from .steps import StepError


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="assay", description="Explainable, approval-gated security assessment of "
                                                          "local infrastructure-as-code, containers, CI and secrets.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="assess a local directory (read-only)")
    s.add_argument("target")
    s.add_argument("--out", default="runs/latest")
    s.add_argument("--llm", action="store_true", help="ask a local llama.cpp server for the briefing")
    s.add_argument("--llm-url", default=None)
    s.add_argument("--llm-plan", action="store_true",
                   help="let a local llama.cpp model order the analysers and propose follow-up active steps "
                        "(validated; steps are only planned, a named human still approves them)")
    s.add_argument("--baseline", default=None, metavar="FINDINGS_JSON",
                   help="a previous run's findings.json; report new / fixed / unchanged and set SARIF baselineState")
    s.add_argument("--fail-on", choices=["none", "new", "any"], default="none",
                   help="exit 4 when findings remain: 'new' = only findings absent from the baseline (default none)")
    s.add_argument("--fail-min-severity", choices=["critical", "high", "medium", "low", "info"], default="low",
                   help="lowest severity that counts for --fail-on (default low)")
    s.add_argument("--lab", default=None, metavar="LAB_JSON",
                   help="lab allowlist file (name, authorised_by, expires, hosts/networks); default is files-only")
    a = sub.add_parser("approve", help="approve specific proposed actions")
    a.add_argument("run_dir")
    a.add_argument("actions", nargs="+")
    a.add_argument("--by", required=True, help="name of the person approving (recorded in the audit log)")
    ap = sub.add_parser("apply", help="apply approved actions (refuses without a matching approval)")
    ap.add_argument("run_dir")
    v = sub.add_parser("verify-log", help="check the hash chain and HMAC of a run's audit log")
    v.add_argument("run_dir")
    ex = sub.add_parser("explain", help="show how the agent reached a finding (F-), chain (C-) or action (A-)")
    ex.add_argument("run_dir")
    ex.add_argument("id")
    st = sub.add_parser("step", help="human-in-the-loop active steps against an allowlisted lab host")
    stsub = st.add_subparsers(dest="step_cmd", required=True)
    sp = stsub.add_parser("plan", help="validate a declared tool profile against the lab allowlist; runs nothing")
    sp.add_argument("run_dir")
    sp.add_argument("--scope", required=True, help="directory that will receive the evidence file")
    sp.add_argument("--lab", required=True, metavar="LAB_JSON")
    sp.add_argument("--tool", required=True, help="declared profile, e.g. nmap-top-ports")
    sp.add_argument("--host", required=True)
    sp.add_argument("--out", default=None, help="evidence file name (default derived from tool and host)")
    sp.add_argument("--requested-by", default="", help="who asks for the step (recorded)")
    sa = stsub.add_parser("approve", help="approve exactly this step (shows the command that will run)")
    sa.add_argument("run_dir")
    sa.add_argument("step_id")
    sa.add_argument("--by", required=True)
    sr = stsub.add_parser("run", help="run an approved step (single use); --dry-run only logs it")
    sr.add_argument("run_dir")
    sr.add_argument("step_id")
    sr.add_argument("--dry-run", action="store_true")
    sr.add_argument("--timeout", type=int, default=600)
    u = sub.add_parser("ui", help="read-only local web page over a run directory (127.0.0.1 only)")
    u.add_argument("run_dir")
    u.add_argument("--port", type=int, default=8765)
    args = p.parse_args(argv)

    try:
        if args.cmd == "scan":
            from .agent import run
            policy = ScopePolicy.from_lab_file(args.lab) if args.lab else ScopePolicy.files_only()
            res = run(args.target, Path(args.out), use_llm=args.llm, llm_url=args.llm_url, policy=policy,
                      baseline=Path(args.baseline) if args.baseline else None,
                      planner_url=(args.llm_url or os.environ.get("ASSAY_LLM_URL", "http://127.0.0.1:8088")) if args.llm_plan else None)
            c = res.counts
            print(f"Assay: {c['findings']} findings, {c['chains']} chains, {len(res.actions)} proposed actions "
                  f"(nothing applied). Report: {Path(args.out) / 'report.md'} (+ report.html, report.sarif, findings.json)")
            for ch in res.chains[:3]:
                print(f"  [{ch.severity}] {ch.title}")
            if res.diff:
                d = res.diff
                print(f"  vs baseline: {len(d['new'])} new, {len(d['fixed'])} fixed, {d['unchanged']} unchanged, "
                      f"{d['moved']} moved")
            gate = should_fail(res.findings, res.diff, args.fail_on, args.fail_min_severity)
            if gate:
                print(f"  gate: {len(gate)} {'new ' if args.fail_on == 'new' else ''}finding(s) at or above "
                      f"{args.fail_min_severity}; exiting 4", file=sys.stderr)
                return 4
            return 0
        if args.cmd == "ui":
            from .ui import serve
            srv = serve(Path(args.run_dir), args.port)
            print(f"Assay UI (read-only) on http://127.0.0.1:{srv.server_address[1]}  - Ctrl-C to stop")
            try:
                srv.serve_forever()
            except KeyboardInterrupt:
                srv.server_close()
            return 0
        if args.cmd == "step":
            from . import steps
            rd = Path(args.run_dir)
            if args.step_cmd == "plan":
                rd.mkdir(parents=True, exist_ok=True)
                st_ = steps.plan_step(rd, args.scope, args.lab, args.tool, args.host, args.out, args.requested_by)
                print(f"Planned {st_['step_id']} (nothing executed). It would run:\n  {' '.join(st_['core']['argv'])}\n"
                      f"Lab '{st_['core']['lab_name']}' authorised by {st_['lab_authorised_by']} until {st_['lab_expires']}.\n"
                      f"Approve with: assay step approve {args.run_dir} {st_['step_id']} --by \"Full Name\"")
                return 0
            if args.step_cmd == "approve":
                r = steps.approve_step(rd, args.step_id, args.by)
                print(f"Approved {r['step_id']} by {r['approver']} for exactly: {' '.join(r['command'])}")
                return 0
            res = steps.run_step(rd, args.step_id, dry_run=args.dry_run, timeout_s=args.timeout)
            print(f"{'Dry run' if args.dry_run else 'Ran'} {args.step_id}: {res.note}"
                  + (f"; evidence {res.output_file} sha256 {res.output_sha256[:12]}" if res.output_sha256 else ""))
            return 0
        if args.cmd == "approve":
            rec = approve(Path(args.run_dir), args.actions, args.by)
            print(f"Approved {', '.join(rec['approved'])} by {rec['approver']} (plan {rec['plan_sha256'][:12]}).")
            return 0
        if args.cmd == "apply":
            done = apply(Path(args.run_dir))
            print(f"Applied {len(done)} approved action(s): {', '.join(done) or '-'}")
            return 0
        if args.cmd == "explain":
            from .explain import explain
            print(explain(Path(args.run_dir), args.id))
            return 0
        if args.cmd == "verify-log":
            r = AuditLog(Path(args.run_dir) / "audit.jsonl").verify_full()
            if not r["chain_ok"]:
                print(f"audit log TAMPERED: hash chain breaks after record {r['records']}")
                return 1
            if r["mac_ok"] is False:
                print(f"audit log TAMPERED: chain re-written without the run key (key {r['key_id']})")
                return 1
            if r["mac_ok"] is None:
                print(f"audit log chain intact ({r['records']} records) but NOT authenticated: key {r['key_id']} "
                      "is not in this machine's keystore")
                return 3
            print(f"audit log intact and authenticated ({r['records']} records, key {r['key_id']}, HMAC-SHA256)")
            return 0
    except (ScopeError, PolicyError, ApprovalError, ExplainError, BaselineError, StepError) as e:
        print(str(e), file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
