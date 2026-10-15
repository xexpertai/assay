"""Command line: assay scan | explain | approve | apply | verify-log."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .actions import ApprovalError, AuditLog, apply, approve
from .explain import ExplainError
from .scope import PolicyError, ScopeError, ScopePolicy


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="assay", description="Explainable, approval-gated security assessment of "
                                                          "local infrastructure-as-code, containers, CI and secrets.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="assess a local directory (read-only)")
    s.add_argument("target")
    s.add_argument("--out", default="runs/latest")
    s.add_argument("--llm", action="store_true", help="ask a local llama.cpp server for the briefing")
    s.add_argument("--llm-url", default=None)
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
    args = p.parse_args(argv)

    try:
        if args.cmd == "scan":
            from .agent import run
            policy = ScopePolicy.from_lab_file(args.lab) if args.lab else ScopePolicy.files_only()
            res = run(args.target, Path(args.out), use_llm=args.llm, llm_url=args.llm_url, policy=policy)
            c = res.counts
            print(f"Assay: {c['findings']} findings, {c['chains']} chains, {len(res.actions)} proposed actions "
                  f"(nothing applied). Report: {Path(args.out) / 'report.md'} (+ report.html, report.sarif, findings.json)")
            for ch in res.chains[:3]:
                print(f"  [{ch.severity}] {ch.title}")
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
    except (ScopeError, PolicyError, ApprovalError, ExplainError) as e:
        print(str(e), file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
