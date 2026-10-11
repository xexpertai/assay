"""Command line: assay scan | approve | apply | verify-log."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .actions import ApprovalError, AuditLog, apply, approve
from .scope import ScopeError


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="assay", description="Explainable, approval-gated security assessment of "
                                                          "local infrastructure-as-code, containers, CI and secrets.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="assess a local directory (read-only)")
    s.add_argument("target")
    s.add_argument("--out", default="runs/latest")
    s.add_argument("--llm", action="store_true", help="ask a local llama.cpp server for the briefing")
    s.add_argument("--llm-url", default=None)
    a = sub.add_parser("approve", help="approve specific proposed actions")
    a.add_argument("run_dir")
    a.add_argument("actions", nargs="+")
    a.add_argument("--by", default=None, help="approver name recorded in the audit log")
    ap = sub.add_parser("apply", help="apply approved actions (refuses without a matching approval)")
    ap.add_argument("run_dir")
    v = sub.add_parser("verify-log", help="check the hash chain of a run's audit log")
    v.add_argument("run_dir")
    args = p.parse_args(argv)

    try:
        if args.cmd == "scan":
            from .agent import run
            res = run(args.target, Path(args.out), use_llm=args.llm, llm_url=args.llm_url)
            c = res.counts
            print(f"Assay: {c['findings']} findings, {c['chains']} chains, {len(res.actions)} proposed actions "
                  f"(nothing applied). Report: {Path(args.out) / 'report.md'}")
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
        if args.cmd == "verify-log":
            ok, n = AuditLog(Path(args.run_dir) / "audit.jsonl").verify()
            print(f"audit log {'intact' if ok else 'TAMPERED'} ({n} records verified)")
            return 0 if ok else 1
    except (ScopeError, ApprovalError) as e:
        print(str(e), file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
