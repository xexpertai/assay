"""Human-in-the-loop flow for ACTIVE steps: plan -> approve -> run.

    assay step plan    <run_dir> --scope DIR --lab LAB --tool PROFILE --host HOST   (writes steps/S-xxxx/step.json)
    assay step approve <run_dir> S-xxxx --by "Full Name"                           (shows the exact command)
    assay step run     <run_dir> S-xxxx [--dry-run]

The approval is bound to the step: its id is a hash of {tool, host, exact argv, evidence file, scope root,
lab name and lab file hash}. Changing any of them changes the id, so an approval cannot be reused for a
different command or host. The approval lives in the HMAC-keyed audit log, not in a plain file, so it
cannot be fabricated by editing the run directory. An approval is single use: after a step has started
(even if it failed) it must be planned and approved again. Nothing here runs without an audit log.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .actions import AuditLog
from .runners import PROFILES, CommandRunner, DryRunRunner, RunnerError, StepRequest, _evidence_path
from .scope import PolicyError, Scope, ScopePolicy


class StepError(RuntimeError):
    pass


def _argv(tool: str, host: str, out: str) -> list[str]:
    return [a.replace("{host}", host).replace("{out}", out) for a in PROFILES[tool]]


def _step_hash(core: dict) -> str:
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()


def _dir(run_dir: Path, step_id: str) -> Path:
    if not step_id.startswith("S-") or not step_id[2:].isalnum():
        raise StepError(f"refused: '{step_id}' is not a step id (expected S-xxxxxxxx)")
    return run_dir / "steps" / step_id


def _load(run_dir: Path, step_id: str) -> dict:
    p = _dir(run_dir, step_id) / "step.json"
    if not p.exists():
        raise StepError(f"refused: no planned step {step_id} in {run_dir}")
    return json.loads(p.read_text())


def _recheck(step: dict, step_id: str) -> None:
    """The step file on disk must still hash to its id and its argv must still be the declared profile."""
    if _step_hash(step["core"]) != step["step_sha256"] or "S-" + step["step_sha256"][:8] != step_id:
        raise StepError("refused: the step file was edited after planning")
    c = step["core"]
    if c["tool"] not in PROFILES or _argv(c["tool"], c["host"], c["evidence"]) != c["argv"]:
        raise StepError("refused: the declared profile for this tool changed since planning; plan again")


def plan_step(run_dir: Path, scope_root: str, lab_file: str, tool: str, host: str, out_name: str | None = None,
              requested_by: str = "", today=None) -> dict:
    """Validate the whole gate except the approval, then record the step. Executes nothing."""
    if tool not in PROFILES:
        raise StepError(f"refused: no runner profile named '{tool}' (declared: {', '.join(sorted(PROFILES))})")
    try:
        policy = ScopePolicy.from_lab_file(lab_file, today=today)
    except PolicyError as e:
        raise StepError(str(e)) from e
    ok, why = policy.permits_host(host)
    if not ok:
        raise StepError(f"refused: active step '{tool}': {why}")
    scope = Scope.from_target(scope_root)
    out_name = out_name or f"{tool}-{host.replace(':', '_').replace('/', '_')}.out"
    try:
        out = _evidence_path(scope, StepRequest(tool, host, "-", out_name), create=False)
    except RunnerError as e:
        raise StepError(str(e)) from e
    core = {"tool": tool, "host": host, "argv": _argv(tool, host, str(out)), "evidence": str(out),
            "scope_root": str(scope.root), "lab_name": policy.name, "lab_sha256": policy.source_sha256,
            "lab_file": str(Path(lab_file).resolve())}
    h = _step_hash(core)
    sid = "S-" + h[:8]
    step = {"step_id": sid, "step_sha256": h, "core": core, "requested_by": requested_by.strip(),
            "planned_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "lab_expires": policy.expires,
            "lab_authorised_by": policy.authorised_by}
    d = _dir(run_dir, sid)
    d.mkdir(parents=True, exist_ok=True)
    (d / "step.json").write_text(json.dumps(step, indent=2))
    AuditLog(run_dir / "audit.jsonl").write("act", "step_planned", step_id=sid, step_sha256=h, tool=tool, host=host,
                                            command=" ".join(core["argv"]), lab=policy.name,
                                            requested_by=step["requested_by"])
    return step


def approve_step(run_dir: Path, step_id: str, approver: str | None) -> dict:
    if not approver or not approver.strip():
        raise StepError("refused: a step approval must name the person approving (--by \"Full Name\")")
    step = _load(run_dir, step_id)
    _recheck(step, step_id)
    log = AuditLog(run_dir / "audit.jsonl")
    if _events(log, "step_run_started", step_id):
        raise StepError(f"refused: step {step_id} has already been run; plan it again")
    log.write("act", "step_approved", step_id=step_id, step_sha256=step["step_sha256"], approver=approver.strip(),
              command=" ".join(step["core"]["argv"]), host=step["core"]["host"],
              self_approved=approver.strip().lower() == step["requested_by"].lower() and bool(step["requested_by"]))
    return {"step_id": step_id, "approver": approver.strip(), "command": step["core"]["argv"]}


def _events(log: AuditLog, event: str, step_id: str) -> list[dict]:
    if not log.path.exists():
        return []
    out = []
    for line in log.path.read_text().splitlines():
        rec = json.loads(line)
        if rec.get("event") == event and rec.get("data", {}).get("step_id") == step_id:
            out.append(rec)
    return out


def run_step(run_dir: Path, step_id: str, dry_run: bool = False, timeout_s: int = 600, today=None):
    log = AuditLog(run_dir / "audit.jsonl")
    if not log.path.exists():
        raise StepError("refused: no audit log in this run directory; plan the step first")

    def refuse(reason: str):
        log.write("act", "step_refused", step_id=step_id, reason=reason)
        raise StepError(f"refused: {reason}")

    step = _load(run_dir, step_id)
    try:
        _recheck(step, step_id)
    except StepError as e:
        refuse(str(e).removeprefix("refused: "))
    v = log.verify_full()
    if not v["chain_ok"] or v["mac_ok"] is not True:
        refuse("the audit log is not intact and authenticated under this machine's run key, so recorded "
               "approvals cannot be trusted")
    approvals = [r for r in _events(log, "step_approved", step_id)
                 if r["data"].get("step_sha256") == step["step_sha256"] and r["data"].get("approver")]
    if not approvals:
        refuse("no approval for exactly this step (id, command, host and lab must all match)")
    if _events(log, "step_run_started", step_id):
        refuse("this step was already run once; an approval is single use, plan and approve it again")
    c = step["core"]
    try:
        policy = ScopePolicy.from_lab_file(c["lab_file"], today=today)
    except PolicyError as e:
        refuse(str(e).removeprefix("refused: "))
    if policy.source_sha256 != c["lab_sha256"]:
        refuse("the lab allowlist file changed since the step was planned")
    approver = approvals[-1]["data"]["approver"]
    req = StepRequest(c["tool"], c["host"], approver, Path(c["evidence"]).name)
    scope = Scope.from_target(c["scope_root"])
    if dry_run:
        return DryRunRunner().run(scope, policy, req, log)
    log.write("act", "step_run_started", step_id=step_id, approver=approver)  # consumes the approval, even on failure
    try:
        res = CommandRunner(timeout_s).run(scope, policy, req, log)
    except RunnerError as e:
        log.write("act", "step_run_failed", step_id=step_id, reason=str(e)[:200])
        raise StepError(str(e)) from e
    (_dir(run_dir, step_id) / "result.json").write_text(json.dumps(res.__dict__, indent=2))
    log.write("act", "step_run_finished", step_id=step_id, output_file=res.output_file, output_sha256=res.output_sha256)
    return res
