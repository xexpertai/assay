"""Runner scaffold for ACTIVE steps (for example running nmap against a lab host).

Every runner goes through the same gate, and none runs without an audit log (RunnerError if `log` is missing):
1. the ScopePolicy must be a lab allowlist and the host must be listed (`authorise_active`);
2. a named human approval must be given for this exact step;
3. the step is written to the audit log before and after it runs, with the command line and the
   sha256 of the output file;
4. the output is saved as a file inside the scan scope, so the normal file-only analysers
   (`rules/toolout.py`) turn it into findings. Runners never parse output themselves.

`DryRunRunner` records what would run without running anything. `CommandRunner` executes a
pre-declared command template (no shell, arguments are a fixed list, the host is the only variable)
and refuses anything not declared in its profile table.
"""
from __future__ import annotations

import hashlib
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .actions import AuditLog
from .scope import PolicyError, Scope, ScopePolicy


class RunnerError(RuntimeError):
    pass


@dataclass(frozen=True)
class StepRequest:
    tool: str  # profile name, e.g. "nmap-service-scan"
    host: str  # must be inside the lab allowlist
    approver: str  # named human who approved this exact step
    out_name: str  # file name inside the evidence directory


@dataclass
class StepResult:
    tool: str
    host: str
    command: list[str]
    output_file: str | None
    output_sha256: str | None
    ran: bool
    note: str
    seconds: float = 0.0


# Profiles: tool name -> argv template; "{host}" is the only substitution, "{out}" is the output path.
# Nothing here runs unless a lab policy, a listed host and a named approval are all present.
PROFILES: dict[str, list[str]] = {
    "nmap-service-scan": ["nmap", "-sV", "-Pn", "--max-rate", "50", "-oX", "{out}", "{host}"],
    "nmap-top-ports": ["nmap", "-Pn", "--top-ports", "100", "-oX", "{out}", "{host}"],
    "nuclei-safe": ["nuclei", "-u", "{host}", "-severity", "medium,high,critical", "-rate-limit", "10", "-jsonl",
                    "-o", "{out}"],
}


def _require_log(log) -> None:
    """Every active step is audited: a runner without an audit log refuses to run (no silent steps)."""
    if log is None or not hasattr(log, "write"):
        raise RunnerError("refused: an active step must be written to an audit log; none was supplied")


def _gate(policy: ScopePolicy, req: StepRequest) -> str:
    if req.tool not in PROFILES:
        raise RunnerError(f"refused: no runner profile named '{req.tool}' (declared: {', '.join(sorted(PROFILES))})")
    try:
        return policy.authorise_active(req.host, req.tool, req.approver)
    except PolicyError as e:
        raise RunnerError(str(e)) from e


def _evidence_path(scope: Scope, req: StepRequest, create: bool = True) -> Path:
    name = req.out_name
    if not name or name.startswith(".") or "/" in name or "\\" in name or ".." in name:
        raise RunnerError("refused: evidence file name must be a plain file name (no directories, no '..')")
    d = scope.root / "evidence"
    if create:
        d.mkdir(exist_ok=True)
    p = d / name
    if not scope.contains(p):
        raise RunnerError("refused: evidence path leaves the scope")
    return p


class DryRunRunner:
    """Checks the gate, logs the step, writes nothing, runs nothing."""

    def run(self, scope: Scope, policy: ScopePolicy, req: StepRequest, log: AuditLog) -> StepResult:
        _require_log(log)
        why = _gate(policy, req)
        out = _evidence_path(scope, req)
        cmd = [a.replace("{host}", req.host).replace("{out}", str(out)) for a in PROFILES[req.tool]]
        log.write("act", "active_step_dry_run", tool=req.tool, host=req.host, approver=req.approver,
                  command=shlex.join(cmd), reason=why)
        return StepResult(req.tool, req.host, cmd, None, None, False, f"dry run: {why}")


class CommandRunner:
    """Runs a declared profile for a permitted host and stores the output as evidence."""

    def __init__(self, timeout_s: int = 600):
        self.timeout_s = timeout_s

    def run(self, scope: Scope, policy: ScopePolicy, req: StepRequest, log: AuditLog) -> StepResult:
        _require_log(log)
        why = _gate(policy, req)
        out = _evidence_path(scope, req)
        cmd = [a.replace("{host}", req.host).replace("{out}", str(out)) for a in PROFILES[req.tool]]
        log.write("act", "active_step_started", tool=req.tool, host=req.host, approver=req.approver,
                  command=shlex.join(cmd), reason=why)
        t = time.perf_counter()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_s, check=False)
        except FileNotFoundError:
            log.write("act", "active_step_failed", tool=req.tool, host=req.host, reason="tool not installed")
            raise RunnerError(f"refused: '{cmd[0]}' is not installed on this machine")
        except subprocess.TimeoutExpired:
            log.write("act", "active_step_failed", tool=req.tool, host=req.host, reason="timeout")
            raise RunnerError(f"active step timed out after {self.timeout_s} s")
        secs = round(time.perf_counter() - t, 1)
        sha = hashlib.sha256(out.read_bytes()).hexdigest() if out.exists() else None
        log.write("act", "active_step_finished", tool=req.tool, host=req.host, exit_code=proc.returncode,
                  output_file=str(out.relative_to(scope.root)) if out.exists() else None, output_sha256=sha,
                  seconds=secs)
        if proc.returncode != 0 and not out.exists():
            raise RunnerError(f"{cmd[0]} exited {proc.returncode}: {proc.stderr.strip()[:200]}")
        return StepResult(req.tool, req.host, cmd, str(out.relative_to(scope.root)) if out.exists() else None, sha,
                          True, f"ran: {why}", secs)
