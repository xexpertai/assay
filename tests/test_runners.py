"""Active-step runner scaffold: every path is gated by the lab policy and a named approval."""
import json
from datetime import date
from pathlib import Path

import pytest

from assay.actions import AuditLog
from assay.runners import PROFILES, CommandRunner, DryRunRunner, RunnerError, StepRequest
from assay.scope import Scope, ScopePolicy


@pytest.fixture(autouse=True)
def _keystore(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("ASSAY_KEYSTORE", str(tmp_path_factory.mktemp("keys")))


def _lab(tmp_path):
    p = tmp_path / "lab.json"
    p.write_text(json.dumps({"name": "lab", "authorised_by": "Owner", "expires": "2026-12-31",
                             "networks": ["10.10.0.0/24"]}))
    return ScopePolicy.from_lab_file(p, today=date(2026, 10, 16))


def test_dry_run_requires_lab_policy_listed_host_and_approver(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    scope = Scope.from_target(str(repo))
    req = StepRequest("nmap-top-ports", "10.10.0.5", "Harsha", "nmap.xml")
    log = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(RunnerError, match="policy is files-only"):
        DryRunRunner().run(scope, ScopePolicy.files_only(), req, log)
    lab = _lab(tmp_path)
    with pytest.raises(RunnerError):
        DryRunRunner().run(scope, lab, StepRequest("nmap-top-ports", "203.0.113.9", "Harsha", "x.xml"), log)
    with pytest.raises(RunnerError):
        DryRunRunner().run(scope, lab, StepRequest("nmap-top-ports", "10.10.0.5", "", "x.xml"), log)
    with pytest.raises(RunnerError):
        DryRunRunner().run(scope, lab, StepRequest("rm-rf", "10.10.0.5", "Harsha", "x.xml"), log)  # undeclared profile
    with pytest.raises(RunnerError):
        DryRunRunner().run(scope, lab, StepRequest("nmap-top-ports", "10.10.0.5", "Harsha", "../escape.xml"), log)
    res = DryRunRunner().run(scope, lab, req, log)
    assert not res.ran and res.command[0] == "nmap" and "10.10.0.5" in res.command
    assert not list((repo / "evidence").iterdir())  # nothing written
    rec = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[-1])
    assert rec["event"] == "active_step_dry_run" and rec["data"]["approver"] == "Harsha"


def test_command_runner_refuses_missing_tool_and_logs(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    scope = Scope.from_target(str(repo))
    lab = _lab(tmp_path)
    monkeypatch.setitem(PROFILES, "fake-tool", ["definitely-not-installed-tool", "{host}", "{out}"])
    log = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(RunnerError):
        CommandRunner().run(scope, lab, StepRequest("fake-tool", "10.10.0.5", "Harsha", "out.txt"), log)
    events = [json.loads(l)["event"] for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert events[-2:] == ["active_step_started", "active_step_failed"]


def test_command_runner_output_becomes_evidence(tmp_path, monkeypatch):
    """A harmless stand-in command writes an nmap-style file; the normal scan then ingests it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    scope = Scope.from_target(str(repo))
    lab = _lab(tmp_path)
    script = tmp_path / "fake-nmap.sh"
    script.write_text('#!/bin/sh\nprintf \'<?xml version="1.0"?><nmaprun><host><address addr="%s" addrtype="ipv4"/>'
                      '<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
                      '</ports></host></nmaprun>\' "$1" > "$2"\n')
    script.chmod(0o755)
    monkeypatch.setitem(PROFILES, "fake-nmap", [str(script), "{host}", "{out}"])
    res = CommandRunner().run(scope, lab, StepRequest("fake-nmap", "10.10.0.5", "Harsha", "nmap.xml"),
                              AuditLog(tmp_path / "audit.jsonl"))
    assert res.ran and res.output_file == "evidence/nmap.xml" and res.output_sha256
    from assay.agent import run
    findings = run(str(repo), policy=lab).findings
    assert any(f.rule_id == "NMAP-OPEN-ADMIN" and f.resource == "host/10.10.0.5" for f in findings)


def test_runners_refuse_without_an_audit_log(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    scope = Scope.from_target(str(repo))
    lab = _lab(tmp_path)
    marker = tmp_path / "ran"
    monkeypatch.setitem(PROFILES, "touch-tool", ["touch", str(marker), "{host}", "{out}"])
    req = StepRequest("touch-tool", "10.10.0.5", "Harsha", "o.txt")
    for runner in (CommandRunner(), DryRunRunner()):
        with pytest.raises(RunnerError, match="audit log"):
            runner.run(scope, lab, req, None)
    assert not marker.exists()  # nothing executed
