"""Judge R3 fix 3: `assay step plan/approve/run` binds the approval to the exact step and always audits."""
import hashlib
import json
import os
import stat
from datetime import date, timedelta

import pytest

from assay.cli import main
from assay.steps import StepError, approve_step, plan_step, run_step

FAKE_NMAP = """#!/bin/sh
# offline stand-in for nmap: finds -oX <file> and the last argument (host)
while [ "$#" -gt 1 ]; do if [ "$1" = "-oX" ]; then out="$2"; fi; shift; done
printf '<?xml version="1.0"?><nmaprun><host><address addr="%s" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>' "$1" > "$out"
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSAY_KEYSTORE", str(tmp_path / "keys"))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "nmap"
    exe.write_text(FAKE_NMAP)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    lab = tmp_path / "lab.json"
    lab.write_text(json.dumps({"name": "lab", "authorised_by": "Lab Owner",
                               "expires": (date.today() + timedelta(days=5)).isoformat(),
                               "networks": ["10.10.0.0/24"]}))
    scope = tmp_path / "scope"
    scope.mkdir()
    return {"run": tmp_path / "run", "scope": str(scope), "lab": str(lab), "tmp": tmp_path}


def _plan(env, host="10.10.0.5", **kw):
    return plan_step(env["run"], env["scope"], env["lab"], "nmap-top-ports", host, "nmap.xml", **kw)


def test_full_flow_cli_and_evidence_is_scanned(env, capsys):
    r, sc, lab = str(env["run"]), env["scope"], env["lab"]
    assert main(["step", "plan", r, "--scope", sc, "--lab", lab, "--tool", "nmap-top-ports", "--host", "10.10.0.5",
                 "--out", "nmap.xml", "--requested-by", "agent"]) == 0
    sid = next(iter((env["run"] / "steps").iterdir())).name
    assert not (env["tmp"] / "scope" / "evidence").exists()  # planning ran nothing
    assert main(["step", "run", r, sid]) == 2  # refused: no approval
    assert main(["step", "approve", r, sid, "--by", "Harsha Shinde"]) == 0
    assert main(["step", "run", r, sid]) == 0
    assert (env["tmp"] / "scope" / "evidence" / "nmap.xml").exists()
    assert main(["step", "run", r, sid]) == 2  # single use
    assert main(["verify-log", r]) == 0
    events = [json.loads(l)["event"] for l in (env["run"] / "audit.jsonl").read_text().splitlines()]
    assert events[:2] == ["step_planned", "step_refused"]
    for e in ("step_approved", "step_run_started", "active_step_started", "active_step_finished", "step_run_finished"):
        assert e in events
    from assay.agent import run
    from assay.scope import ScopePolicy
    res = run(sc, policy=ScopePolicy.from_lab_file(lab))
    assert any(f.rule_id == "NMAP-OPEN-ADMIN" for f in res.findings)


def test_approval_is_bound_to_the_step(env):
    a = _plan(env, "10.10.0.5")
    b = _plan(env, "10.10.0.6")
    assert a["step_id"] != b["step_id"]
    approve_step(env["run"], a["step_id"], "Harsha")
    with pytest.raises(StepError, match="no approval for exactly this step"):
        run_step(env["run"], b["step_id"])
    run_step(env["run"], a["step_id"], dry_run=True)  # the approved one is fine


def test_requester_cannot_approve_by_editing_files(env):
    s = _plan(env, requested_by="agent")
    d = env["run"] / "steps" / s["step_id"]
    # 1. editing the step file to a different host breaks its hash
    doc = json.loads((d / "step.json").read_text())
    doc["core"]["host"] = "10.10.0.99"
    (d / "step.json").write_text(json.dumps(doc))
    with pytest.raises(StepError, match="edited after planning"):
        run_step(env["run"], s["step_id"])


def test_forged_approval_in_the_log_is_rejected(env):
    s = _plan(env)
    log = env["run"] / "audit.jsonl"
    prev = json.loads(log.read_text().splitlines()[-1])["hash"]
    rec = {"ts": "x", "stage": "act", "event": "step_approved", "prev": prev,
           "data": {"step_id": s["step_id"], "step_sha256": s["step_sha256"], "approver": "Someone"}}
    rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
    rec["mac"] = None  # cannot compute the HMAC without the run key
    with log.open("a") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
    with pytest.raises(StepError, match="not intact and authenticated"):
        run_step(env["run"], s["step_id"])


def test_host_outside_the_lab_is_refused_at_plan_time(env):
    with pytest.raises(StepError, match="not in lab"):
        _plan(env, "203.0.113.9")
    with pytest.raises(StepError, match="no runner profile"):
        plan_step(env["run"], env["scope"], env["lab"], "rm-rf", "10.10.0.5")


def test_lab_file_change_or_expiry_after_approval_blocks_run(env):
    s = _plan(env)
    approve_step(env["run"], s["step_id"], "Harsha")
    lab = json.loads(open(env["lab"]).read())
    lab["networks"].append("192.168.0.0/16")
    open(env["lab"], "w").write(json.dumps(lab))
    with pytest.raises(StepError, match="lab allowlist file changed"):
        run_step(env["run"], s["step_id"])
    with pytest.raises(StepError, match="expired"):
        run_step(env["run"], s["step_id"], today=date.today() + timedelta(days=30))


def test_empty_approver_refused_and_every_refusal_is_audited(env):
    s = _plan(env)
    with pytest.raises(StepError, match="name the person"):
        approve_step(env["run"], s["step_id"], "  ")
    with pytest.raises(StepError):
        run_step(env["run"], s["step_id"])
    events = [json.loads(l)["event"] for l in (env["run"] / "audit.jsonl").read_text().splitlines()]
    assert events.count("step_refused") == 1


def test_failed_run_still_consumes_the_approval(env, monkeypatch):
    s = _plan(env)
    approve_step(env["run"], s["step_id"], "Harsha")
    monkeypatch.setenv("PATH", "/nonexistent")  # tool 'not installed'
    with pytest.raises(StepError, match="not installed"):
        run_step(env["run"], s["step_id"])
    with pytest.raises(StepError, match="single use"):
        run_step(env["run"], s["step_id"])
