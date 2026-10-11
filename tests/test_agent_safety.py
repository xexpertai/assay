import json
import shutil
from pathlib import Path

import pytest

from assay.actions import ApprovalError, AuditLog, apply, approve
from assay.agent import run
from assay.cli import main
from assay.scope import ScopeError

FIX = Path(__file__).resolve().parent.parent / "eval" / "fixtures"


def _copy(case, tmp_path):
    dst = tmp_path / "repo"
    shutil.copytree(FIX / case, dst, ignore=shutil.ignore_patterns("expected.json"))
    return dst


@pytest.mark.parametrize("target", ["http://example.com", "10.1.2.3", "10.0.0.0/8", "host.example:443"])
def test_network_targets_refused(target):
    with pytest.raises(ScopeError):
        run(target)


def test_cli_refusal_exit_code(capsys):
    assert main(["scan", "https://example.com", "--out", "/tmp/never"]) == 2


def test_symlink_escape_ignored(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.env").write_text("password = 'Zq8#mL2vT9xP'\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "link.env").symlink_to(outside / "secret.env")
    assert run(str(repo)).findings == []


def test_approval_gate_end_to_end(tmp_path):
    src = _copy("tf_ebs_kms", tmp_path)
    out = tmp_path / "run"
    before = (src / "main.tf").read_text()
    res = run(str(src), out)
    assert (src / "main.tf").read_text() == before  # scanning never writes
    with pytest.raises(ApprovalError):
        apply(out)
    ids = [a.id for a in res.actions]
    approve(out, ids[:1], "tester")
    assert apply(out) == ids[:1]
    rescan = {f.rule_id for f in run(str(src)).findings}
    fixed = next(f.rule_id for f in res.findings if f.id == res.actions[0].finding_id)
    assert fixed not in rescan
    ok, n = AuditLog(out / "audit.jsonl").verify()
    assert ok and n > 5


def test_unknown_action_rejected(tmp_path):
    src = _copy("tf_ebs_kms", tmp_path)
    out = tmp_path / "run"
    run(str(src), out)
    with pytest.raises(ApprovalError):
        approve(out, ["A-99"])


def test_changed_file_blocks_apply(tmp_path):
    src = _copy("tf_ebs_kms", tmp_path)
    out = tmp_path / "run"
    res = run(str(src), out)
    approve(out, [res.actions[0].id])
    (src / "main.tf").write_text((src / "main.tf").read_text() + "\n# edited\n")
    with pytest.raises(ApprovalError):
        apply(out)


def test_outputs_never_contain_full_secret(tmp_path):
    src = _copy("tf_provider_creds", tmp_path)
    out = tmp_path / "run"
    run(str(src), out)
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    for p in out.iterdir():
        assert secret not in p.read_text()


def test_sarif_valid_shape(tmp_path):
    src = _copy("k8s_rbac", tmp_path)
    out = tmp_path / "run"
    run(str(src), out)
    sarif = json.loads((out / "report.sarif").read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]


def test_k8s_takeover_chain(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "rbac.yaml").write_text((FIX / "k8s_rbac" / "rbac.yaml").read_text())
    (repo / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ci-runner\nspec:\n  serviceAccountName: ci\n"
        "  containers:\n    - name: r\n      image: r:1.0\n      securityContext:\n        privileged: true\n")
    chains = run(str(repo)).chains
    assert any("cluster-admin" in c.title and c.severity == "critical" for c in chains)


def test_llm_grounding_rejects_invented_numbers():
    from assay.narrate import validate
    facts = {"counts": {"findings": 3}, "chains": [], "top_findings": [{"id": "F-1", "title": "t",
             "severity": "high", "resource": "r", "score": 7.0}]}
    good = {"summary": "There are 3 issues.", "first_steps": [{"finding_id": "F-1", "why": "it is exposed"}]}
    bad = {"summary": "There are 42 issues and we fixed one.",
           "first_steps": [{"finding_id": "F-9", "why": "x"}]}
    assert validate(good, facts) == []
    assert len(validate(bad, facts)) == 3
