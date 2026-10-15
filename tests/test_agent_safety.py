import json
import os
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
    res = run(str(src), out)
    with pytest.raises(ApprovalError):
        approve(out, ["A-99"], "tester")
    with pytest.raises(ApprovalError):  # an approval must name a person
        approve(out, [res.actions[0].id] if res.actions else ["A-01"], "  ")


def test_changed_file_blocks_apply(tmp_path):
    src = _copy("tf_ebs_kms", tmp_path)
    out = tmp_path / "run"
    res = run(str(src), out)
    approve(out, [res.actions[0].id], "tester")
    (src / "main.tf").write_text((src / "main.tf").read_text() + "\n# edited\n")
    with pytest.raises(ApprovalError):
        apply(out)


def test_outputs_never_contain_full_secret(tmp_path):
    src = _copy("tf_provider_creds", tmp_path)
    out = tmp_path / "run"
    run(str(src), out)
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert {p.name for p in out.iterdir()} >= {"report.md", "report.html", "report.sarif", "findings.json", "plan.json",
                                               "audit.jsonl"}
    for p in out.iterdir():
        assert secret not in p.read_text()


def test_html_report_is_self_contained_and_draws_chains(tmp_path):
    src = _copy("evidence_nmap_confirmed", tmp_path)
    out = tmp_path / "run"
    res = run(str(src), out)
    page = (out / "report.html").read_text()
    assert "<script" not in page and "http://" not in page.split("<body>")[0]  # no external assets, no scripts
    assert page.count("<svg") == len(res.chains) and all(c.id in page for c in res.chains)
    assert "AKIAIOSFODNN7EXAMPLE" not in page and "wJalrXUtnFEMI" not in page
    src2 = _copy("tf_ebs_kms", tmp_path / "b")
    run(str(src2), tmp_path / "run2")
    assert "<ins>" in (tmp_path / "run2" / "report.html").read_text()  # a proposed diff is rendered


def test_sarif_validates_against_schema(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    src = _copy("k8s_rbac", tmp_path)
    out = tmp_path / "run"
    run(str(src), out)
    sarif = json.loads((out / "report.sarif").read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    schema = json.loads((Path(__file__).parent / "data" / "sarif-2.1.0.json").read_text())
    jsonschema.Draft7Validator(schema).validate(sarif)  # raises on any violation


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


def test_multi_attribute_fix_applies_all_flags(tmp_path):
    src = _copy("tf_s3_v4_public", tmp_path)
    out = tmp_path / "run"
    res = run(str(src), out)
    act = next(a for a in res.actions if "block_public_acls" in a.description)
    approve(out, [act.id], "tester")
    assert apply(out) == [act.id]
    text = (src / "main.tf").read_text()
    assert text.count("= true") == 4 and "= false" not in text
    assert "TF-AWS-S3-PUBLIC-ACCESS-BLOCK-OFF" not in {f.rule_id for f in run(str(src)).findings}


@pytest.fixture(autouse=True)
def _private_keystore(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("ASSAY_KEYSTORE", str(tmp_path_factory.mktemp("keys")))


def test_audit_log_is_keyed(tmp_path, monkeypatch):
    src = _copy("tf_ebs_kms", tmp_path)
    out = tmp_path / "run"
    run(str(src), out)
    log = AuditLog(out / "audit.jsonl")
    r = log.verify_full()
    assert r["chain_ok"] and r["mac_ok"] is True and r["key_available"]
    key_id = r["key_id"]
    assert key_id and not any(key_id in p.name for p in out.iterdir())  # key is not in the run dir
    key_hex = (Path(os.environ["ASSAY_KEYSTORE"]) / f"{key_id}.key").read_text()
    assert all(key_hex not in p.read_text() for p in out.iterdir())
    # an attacker with write access regenerates a self-consistent chain without the key
    import hashlib
    lines = [json.loads(line) for line in (out / "audit.jsonl").read_text().splitlines()]
    prev = "0" * 64
    forged = []
    for rec in lines:
        rec.pop("hash"), rec.pop("mac")
        rec["prev"] = prev
        rec["data"]["forged"] = True
        rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
        rec["mac"] = "00" * 32
        prev = rec["hash"]
        forged.append(json.dumps(rec, sort_keys=True))
    (out / "audit.jsonl").write_text("\n".join(forged) + "\n")
    r = AuditLog(out / "audit.jsonl").verify_full()
    assert r["chain_ok"] and r["mac_ok"] is False
    assert main(["verify-log", str(out)]) == 1
    # without the key the chain is checked but not authenticated
    monkeypatch.setenv("ASSAY_KEYSTORE", str(tmp_path / "empty"))
    assert main(["verify-log", str(out)]) == 3


def test_short_secret_redaction_keeps_two_chars():
    from assay.rules.secrets import redact
    assert redact("Ab3$xy") == "Ab... (6 chars, redacted)"
    assert redact("wJalrXUtnFEMI/K7MDENG").startswith("wJal...")


def test_explain_finding_chain_and_action(tmp_path, capsys):
    src = _copy("evidence_nmap_confirmed", tmp_path)
    out = tmp_path / "run"
    res = run(str(src), out)
    chain = next(c for c in res.chains if "confirmed" in c.title)
    sg = next(f for f in res.findings if f.rule_id == "TF-AWS-SG-OPEN-ADMIN")
    assert main(["explain", str(out), sg.id]) == 0
    text = capsys.readouterr().out
    assert "decided by  run Terraform rules" in text and chain.id in text and "NMAP-OPEN-ADMIN" not in text
    assert "with " in text and "score" in text and "patch       none" in text
    assert main(["explain", str(out), chain.id]) == 0
    text = capsys.readouterr().out
    assert "built from" in text and "NMAP-OPEN-ADMIN" in text and "TF-AWS-EC2-USERDATA-SECRET" in text
    assert main(["explain", str(out), "F-00000000"]) == 2
    src2 = _copy("tf_ebs_kms", tmp_path / "b")
    out2 = tmp_path / "run2"
    res2 = run(str(src2), out2)
    aid = res2.actions[0].id
    assert main(["explain", str(out2), aid]) == 0
    assert "NOT approved" in capsys.readouterr().out
    approve(out2, [aid], "tester")
    apply(out2)
    assert main(["explain", str(out2), aid]) == 0
    text = capsys.readouterr().out
    assert "approved by tester" in text and "applied at" in text and "+" in text
