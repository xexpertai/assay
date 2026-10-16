"""Baseline / diff mode: new, fixed, unchanged and moved findings; CI exit codes; SARIF baselineState."""
import json
import shutil
from pathlib import Path

import pytest

from assay.actions import apply, approve
from assay.agent import run
from assay.baseline import BaselineError
from assay.cli import main

FIX = Path(__file__).resolve().parent.parent / "eval" / "fixtures"


@pytest.fixture(autouse=True)
def _keystore(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("ASSAY_KEYSTORE", str(tmp_path_factory.mktemp("keys")))


def _copy(case, dst):
    shutil.copytree(FIX / case, dst, ignore=shutil.ignore_patterns("expected.json"))
    return dst


def test_new_fixed_unchanged_and_moved(tmp_path):
    src = _copy("tf_ebs_kms", tmp_path / "repo")
    base_run = tmp_path / "base"
    base = run(str(src), base_run)
    baseline = base_run / "findings.json"
    # 1. fix one finding through the approval gate; 2. shift every line; 3. add a new weakness
    act = base.actions[0]
    approve(base_run, [act.id], "tester")
    apply(base_run)
    (src / "main.tf").write_text("# header comment added later\n\n" + (src / "main.tf").read_text())
    (src / "extra.tf").write_text('resource "aws_security_group" "x" {\n  name = "x"\n  ingress {\n    from_port = 22\n'
                                  '    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
    out = tmp_path / "next"
    res = run(str(src), out, baseline=baseline)
    d = res.diff
    fixed_ids = {x["id"] for x in d["fixed"]}
    assert act.finding_id in fixed_ids  # the patched volume, plus the snapshot finding derived from it
    assert {x["rule_id"] for x in d["fixed"]} == {"TF-AWS-EBS-UNENCRYPTED", "TF-AWS-EBS-SNAPSHOT-UNENCRYPTED"}
    assert [x["rule_id"] for x in d["new"]] == ["TF-AWS-SG-OPEN-ADMIN"]
    assert d["unchanged"] == 0 and d["moved"] == len(base.findings) - len(fixed_ids)  # survivors moved two lines
    assert d["baseline_sha256"] and any(x.stage == "compare" for x in res.decisions)
    data = json.loads((out / "findings.json").read_text())
    assert data["diff"]["new"][0]["rule_id"] == "TF-AWS-SG-OPEN-ADMIN"
    md = (out / "report.md").read_text()
    assert "## Changes since baseline" in md and "**1 new**" in md and "**2 fixed**" in md
    assert "Changes since baseline" in (out / "report.html").read_text()


def test_sarif_baseline_state_is_schema_valid(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    src = _copy("tf_ebs_kms", tmp_path / "repo")
    base_run = tmp_path / "base"
    base = run(str(src), base_run)
    approve(base_run, [base.actions[0].id], "tester")
    apply(base_run)
    out = tmp_path / "next"
    run(str(src), out, baseline=base_run / "findings.json")
    sarif = json.loads((out / "report.sarif").read_text())
    states = {r.get("baselineState") for r in sarif["runs"][0]["results"]}
    assert "absent" in states and states <= {"unchanged", "updated", "absent"}  # the patch inserted a line
    schema = json.loads((Path(__file__).parent / "data" / "sarif-2.1.0.json").read_text())
    jsonschema.Draft7Validator(schema).validate(sarif)


def test_cli_gate_exit_codes(tmp_path, capsys):
    src = _copy("tf_ebs_kms", tmp_path / "repo")
    base_run = tmp_path / "base"
    assert main(["scan", str(src), "--out", str(base_run), "--fail-on", "any"]) == 4  # findings exist
    assert main(["scan", str(src), "--out", str(tmp_path / "r1"), "--fail-on", "any",
                 "--fail-min-severity", "critical"]) == 0  # nothing critical in this fixture
    assert main(["scan", str(src), "--out", str(tmp_path / "r2"), "--baseline", str(base_run / "findings.json"),
                 "--fail-on", "new"]) == 0  # nothing new
    (src / "extra.tf").write_text('resource "aws_ebs_volume" "v" {\n  availability_zone = "a"\n  size = 1\n}\n')
    assert main(["scan", str(src), "--out", str(tmp_path / "r3"), "--baseline", str(base_run / "findings.json"),
                 "--fail-on", "new"]) == 4
    assert "1 new" in capsys.readouterr().out
    assert main(["scan", str(src), "--out", str(tmp_path / "r4"), "--baseline", str(tmp_path / "missing.json")]) == 2


def test_bad_baseline_refused_before_work(tmp_path):
    src = _copy("tf_ebs_kms", tmp_path / "repo")
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    with pytest.raises(BaselineError):
        run(str(src), tmp_path / "out", baseline=bad)
    assert not (tmp_path / "out").exists()
