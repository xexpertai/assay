import json
import shutil
from pathlib import Path

import pytest

from assay.agent import run
from assay.rules.secrets import redact, scan_text

FIX = Path(__file__).resolve().parent.parent / "eval" / "fixtures"
CASES = sorted(p.name for p in FIX.iterdir() if p.is_dir())


@pytest.mark.parametrize("case", CASES)
def test_fixture_exact(case, tmp_path):
    dst = tmp_path / case
    shutil.copytree(FIX / case, dst, ignore=shutil.ignore_patterns("expected.json"))
    expected = set(json.loads((FIX / case / "expected.json").read_text())["expect"])
    assert {f.rule_id for f in run(str(dst)).findings} == expected


def test_secret_patterns_and_redaction():
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    hits = scan_text(f"x = {key}\npassword = 'Zq8#mL2vT9xP'\nhttp_tokens = \"required\"\n")
    kinds = [h.kind for h in hits]
    assert "AWS access key ID" in kinds
    assert any("password" in k for k in kinds)
    assert not any("http_tokens" in k for k in kinds)
    assert key not in redact(key) and redact(key).startswith("AKIA...")


def test_private_key_header_detected():
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----"
    assert scan_text(pem)[0].kind == "private key"


def test_findings_are_explained(tmp_path):
    dst = tmp_path / "x"
    shutil.copytree(FIX / "tf_rds_public", dst, ignore=shutil.ignore_patterns("expected.json"))
    for f in run(str(dst)).findings:
        assert f.rationale and f.remediation and f.evidence and f.score_factors
