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
    spec = json.loads((FIX / case / "expected.json").read_text())
    findings = run(str(dst)).findings
    assert {f.rule_id for f in findings} == set(spec["expect"])
    for rule, conf in spec.get("confidence", {}).items():  # e.g. non-literal CIDR expressions drop to medium
        assert {f.confidence for f in findings if f.rule_id == rule} == {conf}


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


def test_v4_bucket_findings_attach_to_the_bucket(tmp_path):
    dst = tmp_path / "x"
    shutil.copytree(FIX / "tf_s3_v4_public", dst, ignore=shutil.ignore_patterns("expected.json"))
    res = run(str(dst))
    assert {f.resource for f in res.findings} == {"aws_s3_bucket.exports"}
    pab = next(f for f in res.findings if f.rule_id == "TF-AWS-S3-PUBLIC-ACCESS-BLOCK-OFF")
    assert set(pab.fix["attrs"]) == {"block_public_acls", "block_public_policy", "ignore_public_acls",
                                     "restrict_public_buckets"}


def test_policy_statements_are_judged_separately():
    from assay.rules.terraform import _principal_any
    deny_star_allow_named = '{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*"},' \
                            '{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:role/r"},"Action":"s3:GetObject"}]}'
    assert not _principal_any(deny_star_allow_named)
    assert _principal_any('{"Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"s3:GetObject"}]}')
    assert _principal_any('jsonencode({Statement=[{Effect="Allow",Principal="*",Action="sts:AssumeRole"}]})')
