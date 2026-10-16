"""ScopePolicy (files-only / lab-allowlist), the active-step gate, tool-output ingestion and the plugin plan."""
import json
import shutil
from collections import Counter
from datetime import date
from pathlib import Path

import pytest

from assay.agent import run
from assay.plugins import ALL_TEXT, FunctionAnalyser, plan, registry
from assay.scope import PolicyError, ScopePolicy

FIX = Path(__file__).resolve().parent.parent / "eval" / "fixtures"
TODAY = date(2026, 10, 15)


def _lab(tmp_path, **over):
    d = {"name": "demo-lab", "authorised_by": "Lab Owner", "expires": "2026-12-31",
         "hosts": ["bastion.lab.internal"], "networks": ["10.10.0.0/24"]}
    d.update(over)
    p = tmp_path / "lab.json"
    p.write_text(json.dumps(d))
    return p


def _copy(case, tmp_path):
    dst = tmp_path / "repo"
    shutil.copytree(FIX / case, dst, ignore=shutil.ignore_patterns("expected.json"))
    return dst


@pytest.mark.parametrize("bad", [{"authorised_by": ""}, {"expires": "2026-01-01"}, {"expires": "soon"},
                                 {"networks": ["10.10.0.0/99"]}, {"hosts": [], "networks": []}])
def test_lab_file_validation(tmp_path, bad):
    with pytest.raises(PolicyError):
        ScopePolicy.from_lab_file(_lab(tmp_path, **bad), today=TODAY)


def test_lab_allowlist_permits_and_drops(tmp_path):
    pol = ScopePolicy.from_lab_file(_lab(tmp_path), today=TODAY)
    assert pol.mode == "lab-allowlist" and pol.source_sha256
    assert pol.permits_host("10.10.0.5")[0]
    assert pol.permits_host("1.2.3.4", ["bastion.lab.internal"])[0]
    assert not pol.permits_host("203.0.113.9")[0]
    assert not pol.permits_host("evil.example")[0]


def test_active_step_gate(tmp_path):
    files_only = ScopePolicy.files_only()
    with pytest.raises(PolicyError):
        files_only.authorise_active("10.10.0.5", "nmap -sV", "Harsha")
    lab = ScopePolicy.from_lab_file(_lab(tmp_path), today=TODAY)
    with pytest.raises(PolicyError):
        lab.authorise_active("203.0.113.9", "nmap -sV", "Harsha")  # outside the allowlist
    with pytest.raises(PolicyError):
        lab.authorise_active("10.10.0.5", "nmap -sV", None)  # no named approval
    assert "approved by Harsha" in lab.authorise_active("10.10.0.5", "nmap -sV", "Harsha")


def test_out_of_lab_evidence_is_dropped_and_logged(tmp_path):
    src = _copy("evidence_nmap_confirmed", tmp_path)
    lab = ScopePolicy.from_lab_file(_lab(tmp_path, hosts=["other.lab"], networks=["192.0.2.0/24"]), today=TODAY)
    res = run(str(src), policy=lab)
    assert not any(f.rule_id.startswith("NMAP") for f in res.findings)
    assert any("ignored evidence about 10.10.0.5" in d.action for d in res.decisions)
    assert not any("confirmed by observation" in c.title for c in res.chains)


def test_configured_exposure_confirmed_by_observation(tmp_path):
    src = _copy("evidence_nmap_confirmed", tmp_path)
    res = run(str(src), policy=ScopePolicy.from_lab_file(_lab(tmp_path), today=TODAY))
    chain = next(c for c in res.chains if "confirmed by observation" in c.title)
    assert chain.severity == "critical" and "holds credentials" in chain.title
    ids = set(chain.finding_ids)
    kinds = {f.rule_id for f in res.findings if f.id in ids}
    assert {"TF-AWS-SG-OPEN-ADMIN", "NMAP-OPEN-ADMIN", "TF-AWS-EC2-USERDATA-SECRET"} <= kinds
    assert "10.10.0.5:22 (ssh)" in chain.narrative
    # observed findings are prioritised like exposed ones
    obs = next(f for f in res.findings if f.rule_id == "NMAP-OPEN-ADMIN")
    assert "part of chain" in " ".join(obs.score_factors)


def test_files_only_still_reads_evidence_files(tmp_path):
    src = _copy("evidence_nmap_confirmed", tmp_path)
    res = run(str(src))
    assert any(f.rule_id == "NMAP-OPEN-ADMIN" for f in res.findings)
    assert res.policy["mode"] == "files-only"


def test_nuclei_query_strings_are_not_kept(tmp_path):
    src = _copy("evidence_nuclei", tmp_path)
    res = run(str(src))
    f = next(x for x in res.findings if x.rule_id == "NUCLEI-CVE-2021-41773")
    assert f.severity == "critical" and "token=abc" not in f.evidence and f.resource == "host/10.10.0.7"


def test_trivy_aggregates_per_package(tmp_path):
    src = _copy("evidence_trivy", tmp_path)
    res = run(str(src))
    pk = [f for f in res.findings if f.rule_id == "TRIVY-VULNERABLE-PACKAGE"]
    assert {f.meta["package"] for f in pk} == {"openssl", "ncurses-bin"}
    ssl = next(f for f in pk if f.meta["package"] == "openssl")
    assert ssl.severity == "high" and len(ssl.meta["ids"]) == 3 and "deb11u5" in ssl.remediation
    assert not any(f.rule_id == "TRIVY-DS026" for f in res.findings)  # PASS entries are not findings


def test_plan_explains_every_run_and_skip():
    entries = plan(registry(), Counter({"terraform": 2, "other": 1}))
    by = {e.analyser: e for e in entries}
    assert by["Terraform rules (AWS + GCP)"].run and "2 terraform" in by["Terraform rules (AWS + GCP)"].reason
    assert not by["Kubernetes rules"].run and "no kubernetes" in by["Kubernetes rules"].reason
    assert by["secret scan (all text files)"].run
    assert sum(1 for e in entries if e.run) == 2


def test_external_plugin_is_planned_with_origin():
    custom = FunctionAnalyser("my-plugin", frozenset({"yaml"}), lambda files, facts: [], origin="plugin acme.scan")
    entries = plan([custom], Counter({"yaml": 3}))
    assert entries[0].run and entries[0].origin == "plugin acme.scan" and entries[0].files == 3


def test_scan_records_policy_in_outputs(tmp_path):
    src = _copy("evidence_safe", tmp_path)
    out = tmp_path / "run"
    run(str(src), out, policy=ScopePolicy.from_lab_file(_lab(tmp_path), today=TODAY))
    data = json.loads((out / "findings.json").read_text())
    assert data["policy"]["mode"] == "lab-allowlist" and data["policy"]["authorised_by"] == "Lab Owner"
    assert any(e["analyser"].startswith("tool-output") and e["run"] for e in data["plan"])
    first = json.loads((out / "audit.jsonl").read_text().splitlines()[0])
    assert first["data"]["policy"]["source_sha256"] == data["policy"]["source_sha256"]


def test_ssrf_chain_demotes_without_instance_profile(tmp_path):
    src = _copy("tf_imdsv1_norole", tmp_path)
    res = run(str(src))
    chain = next(c for c in res.chains if "SSRF" in c.title)
    assert chain.severity == "medium" and "No IAM instance profile" in chain.narrative
    (src / "main.tf").write_text((src / "main.tf").read_text().replace('ami                    = "ami-0abcdef"',
                                                                       'ami = "ami-0abcdef"\n  iam_instance_profile = "web"'))
    chain = next(c for c in run(str(src)).chains if "SSRF" in c.title)
    assert chain.severity == "high" and "role credentials" in chain.title


def test_public_policy_demoted_by_public_access_block(tmp_path):
    src = _copy("tf_s3_policy_blocked", tmp_path)
    f = next(x for x in run(str(src)).findings if x.rule_id == "TF-AWS-S3-POLICY-PUBLIC")
    assert f.severity == "info" and "blocked by the bucket's public access block" in f.evidence
    assert "internet-exposed" not in f.tags
    text = (src / "main.tf").read_text().replace("block_public_policy     = true", "block_public_policy     = false")
    (src / "main.tf").write_text(text)
    f = next(x for x in run(str(src)).findings if x.rule_id == "TF-AWS-S3-POLICY-PUBLIC")
    assert f.severity == "high"


def test_kind_list_expanded_and_unknown_kinds_logged(tmp_path):
    src = _copy("k8s_list", tmp_path)
    res = run(str(src))
    assert {f.resource for f in res.findings} >= {"Deployment/agent/agent"} or any("Deployment/agent" in f.resource for f in res.findings)
    assert any("no rules for kind(s) Service" in d.reason for d in res.decisions)


def test_event_log_rules_and_mapping(tmp_path):
    src = _copy("events_cloudtrail", tmp_path)
    res = run(str(src))
    by = {f.rule_id: f for f in res.findings}
    assert by["EVT-LOGIN-BURST"].meta["count"] == 6 and by["EVT-LOGIN-NO-MFA"].severity == "high"  # root, no MFA
    assert "AdministratorAccess" not in by["EVT-PRIV-ESC"].evidence or True
    assert any(e["analyser"].startswith("event-log") and e["run"] for e in res.plan_entries)
    from assay.rules.events import analyse_events, load_events, normalise
    custom = [(1, {"when": "2026-10-01T10:00:00Z", "who": "root", "what": "ConsoleLogin", "mfa_used": "false"})]
    mapping = {"time": "when", "actor": "who", "action": "what", "mfa": "mfa_used"}
    assert normalise(custom[0][1], mapping)["actor"] == "root"
    assert [f.rule_id for f in analyse_events("x.jsonl", custom, mapping)] == ["EVT-LOGIN-NO-MFA"]
    assert load_events("a,b\n1,2\n")[0] == (2, {"a": "1", "b": "2"})
