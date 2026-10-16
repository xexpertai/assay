"""Judge R3 fix 2: chains for event logs and DataOps findings."""
import json

from assay.agent import run
from tests.test_event_intake import AUTH_LOG, _trail


def _chain_titles(res):
    return [c.title for c in res.chains]


def test_cloudtrail_intrusion_becomes_one_timeline_chain(tmp_path):
    t = _trail(20)
    ip = "203.0.113.9"
    t["Records"] += [
        {"eventTime": "2026-10-02T10:09:00Z", "eventName": "AttachUserPolicy", "userIdentity": {"arn": "arn:aws:iam::1:user/alice"},
         "sourceIPAddress": ip, "requestParameters": {"userName": "alice", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
        {"eventTime": "2026-10-02T10:10:00Z", "eventName": "CreateAccessKey", "userIdentity": {"arn": "arn:aws:iam::1:user/alice"},
         "sourceIPAddress": ip, "requestParameters": {"userName": "alice"}},
        {"eventTime": "2026-10-02T10:11:00Z", "eventName": "StopLogging", "userIdentity": {"arn": "arn:aws:iam::1:user/alice"},
         "sourceIPAddress": ip},
    ]
    (tmp_path / "trail.json").write_text(json.dumps(t, indent=1))
    res = run(str(tmp_path))
    ch = [c for c in res.chains if c.title.startswith("Brute force succeeded")]
    assert len(ch) == 1
    c = ch[0]
    assert c.severity == "critical" and len(c.finding_ids) >= 5
    for stage in ("privilege escalation", "persistence", "defence evasion"):
        assert stage in c.title
    assert any("same account" in f.title for f in res.findings if f.rule_id == "EVT-BRUTE-FORCE-SUCCESS")
    assert "Timeline:" in c.narrative and c.narrative.index("AttachUserPolicy") < c.narrative.index("StopLogging")


def test_unrelated_actors_are_not_chained(tmp_path):
    rec = lambda t, name, who, ip: {"eventTime": t, "eventName": name, "userIdentity": {"arn": f"arn:aws:iam::1:user/{who}"},
                                    "sourceIPAddress": ip}
    (tmp_path / "t.json").write_text(json.dumps({"Records": [
        rec("2026-10-02T10:00:00Z", "CreateAccessKey", "carol", "10.0.0.1"),
        rec("2026-10-02T10:01:00Z", "StopLogging", "dave", "10.0.0.2")]}))
    res = run(str(tmp_path))
    assert {f.rule_id for f in res.findings} >= {"EVT-NEW-ACCESS-KEY", "EVT-LOGGING-OFF"}
    assert not res.chains


def test_events_far_apart_are_not_chained(tmp_path):
    rec = lambda t, name: {"eventTime": t, "eventName": name, "userIdentity": {"arn": "arn:aws:iam::1:user/carol"},
                           "sourceIPAddress": "10.0.0.1"}
    (tmp_path / "t.json").write_text(json.dumps({"Records": [
        rec("2026-10-02T10:00:00Z", "CreateAccessKey"), rec("2026-10-05T10:01:00Z", "StopLogging")]}))
    assert not run(str(tmp_path)).chains


def test_auth_log_brute_force_chain_with_burst_and_success(tmp_path):
    (tmp_path / "auth.log").write_text(AUTH_LOG)
    res = run(str(tmp_path))
    assert not res.chains  # access stage only: one stage is not a multi-stage chain
    assert "EVT-BRUTE-FORCE-SUCCESS" in {f.rule_id for f in res.findings}


def test_log_actor_matches_iam_wildcard_in_terraform(tmp_path):
    (tmp_path / "iam.tf").write_text('''
resource "aws_iam_user" "alice" { name = "alice" }
resource "aws_iam_user_policy" "alice_admin" {
  name   = "admin"
  user   = aws_iam_user.alice.name
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
''')
    (tmp_path / "trail.json").write_text(json.dumps({"Records": [
        {"eventTime": "2026-10-02T10:00:00Z", "eventName": "CreateAccessKey",
         "userIdentity": {"arn": "arn:aws:iam::1:user/alice"}, "sourceIPAddress": "1.2.3.4"}]}))
    res = run(str(tmp_path))
    assert any("'alice'" in t and "Terraform grants" in t for t in _chain_titles(res)), _chain_titles(res)


def test_airflow_kafka_and_sql_combinations(tmp_path):
    (tmp_path / "airflow.cfg").write_text(
        "[api]\nauth_backends = airflow.api.auth.backend.default\n"
        "[database]\nsql_alchemy_conn = postgresql+psycopg2://airflow:S3cretPw99@db/airflow\n")
    (tmp_path / "server.properties").write_text(
        "listeners=PLAINTEXT://0.0.0.0:9092\nallow.everyone.if.no.acl.found=true\nbroker.id=1\n")
    (tmp_path / "grants.sql").write_text("GRANT SELECT ON t TO PUBLIC;\nCREATE USER etl IDENTIFIED BY 'Sup3rSecretPw';\n")
    res = run(str(tmp_path))
    titles = _chain_titles(res)
    assert any(t.startswith("Unauthenticated Airflow exposes stored credentials") for t in titles), titles
    assert any(t.startswith("Kafka broker is unauthenticated and unencrypted") for t in titles), titles
    assert any(t.startswith("Database script hard-codes a password") for t in titles), titles


def test_safe_dataops_files_make_no_chain(tmp_path):
    (tmp_path / "airflow.cfg").write_text("[api]\nauth_backends = airflow.api.auth.backend.basic_auth\n")
    (tmp_path / "server.properties").write_text("listeners=SASL_SSL://0.0.0.0:9093\nauthorizer.class.name=kafka.security.authorizer.AclAuthorizer\nbroker.id=1\n")
    assert not run(str(tmp_path)).chains
