"""Regression tests for judge R3 small bugs: URI redaction, SQL line numbers, logging-enabled false positive."""
import json

from assay.agent import run
from assay.rules.dataops import analyse_airflow_config, analyse_sql
from assay.rules.events import analyse_events


def test_airflow_conn_evidence_has_user_not_backreference():
    f = analyse_airflow_config("airflow.cfg", "[database]\nsql_alchemy_conn = postgresql+psycopg2://airflow:S3cretPw99@db/airflow\n")
    ev = next(x for x in f if x.rule_id == "AIRFLOW-CONN-PASSWORD").evidence
    assert "\\1" not in ev and "airflow:<redacted>@db" in ev and "S3cretPw99" not in ev


def test_sql_line_numbers_are_exact():
    sql = "-- header\nGRANT ALL PRIVILEGES ON *.* TO a;\n\n-- note\nGRANT SELECT ON t TO PUBLIC;\nCREATE USER bob IDENTIFIED BY 'Sup3rSecretPw';\n"
    got = {f.rule_id: f.line for f in analyse_sql("g.sql", sql)}
    assert got["SQL-GRANT-ALL-GLOBAL"] == 2
    assert got["SQL-GRANT-PUBLIC"] == 5
    assert got["SQL-USER-PASSWORD-LITERAL"] == 6
    ev = next(f for f in analyse_sql("g.sql", sql) if f.rule_id == "SQL-USER-PASSWORD-LITERAL").evidence
    assert "bob" in ev and "Sup3rSecretPw" not in ev


def _ev(name, rp=None):
    r = {"eventTime": "2026-01-01T10:00:00Z", "eventName": name, "userIdentity": {"arn": "arn:aws:iam::1:user/a"},
         "sourceIPAddress": "1.2.3.4"}
    if rp is not None:
        r["requestParameters"] = rp
    return (1, r)


def test_enabling_logging_is_not_flagged_but_disabling_is():
    on = analyse_events("t.jsonl", [_ev("PutBucketLogging", {"bucketLoggingStatus": {"LoggingEnabled": {"TargetBucket": "x"}}})])
    off = analyse_events("t.jsonl", [_ev("PutBucketLogging", {"bucketLoggingStatus": {}})])
    assert not [f for f in on if f.rule_id == "EVT-LOGGING-OFF"]
    assert [f for f in off if f.rule_id == "EVT-LOGGING-OFF"]
    assert not analyse_events("t.jsonl", [_ev("UpdateTrail", {"name": "t", "s3BucketName": "b"})])
    assert analyse_events("t.jsonl", [_ev("StopLogging")])[0].rule_id == "EVT-LOGGING-OFF"
