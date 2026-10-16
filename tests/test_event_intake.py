"""Judge R3 fix 1: real-size CloudTrail exports, syslog auth.log, logged skips, brute-force-then-success."""
import json

from assay.agent import run


def _trail(n_noise=300):
    recs = []
    for i in range(n_noise):
        recs.append({"eventTime": f"2026-10-01T08:{i % 60:02d}:00Z", "eventName": "DescribeInstances",
                     "userIdentity": {"arn": "arn:aws:iam::1:user/ci"}, "sourceIPAddress": "10.0.0.5",
                     "requestParameters": {"filter": "x" * 40}})
    for i in range(6):
        recs.append({"eventTime": f"2026-10-02T10:0{i}:00Z", "eventName": "ConsoleLogin",
                     "userIdentity": {"userName": "alice"}, "sourceIPAddress": "203.0.113.9",
                     "responseElements": {"ConsoleLogin": "Failure"}})
    recs.append({"eventTime": "2026-10-02T10:07:00Z", "eventName": "ConsoleLogin",
                 "userIdentity": {"userName": "alice", "arn": "arn:aws:iam::1:user/alice"}, "sourceIPAddress": "203.0.113.9",
                 "responseElements": {"ConsoleLogin": "Success"}, "additionalEventData": {"MFAUsed": "No"}})
    return {"Records": recs}


def test_large_pretty_printed_cloudtrail_is_read(tmp_path):
    (tmp_path / "trail.json").write_text(json.dumps(_trail(), indent=2))
    assert (tmp_path / "trail.json").stat().st_size > 20000
    res = run(str(tmp_path))
    ids = {f.rule_id for f in res.findings}
    assert "EVT-BRUTE-FORCE-SUCCESS" in ids and "EVT-LOGIN-NO-MFA" in ids
    f = next(f for f in res.findings if f.rule_id == "EVT-BRUTE-FORCE-SUCCESS")
    assert f.line > 1  # exact record line, not 1


def test_single_line_cloudtrail_is_read(tmp_path):
    (tmp_path / "trail.json").write_text(json.dumps(_trail()))
    assert "EVT-BRUTE-FORCE-SUCCESS" in {f.rule_id for f in run(str(tmp_path)).findings}


AUTH_LOG = "".join(
    f"Oct 16 10:2{i}:01 web1 sshd[41{i}]: Failed password for {'invalid user ' if i % 2 else ''}admin from 198.51.100.7 port 5{i}000 ssh2\n"
    for i in range(6)) + (
    "Oct 16 10:27:30 web1 sshd[500]: Accepted password for admin from 198.51.100.7 port 51000 ssh2\n"
    "Oct 16 10:28:00 web1 CRON[7]: pam_unix(cron:session): session opened for user root\n"
    "Oct 16 10:30:00 web1 sshd[501]: Accepted publickey for deploy from 10.0.0.2 port 40000 ssh2\n")


def test_auth_log_sshd_text(tmp_path):
    (tmp_path / "auth.log").write_text(AUTH_LOG)
    res = run(str(tmp_path))
    ids = {f.rule_id for f in res.findings}
    assert {"EVT-LOGIN-BURST", "EVT-BRUTE-FORCE-SUCCESS"} <= ids
    bf = next(f for f in res.findings if f.rule_id == "EVT-BRUTE-FORCE-SUCCESS")
    assert bf.line == 7 and bf.meta["source_ip"] == "198.51.100.7"
    # the legitimate key login must not be flagged
    assert not any("deploy" in f.title for f in res.findings)


def test_success_without_a_burst_is_quiet(tmp_path):
    (tmp_path / "auth.log").write_text(
        "Oct 16 10:20:01 h sshd[1]: Failed password for bob from 192.0.2.1 port 1 ssh2\n"
        "Oct 16 10:21:01 h sshd[1]: Accepted password for bob from 192.0.2.1 port 1 ssh2\n")
    assert not [f for f in run(str(tmp_path)).findings if f.rule_id.startswith("EVT-")]


def test_unparseable_event_log_is_a_logged_skip_not_silence(tmp_path):
    (tmp_path / "export.json").write_text('{"Records": [{"eventName": "ConsoleLogin", "eventTime":')  # truncated
    res = run(str(tmp_path))
    assert any("looks like an event log but could not be parsed" in d.action for d in res.decisions)


def test_oversize_file_skip_is_logged(tmp_path):
    (tmp_path / "huge.log").write_text("x" * 1_100_000)
    res = run(str(tmp_path))
    assert any(d.action == "skipped huge.log" for d in res.decisions)
