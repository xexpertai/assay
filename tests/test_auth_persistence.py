"""Judge R4 fix 7: host persistence in auth.log (sudo / useradd / privileged group) and the syslog year."""
import os
import time

from assay.agent import run
from tests.test_event_intake import AUTH_LOG

PERSIST = (
    "Oct 16 10:28:10 web1 sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/tee -a /root/.ssh/authorized_keys\n"
    "Oct 16 10:28:30 web1 useradd[900]: new user: name=support, UID=1001, GID=1001, home=/home/support, shell=/bin/bash\n"
    "Oct 16 10:28:40 web1 usermod[901]: add 'support' to group 'sudo'\n"
    "Oct 16 10:28:41 web1 usermod[902]: add 'support' to group 'docker'\n")


def _dir(tmp_path, text, year=2026):
    f = tmp_path / "auth.log"
    f.write_text(text)
    ts = time.mktime((year, 10, 17, 12, 0, 0, 0, 0, -1))
    os.utime(f, (ts, ts))
    return str(tmp_path)


def test_persistence_after_brute_force_is_high_and_chained(tmp_path):
    res = run(_dir(tmp_path, AUTH_LOG + PERSIST))
    per = [f for f in res.findings if f.rule_id == "EVT-HOST-PERSISTENCE"]
    assert len(per) == 3  # authorized_keys, new user, sudo group; docker group is not privileged for this rule
    assert {f.severity for f in per} == {"high"} and all("after a successful brute force" in f.title for f in per)
    ch = [c for c in res.chains if c.title.startswith("Brute force succeeded, then persistence")]
    assert len(ch) == 1 and ch[0].severity == "critical" and "Timeline:" in ch[0].narrative


def test_routine_admin_work_without_a_suspicious_login_is_not_an_intrusion(tmp_path):
    text = ("Oct 16 09:00:00 web1 sshd[1]: Accepted publickey for jane from 10.0.0.9 port 1 ssh2\n"
            "Oct 16 09:01:00 web1 sudo:     jane : TTY=pts/0 ; PWD=/home/jane ; USER=root ; COMMAND=/usr/sbin/useradd -m bob\n"
            "Oct 16 09:01:01 web1 useradd[5]: new user: name=bob, UID=1002, GID=1002, home=/home/bob, shell=/bin/bash\n")
    res = run(_dir(tmp_path, text))
    per = [f for f in res.findings if f.rule_id == "EVT-HOST-PERSISTENCE"]
    assert len(per) == 1 and per[0].severity == "medium" and "admin-activity" in per[0].tags
    assert per[0].meta["actor"] == "jane"  # attributed through the sudo line
    assert not res.chains


def test_syslog_year_comes_from_the_file_time_and_is_logged(tmp_path):
    res = run(_dir(tmp_path, AUTH_LOG, 2026))
    bf = next(f for f in res.findings if f.rule_id == "EVT-BRUTE-FORCE-SUCCESS")
    assert "2026-10-16" in bf.evidence
    assert any(d.action == "assumption for auth.log" and "2026" in d.reason for d in res.decisions)


def test_log_read_just_after_new_year_places_december_in_the_previous_year(tmp_path):
    text = AUTH_LOG.replace("Oct 16", "Dec 31")
    f = tmp_path / "auth.log"
    f.write_text(text)
    ts = time.mktime((2027, 1, 2, 12, 0, 0, 0, 0, -1))
    os.utime(f, (ts, ts))
    bf = next(x for x in run(str(tmp_path)).findings if x.rule_id == "EVT-BRUTE-FORCE-SUCCESS")
    assert "2026-12-31" in bf.evidence


def test_root_session_without_sudo_is_attributed_to_the_last_login(tmp_path):
    text = "".join(f"Oct 16 10:2{i}:01 web1 sshd[41{i}]: Failed password for root from 198.51.100.7 port 5{i}000 ssh2\n"
                   for i in range(6))
    text += ("Oct 16 10:27:30 web1 sshd[500]: Accepted password for root from 198.51.100.7 port 51000 ssh2\n"
             "Oct 16 10:29:00 web1 useradd[77]: new user: name=svc, UID=1005, GID=1005, home=/home/svc, shell=/bin/sh\n")
    res = run(_dir(tmp_path, text))
    p = next(f for f in res.findings if f.rule_id == "EVT-HOST-PERSISTENCE")
    assert p.meta["actor"] == "root" and p.meta["source_ip"] == "198.51.100.7"
    assert any(c.title.startswith("Brute force succeeded, then persistence") for c in res.chains)
