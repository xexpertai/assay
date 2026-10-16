"""Event-log analyser scaffold: security events from JSONL or CSV exports (CloudTrail-style, auth logs, SIEM dumps).

Generic field mapping, so an unknown log schema can be plugged in during an event with one dict:
time, actor, action, source_ip, outcome, mfa, target. Rules are deliberately few and explainable:
failed-login bursts, console/root logins without MFA, privilege-escalation API calls, new long-lived
access keys, and security-logging being switched off. Every finding points at the first event line.
"""
from __future__ import annotations

import csv
import io
import json
import re
from collections import defaultdict
from datetime import datetime, timezone

from ..models import Finding

FIELD_ALIASES = {
    "time": ("eventTime", "timestamp", "time", "@timestamp", "ts", "date"),
    "actor": ("userIdentity.arn", "userIdentity.userName", "userIdentity.principalId", "user", "username", "actor", "principal", "userName"),
    "action": ("eventName", "action", "event", "operation", "method"),
    "source_ip": ("sourceIPAddress", "source_ip", "src_ip", "ip", "client_ip", "remote_addr"),
    "outcome": ("errorCode", "responseElements.ConsoleLogin", "outcome", "status", "result", "errorMessage"),
    "mfa": ("additionalEventData.MFAUsed", "mfa", "mfa_used", "MFAUsed"),
    "target": ("requestParameters.userName", "target", "resource", "object"),
}
PRIV_ESC_ACTIONS = {"AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreatePolicyVersion",
                    "SetDefaultPolicyVersion", "AddUserToGroup", "UpdateAssumeRolePolicy", "CreateLoginProfile",
                    "UpdateLoginProfile", "AttachGroupPolicy", "PutGroupPolicy"}
# note: iam:PassRole is an IAM permission, not a CloudTrail event name, so it is not listed here
LOGGING_OFF_ACTIONS = {"StopLogging", "DeleteTrail", "DeleteFlowLogs", "DisableKey", "DeleteDetector",
                       "DeleteLogGroup"}
# Calls that can enable OR disable logging; flagged only when the request visibly disables it.
LOGGING_CONDITIONAL = {"PutBucketLogging", "UpdateTrail"}


def _acts_on_other_user(actor: str, target: str | None) -> bool:
    """True when the call names a different user than the caller (admin work), False for self or unknown."""
    if not target:
        return False
    return target.rsplit("/", 1)[-1].lower() != actor.rsplit("/", 1)[-1].lower()


def _disables_logging(act: str, raw: dict) -> bool:
    rp = _get(raw, "requestParameters")
    if not isinstance(rp, dict):
        return False  # no request body in this export: cannot tell, do not guess
    if act == "PutBucketLogging":
        st = _ci(rp, "bucketLoggingStatus")
        return not (isinstance(st, dict) and _ci(st, "LoggingEnabled"))
    if act == "UpdateTrail":
        return _ci(rp, "enableLogFileValidation") is False or _ci(rp, "isMultiRegionTrail") is False
    return False
KEY_ACTIONS = {"CreateAccessKey"}
LOGIN_ACTIONS = {"ConsoleLogin", "login", "Login", "sshd:auth", "authentication"}
FAIL_RE = re.compile(r"(?i)fail|denied|invalid|unauthori[sz]ed|AccessDenied|incorrect")


def _ci(d: dict, key: str):
    """Dict lookup that tolerates key-case differences (real CloudTrail mixes bucketName / BucketLoggingStatus)."""
    if key in d:
        return d[key]
    low = key.lower()
    for k, v in d.items():
        if isinstance(k, str) and k.lower() == low:
            return v
    return None


def _get(d: dict, dotted: str):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = _ci(cur, part)
    return cur


def normalise(raw: dict, mapping: dict | None = None) -> dict:
    """Map a raw event to the common fields using an explicit mapping or the alias table."""
    out = {}
    for field, aliases in FIELD_ALIASES.items():
        keys = ([mapping[field]] if mapping and field in mapping else []) + list(aliases)
        for k in keys:
            v = _get(raw, k)
            if v not in (None, ""):
                out[field] = str(v)
                break
    return out


def _parse_time(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        try:
            return datetime.fromtimestamp(float(s), tz=timezone.utc)
        except ValueError:
            return None


SSHD_RE = re.compile(
    r"^(?P<ts>(?:\d{4}-\d{2}-\d{2}T\S+)|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+\S+\s+sshd(?:\[\d+\])?:\s+"
    r"(?P<msg>(?:Failed|Accepted)\s+\S+\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)\b.*"
    r"|Invalid user\s+(?P<user2>\S+)\s+from\s+(?P<ip2>[0-9a-fA-F:.]+)\b.*)$")
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
SYSLOG_YEAR = 1970  # classic syslog lines carry no year; without a reference time only relative times are valid
SYS_TS = r"(?P<ts>(?:\d{4}-\d{2}-\d{2}T\S+)|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))"
SUDO_RE = re.compile(SYS_TS + r"\s+\S+\s+sudo(?:\[\d+\])?:\s+(?P<user>\S+)\s+:.*?COMMAND=(?P<cmd>.*)$")
USERADD_RE = re.compile(SYS_TS + r"\s+\S+\s+useradd(?:\[\d+\])?:\s+new user:\s+name=(?P<name>[^,\s]+)")
GROUPADD_RE = re.compile(SYS_TS + r"\s+\S+\s+(?:usermod|gpasswd)(?:\[\d+\])?:\s+add '?(?P<name>[^' ]+)'? to (?:shadow )?group '?(?P<group>[^' ]+)'?")
PRIV_GROUPS = {"sudo", "wheel", "admin", "root", "adm"}
PERSIST_CMD_RE = re.compile(r"authorized_keys|crontab|/etc/sudoers|visudo|systemctl\s+(?:enable|edit)|chmod\s+[ugo]*\+s|"
                            r"\b(?:useradd|adduser|usermod|gpasswd)\b")
SESSION_WINDOW_S = 3600


def _syslog_time(ts: str, ref: datetime | None = None) -> str:
    """ISO time for a syslog stamp. `ref` (the file's modification time) supplies the missing year; a stamp that
    would land in the future relative to `ref` belongs to the previous year (a log read just after New Year)."""
    if ts[:4].isdigit():
        return ts
    mon, day, hms = ts.split()[0], int(ts.split()[1]), ts.split()[2]
    year = ref.year if ref else SYSLOG_YEAR
    try:
        t = datetime.fromisoformat(f"{year}-{MONTHS[mon]:02d}-{day:02d}T{hms}+00:00")
    except ValueError:  # 29 Feb in a non-leap reference year
        return f"{SYSLOG_YEAR}-{MONTHS[mon]:02d}-{day:02d}T{hms}+00:00"
    if ref and (t - ref).total_seconds() > 86400:
        t = t.replace(year=year - 1)
    return t.isoformat()


def parse_sshd(text: str, ref: datetime | None = None) -> list[tuple[int, dict]]:
    """(line_no, event) for syslog-style auth.log lines: sshd failed/accepted logins and invalid users, plus
    host persistence signals (sudo commands, useradd, adding a user to a privileged group). Persistence events are
    attributed to the sudo user, else to the most recent accepted login within the last hour."""
    out = []
    session: dict[str, str] = {}  # user -> source ip of their latest accepted login
    last_login: tuple[datetime | None, str, str] = (None, "", "")  # time, user, ip
    last_sudo: tuple[datetime | None, str] = (None, "")

    def actor_near(t: datetime | None) -> tuple[str, str]:
        if last_sudo[0] and t and 0 <= (t - last_sudo[0]).total_seconds() <= 60:
            return last_sudo[1], session.get(last_sudo[1], "")
        if last_login[0] and t and 0 <= (t - last_login[0]).total_seconds() <= SESSION_WINDOW_S:
            return last_login[1], last_login[2]
        return "unknown", ""

    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        m = SSHD_RE.match(line)
        if m:
            msg = m.group("msg")
            user = m.group("user") or m.group("user2")
            ip = m.group("ip") or m.group("ip2")
            iso = _syslog_time(m.group("ts"), ref)
            out.append((i, {"timestamp": iso, "user": user, "action": "sshd:auth", "src_ip": ip,
                            "status": msg.split(" for ")[0].split(" from ")[0], "mfa": "n/a"}))
            if msg.startswith("Accepted"):
                session[user] = ip
                last_login = (_parse_time(iso), user, ip)
            continue
        m = SUDO_RE.match(line)
        if m:
            iso = _syslog_time(m.group("ts"), ref)
            user, cmd = m.group("user"), m.group("cmd").strip()
            last_sudo = (_parse_time(iso), user)
            # commands that the daemon logs itself (useradd, usermod, gpasswd) are reported from those lines
            if PERSIST_CMD_RE.search(cmd) and not re.search(r"\b(?:useradd|adduser|usermod|gpasswd)\b", cmd):
                out.append((i, {"timestamp": iso, "user": user, "action": "sudo:command", "src_ip": session.get(user, ""),
                                "status": "ok", "target": cmd[:120]}))
            continue
        for rx, action in ((USERADD_RE, "useradd"), (GROUPADD_RE, "group-add")):
            m = rx.match(line)
            if m:
                iso = _syslog_time(m.group("ts"), ref)
                if action == "group-add" and m.group("group") not in PRIV_GROUPS:
                    break
                who, ip = actor_near(_parse_time(iso))
                tgt = m.group("name") + (f" -> {m.group('group')}" if action == "group-add" else "")
                out.append((i, {"timestamp": iso, "user": who, "action": action, "src_ip": ip, "status": "ok",
                                "target": tgt}))
                break
    return out


def _records(text: str) -> list[tuple[int, dict]] | None:
    """Exact line numbers for a JSON document holding {"Records": [...]} (or events/items) or a bare array."""
    t = text.lstrip()
    try:
        doc = json.loads(t)
    except json.JSONDecodeError:
        return None
    if isinstance(doc, list):
        arr_re = re.compile(r"\[")
    elif isinstance(doc, dict):
        key = next((k for k in ("Records", "events", "items") if isinstance(doc.get(k), list)), None)
        if key is None:
            return [(1, doc)] if doc else []
        arr_re = re.compile(r'"%s"\s*:\s*\[' % key)
    else:
        return []
    m = arr_re.search(text)
    out: list[tuple[int, dict]] = []
    if m:
        dec = json.JSONDecoder()
        idx = m.end()
        line, last = 1 + text.count("\n", 0, idx), idx  # count newlines incrementally: O(n), not O(n^2)
        while True:
            while idx < len(text) and text[idx] in " \t\r\n,":
                idx += 1
            if idx >= len(text) or text[idx] == "]":
                break
            try:
                obj, nxt = dec.raw_decode(text, idx)
            except json.JSONDecodeError:
                break
            if isinstance(obj, dict):
                line += text.count("\n", last, idx)
                last = idx
                out.append((line, obj))
            idx = nxt
    return out


def load_events(text: str, ref: datetime | None = None) -> list[tuple[int, dict]]:
    """(line_no, raw_event) from a JSON document (Records/events/items or a bare array; pretty-printed or not),
    JSONL, a syslog-style sshd auth.log, or CSV with a header."""
    t = text.lstrip()
    if t.startswith("{") or t.startswith("["):
        recs = _records(text)
        if recs:
            return recs
        out = []
        for i, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if line.startswith("{"):
                try:
                    out.append((i, json.loads(line)))
                except json.JSONDecodeError:
                    continue
        return out
    ssh = parse_sshd(text, ref)
    if ssh:
        return ssh
    try:
        rows = list(csv.DictReader(io.StringIO(text)))
    except csv.Error:
        return []
    return [(i + 2, r) for i, r in enumerate(rows) if isinstance(r, dict)]


EVENT_SUFFIXES = (".jsonl", ".ndjson", ".json", ".csv", ".log")
EVENT_NAMES = ("auth.log", "secure", "syslog", "messages")
LOOKS_LIKE_EVENTS_RE = re.compile(r'"eventName"|"eventTime"|"Records"|sshd\[?\d*\]?:|(?i:timestamp.*(user|action))')


def kind_of(name: str, head: str, full: str | None = None) -> str | None:
    """Heuristic: a file whose first record carries time + action-like fields is an event log.

    `full` is the whole file text when the caller has it: a real CloudTrail export is far larger than the head.
    """
    if not (name.endswith(EVENT_SUFFIXES) or name.startswith(EVENT_NAMES) or ".log." in name):
        return None
    evs = load_events(full if full is not None else head)
    if not evs:
        return None
    n = normalise(evs[0][1])
    return "eventlog" if "time" in n and "action" in n else None


def looks_like_unparsed_events(name: str, head: str) -> bool:
    """True when a file has an event-log name and event-log vocabulary but kind_of() could not read it."""
    if not (name.endswith(EVENT_SUFFIXES) or name.startswith(EVENT_NAMES) or ".log." in name):
        return False
    return bool(LOOKS_LIKE_EVENTS_RE.search(head))


def analyse_events(rel: str, events: list[tuple[int, dict]], mapping: dict | None = None) -> list[Finding]:
    out: list[Finding] = []
    ev = [(ln, normalise(r, mapping), r) for ln, r in events]

    def ctx(n):
        t = _parse_time(n.get("time"))
        return {"source_ip": n.get("source_ip") or "", "time": t.isoformat() if t else ""}

    def mk(ln, **kw):
        return Finding(file=rel, line=ln, resource=kw.pop("resource", rel), **kw)

    # 1. failed-login bursts per actor/source (>= 5 within 10 minutes)
    fails: dict[str, list[tuple[datetime, int, str]]] = defaultdict(list)
    for ln, n, _ in ev:
        if n.get("action") in LOGIN_ACTIONS and FAIL_RE.search(n.get("outcome") or ""):
            t = _parse_time(n.get("time"))
            if t:
                fails[n.get("actor") or n.get("source_ip") or "unknown"].append((t, ln, n.get("source_ip") or ""))
    for who, items in fails.items():
        items.sort()
        for i in range(len(items)):
            window = [x for x in items[i:] if (x[0] - items[i][0]).total_seconds() <= 600]
            if len(window) >= 5:
                out.append(mk(window[0][1], resource=f"actor/{who}", rule_id="EVT-LOGIN-BURST",
                              title=f"{len(window)} failed logins for {who} within 10 minutes", severity="medium",
                              confidence="high", evidence=f"first at {window[0][0].isoformat()}, {len(window)} failures",
                              rationale="A burst of failed logins is the signature of password guessing or credential "
                                        "stuffing.",
                              remediation="Confirm the source, lock or rate-limit the account, require MFA.",
                              cwe="CWE-307", category="auth_bruteforce", tags=["observed", "event"],
                              meta={"actor": who, "count": len(window), "key": who, "time": window[0][0].isoformat(),
                                    "source_ip": window[0][2]}))
                break
    # 1b. brute force that SUCCEEDED: >= 5 failures within 10 minutes for the same account or the same source,
    # then a successful login for that account or from that source within 30 minutes of the last failure
    failed_ev: list[tuple[datetime, int, str, str]] = []  # (time, line, actor, ip)
    ok_ev: list[tuple[datetime, int, str, str, dict]] = []
    for ln, n, _ in ev:
        if n.get("action") not in LOGIN_ACTIONS:
            continue
        t = _parse_time(n.get("time"))
        if not t:
            continue
        rec = (t, ln, (n.get("actor") or "").rsplit("/", 1)[-1].lower(), n.get("source_ip") or "")
        if FAIL_RE.search(n.get("outcome") or ""):
            failed_ev.append(rec)
        else:
            ok_ev.append((*rec, n))
    failed_ev.sort()
    reported: set[str] = set()
    for t_ok, ln_ok, actor, ip, n in sorted(ok_ev, key=lambda x: (x[0], x[1])):
        for by, val in (("account", actor), ("source", ip)):
            if not val:
                continue
            prior = [f for f in failed_ev if f[0] <= t_ok and (f[2] if by == "account" else f[3]) == val]
            if not prior:
                continue
            last = prior[-1]
            if (t_ok - last[0]).total_seconds() > 1800:
                continue
            burst = [f for f in prior if 0 <= (last[0] - f[0]).total_seconds() <= 600]
            if len(burst) < 5:
                continue
            key = f"{actor}|{ip}|{ln_ok}"
            if key in reported:
                continue
            reported.add(key)
            out.append(mk(ln_ok, resource=f"actor/{actor or ip}", rule_id="EVT-BRUTE-FORCE-SUCCESS",
                          title=f"Login succeeded for {actor or ip} right after {len(burst)} failures "
                                f"(same {by})", severity="critical", confidence="high",
                          evidence=f"{len(burst)} failures from {burst[0][0].isoformat()} to {last[0].isoformat()}, "
                                   f"then success at {t_ok.isoformat()} from {ip or '?'}",
                          rationale="A burst of failures followed by a success is how a guessed or stuffed password "
                                    "looks in a log: the attacker is probably already in.",
                          remediation="Treat the account as compromised: revoke sessions and keys, reset the "
                                      "password, require MFA, then review everything the actor did afterwards.",
                          cwe="CWE-307", category="auth_bruteforce_success", tags=["observed", "event"],
                          meta={**ctx(n), "actor": actor, "source_ip": ip, "by": by, "failures": len(burst),
                                "first_fail_line": burst[0][1], "time": t_ok.isoformat(), "key": key}))
            break
    # 2. console/root login without MFA; 3. privilege escalation; 4. new access key; 5. logging switched off
    for ln, n, raw in ev:
        act = n.get("action") or ""
        actor = n.get("actor") or "unknown"
        if act in LOGIN_ACTIONS and not FAIL_RE.search(n.get("outcome") or "") and \
                (n.get("mfa") or "").lower() in ("no", "false", "0"):
            root = "root" in actor.lower()
            out.append(mk(ln, resource=f"actor/{actor}", rule_id="EVT-LOGIN-NO-MFA",
                          title=f"{'Root' if root else 'Console'} login without MFA by {actor}",
                          severity="high" if root else "medium", confidence="high",
                          evidence=f"{act} succeeded, MFAUsed = {n.get('mfa')}, from {n.get('source_ip') or '?'}",
                          rationale="A password-only login means one leaked password is full access.",
                          remediation="Enforce MFA for every console user; never use the root user day to day.",
                          cwe="CWE-308", category="auth_no_mfa", tags=["observed", "event"],
                          meta={**ctx(n), "actor": actor, "key": f"{actor}|{ln}"}))
        other = _acts_on_other_user(actor, n.get("target"))
        if act in PRIV_ESC_ACTIONS and not FAIL_RE.search(n.get("outcome") or ""):
            out.append(mk(ln, resource=f"actor/{actor}", rule_id="EVT-PRIV-ESC",
                          title=(f"Admin activity: {act} on {n.get('target')} by {actor} (review)" if other
                                 else f"Privilege change: {act} by {actor}"),
                          severity="medium" if other else "high", confidence="medium",
                          evidence=f"{act} on {n.get('target') or '?'} from {n.get('source_ip') or '?'}",
                          rationale=("An identity changed ANOTHER user's permissions. That is normal onboarding work "
                                     "and is only an intrusion signal when something suspicious came first."
                                     if other else
                                     "Policy and login-profile changes are how an intruder turns a foothold into "
                                     "persistent admin access; each one needs a known change ticket."),
                          remediation="Match against approved changes; revert and rotate if unexplained.",
                          cwe="CWE-269", category="priv_change",
                          tags=["observed", "event"] + (["admin-activity"] if other else []),
                          meta={**ctx(n), "actor": actor, "action": act, "other_user": other,
                                "key": f"{act}|{ln}"}))
        if act in KEY_ACTIONS and not FAIL_RE.search(n.get("outcome") or ""):
            out.append(mk(ln, resource=f"actor/{actor}", rule_id="EVT-NEW-ACCESS-KEY",
                          title=(f"Admin activity: access key created for {n.get('target')} by {actor} (review)"
                                 if other else f"Long-lived access key created by {actor}"),
                          severity="low" if other else "medium", confidence="high",
                          evidence=f"{act} for {n.get('target') or actor}",
                          rationale="New static keys are a common persistence step and leak easily."
                                    + (" Created for another user, which is routine in onboarding; review it." if other
                                       else ""),
                          remediation="Confirm the key is expected; prefer roles and short-lived credentials.",
                          cwe="CWE-798", category="iam_static_key",
                          tags=["observed", "event"] + (["admin-activity"] if other else []),
                          meta={**ctx(n), "actor": actor, "other_user": other, "key": f"{act}|{ln}"}))
        if act in ("sudo:command", "useradd", "group-add"):
            after_bf = any(f.rule_id == "EVT-BRUTE-FORCE-SUCCESS" and f.meta.get("time", "") <= (n.get("time") or "")
                           for f in out)
            what = {"sudo:command": "persistence command", "useradd": "new local account",
                    "group-add": "privileged group membership"}[act]
            out.append(mk(ln, resource=f"actor/{actor}", rule_id="EVT-HOST-PERSISTENCE",
                          title=(f"Host persistence after a successful brute force: {what} ({n.get('target')}) by {actor}"
                                 if after_bf else f"Admin activity: {what} ({n.get('target')}) by {actor} (review)"),
                          severity="high" if after_bf else "medium", confidence="medium",
                          evidence=f"{act}: {n.get('target')} from {n.get('source_ip') or 'local session'}",
                          rationale="New accounts, sudo group membership, authorized_keys, cron and sudoers edits are how "
                                    "an intruder keeps access after the password is changed."
                                    + ("" if after_bf else " On its own this is routine admin work; it only becomes an "
                                                           "intrusion signal after a suspicious login."),
                          remediation="Match against a change ticket; if unexplained, remove the account/key, rotate "
                                      "credentials and review the session.",
                          cwe="CWE-912" if after_bf else "CWE-269", category="host_persistence",
                          tags=["observed", "event"] + ([] if after_bf else ["admin-activity"]),
                          meta={**ctx(n), "actor": actor, "other_user": not after_bf, "key": f"{act}|{ln}"}))
        if (act in LOGGING_OFF_ACTIONS or (act in LOGGING_CONDITIONAL and _disables_logging(act, raw))) \
                and not FAIL_RE.search(n.get("outcome") or ""):
            out.append(mk(ln, resource=f"actor/{actor}", rule_id="EVT-LOGGING-OFF",
                          title=f"Security logging changed or disabled: {act} by {actor}", severity="high",
                          confidence="medium", evidence=f"{act} from {n.get('source_ip') or '?'}",
                          rationale="Turning off trails, flow logs or detectors is defence evasion.",
                          remediation="Re-enable logging; investigate the actor and the time window.",
                          cwe="CWE-778", category="logging_off", tags=["observed", "event"],
                          meta={**ctx(n), "actor": actor, "key": f"{act}|{ln}"}))
    return out


def _mtime(facts, rel: str) -> datetime | None:
    root = getattr(facts, "root", None)
    try:
        return datetime.fromtimestamp((root / rel).stat().st_mtime, tz=timezone.utc) if root else None
    except OSError:
        return None


def analyse(files: list[tuple[str, str]], facts) -> list[Finding]:
    out: list[Finding] = []
    for rel, txt in files:
        ref = _mtime(facts, rel)
        evs = load_events(txt, ref)
        if evs:
            if ref and parse_sshd(txt[:200000]):
                facts.notes.append((rel, f"syslog lines carry no year; {ref.year} was taken from the file's "
                                         "modification time (a stamp later than that is placed in the previous year)"))
            out += analyse_events(rel, evs)
            for _, n, _ in [(ln, normalise(r), r) for ln, r in evs]:
                if n.get("actor"):
                    facts.actors.add(n["actor"])
    return out
