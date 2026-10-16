"""Correlation for observed events and DataOps configuration: kill-chain timelines per actor,
log actors matched to IAM findings, and pipeline-config combinations.

Deterministic like the rest of correlate.py: every chain lists the findings it was built from and explains
why they belong together (same actor, same source address, time window, same file).
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime

from .models import Chain, Finding

STAGE = {"auth_bruteforce": "access", "auth_bruteforce_success": "access", "auth_no_mfa": "access",
         "priv_change": "privilege escalation", "iam_static_key": "persistence", "logging_off": "defence evasion"}
STAGE_ORDER = ["access", "privilege escalation", "persistence", "defence evasion"]
CLUSTER_GAP_S = 3600  # events of one intrusion are at most an hour apart


def _cid(kind: str, ids: list[str]) -> str:
    return "C-" + hashlib.sha256((kind + "|".join(sorted(ids))).encode()).hexdigest()[:8]


def actor_key(a: str) -> str:
    return (a or "").strip().rsplit("/", 1)[-1].lower()


def _when(f: Finding) -> datetime | None:
    try:
        return datetime.fromisoformat(f.meta.get("time", ""))
    except ValueError:
        return None


def _clusters(evt: list[Finding]) -> list[list[Finding]]:
    """Connected groups by shared actor or source address, then split where the time gap is large."""
    parent: dict[str, str] = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    for f in evt:
        node = f"f:{f.id}"
        find(node)
        if f.meta.get("actor"):
            union(node, "a:" + actor_key(f.meta["actor"]))
        if f.meta.get("source_ip"):
            union(node, "i:" + f.meta["source_ip"])
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in evt:
        groups[find(f"f:{f.id}")].append(f)
    out = []
    for g in groups.values():
        g.sort(key=lambda f: (f.meta.get("time", ""), f.line))
        cur = [g[0]]
        for f in g[1:]:
            a, b = _when(cur[-1]), _when(f)
            if a and b and (b - a).total_seconds() > CLUSTER_GAP_S:
                out.append(cur)
                cur = [f]
            else:
                cur.append(f)
        out.append(cur)
    return out


def _timeline(fs: list[Finding]) -> str:
    rows = []
    for f in fs:
        t = f.meta.get("time", "")
        rows.append(f"{t[11:19] or '??:??:??'} line {f.line}: {f.title}")
    return "Timeline: " + " -> ".join(rows) + "."


def _kill_chains(evt: list[Finding]) -> list[Chain]:
    out = []
    for cl in _clusters(evt):
        stages = {STAGE[f.category] for f in cl if f.category in STAGE}
        if len(stages) < 2 or len(cl) < 2:
            continue
        who = sorted({actor_key(f.meta.get("actor", "")) for f in cl if f.meta.get("actor")})
        ips = sorted({f.meta["source_ip"] for f in cl if f.meta.get("source_ip")})
        ordered = [s for s in STAGE_ORDER if s in stages]
        brute = any(f.category == "auth_bruteforce_success" for f in cl)
        sev = "critical" if (brute or "access" in stages) and len(stages) >= 2 else "high"
        head = "Brute force succeeded, then " + ", ".join(ordered[1:]) if brute and len(ordered) > 1 else \
            "Multi-stage intrusion pattern: " + " -> ".join(ordered)
        ids = [f.id for f in cl]
        out.append(Chain(_cid("event-killchain", ids), f"{head} ({', '.join(who) or ', '.join(ips)})", sev, ids,
                         f"Events from {', '.join(who) or 'one source'}"
                         + (f" at {', '.join(ips)}" if ips else "")
                         + f" fall within an hour of each other and cover {len(stages)} stages of an intrusion "
                           f"({', '.join(ordered)}). Separately each could be routine; in this order, by the same "
                           f"actor or address, they describe an attacker getting in and then securing and hiding "
                           f"access. " + _timeline(cl),
                         sorted({f.resource for f in cl})))
    return out


def _iam_identities(f: Finding, facts) -> dict[str, str]:
    """Names of aws_iam_user/role resources that a wildcard-policy finding is attached to (two reference hops)."""
    seen = {f.resource}
    frontier = {f.resource}
    for _ in range(2):
        nxt = set()
        for a in frontier:
            nxt |= set(facts.tf_refs.get(a, set()))
            nxt |= {x for x, refs in facts.tf_refs.items() if a in refs}
        frontier = nxt - seen
        seen |= nxt
    names = {}
    for a in seen:
        if a.startswith(("aws_iam_user.", "aws_iam_role.")):
            n = facts.iam_names.get(a)
            names[actor_key(n) if n else a.split(".", 1)[1].lower()] = a
    return names


def _actor_iam_chains(evt: list[Finding], findings: list[Finding], facts) -> list[Chain]:
    out = []
    iam = [f for f in findings if f.category == "iam_wildcard" and f.rule_id.startswith("TF-")]
    for f in iam:
        for name, addr in _iam_identities(f, facts).items():
            hits = [e for e in evt if actor_key(e.meta.get("actor", "")) == name]
            if not hits:
                continue
            ids = [f.id] + [e.id for e in hits]
            access = any(e.category in ("auth_bruteforce_success", "auth_no_mfa") for e in hits)
            out.append(Chain(_cid("log-actor-iam", ids),
                             f"Observed activity by '{name}', an identity the Terraform grants broad rights", 
                             "critical" if access or len(hits) >= 2 else "high", ids,
                             f"The event log shows {len(hits)} suspicious event(s) by '{name}' "
                             f"({', '.join(sorted({h.rule_id for h in hits}))}), and the Terraform identity {addr} is "
                             f"covered by {f.rule_id} ({f.resource}). Whatever this actor does with those rights is "
                             f"unrestricted, so a compromise of '{name}' is a compromise of the account. "
                             "Matched by identity name; confirm the log's account is the one this code deploys.",
                             sorted({addr, f.resource, *(e.resource for e in hits)})))
    return out


def _by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    d: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        d[f.file].append(f)
    return d


def _combo(kind: str, fs: list[Finding], title: str, sev: str, why: str) -> Chain:
    ids = [f.id for f in fs]
    return Chain(_cid(kind, ids), title, sev, ids, why, sorted({f.resource for f in fs}))


def _dataops_chains(findings: list[Finding]) -> list[Chain]:
    out = []
    for file, fs in _by_file(findings).items():
        rid = {f.rule_id: f for f in fs}
        unauth = [f for f in fs if f.category == "dataops_unauth"]
        stored = [f for f in fs if f.rule_id in ("AIRFLOW-CONN-PASSWORD", "AIRFLOW-NO-FERNET-KEY")]
        if unauth and stored:
            out.append(_combo("airflow-open-creds", unauth[:1] + stored,
                              f"Unauthenticated Airflow exposes stored credentials ({file})", "critical",
                              "Airflow in this configuration accepts requests without credentials "
                              f"({unauth[0].rule_id}) and the same file keeps database/connection secrets in the open "
                              f"({', '.join(f.rule_id for f in stored)}). Anyone who can reach the webserver can read "
                              "or trigger pipelines that hold those credentials."))
        if "KAFKA-PLAINTEXT-LISTENER" in rid and ("KAFKA-ALLOW-EVERYONE" in rid or "KAFKA-NO-AUTHORIZER" in rid):
            second = rid.get("KAFKA-ALLOW-EVERYONE") or rid["KAFKA-NO-AUTHORIZER"]
            out.append(_combo("kafka-open", [rid["KAFKA-PLAINTEXT-LISTENER"], second],
                              f"Kafka broker is unauthenticated and unencrypted ({file})", "critical",
                              "A PLAINTEXT listener means no client is authenticated and traffic is readable; "
                              f"{second.rule_id} means no ACL restricts what an anonymous client can read or write. "
                              "Together any host that can reach the broker can read and inject records."))
        grants = [f for f in fs if f.rule_id in ("SQL-GRANT-PUBLIC", "SQL-GRANT-ALL-GLOBAL", "SQL-SUPERUSER")]
        if grants and "SQL-USER-PASSWORD-LITERAL" in rid:
            out.append(_combo("sql-pw-grants", grants[:1] + [rid["SQL-USER-PASSWORD-LITERAL"]],
                              f"Database script hard-codes a password and over-grants ({file})", "high",
                              "The script writes a database password in clear and also grants broad privileges "
                              f"({grants[0].rule_id}); a reader of the script (git, CI logs) gets a high-privilege "
                              "login."))
    unauth_any = [f for f in findings if f.category == "dataops_unauth"]
    dag = [f for f in findings if f.rule_id == "AIRFLOW-DAG-SECRET"]
    if unauth_any and dag:
        ids = [unauth_any[0].id] + [f.id for f in dag]
        out.append(Chain(_cid("airflow-dag-open", ids), "Credentials in DAG code on an unauthenticated Airflow",
                         "high", ids,
                         f"{len(dag)} DAG file(s) contain credential literals and Airflow is configured without "
                         f"authentication ({unauth_any[0].rule_id} in {unauth_any[0].file}). Assumes the DAGs run on "
                         "that deployment (same repository); DAG source is readable through the UI/API.",
                         sorted({f.resource for f in dag + unauth_any[:1]})))
    return out


def event_and_dataops_chains(findings: list[Finding], facts) -> list[Chain]:
    evt = [f for f in findings if f.rule_id.startswith("EVT-") and f.meta.get("time") is not None]
    out = []
    if evt:
        out += _kill_chains(evt)
        out += _actor_iam_chains(evt, findings, facts)
    out += _dataops_chains(findings)
    return out
