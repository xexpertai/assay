"""Stage 3 and 4: correlate findings into attack chains, then prioritise with explained scores.

Correlation is deterministic: it follows resource references (Terraform), service-account
bindings (Kubernetes) and identical secret fingerprints. Every chain names the findings
it was built from, so a reviewer can check each step.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field

from .models import SEVERITY_POINTS, Chain, Finding

CONF_FACTOR = {"high": 1.0, "medium": 0.85, "low": 0.6}
ESCAPE_CATS = {"k8s_privileged", "k8s_hostpath", "k8s_host_namespace", "k8s_caps"}
SECRET_CATS = {"secret_in_userdata", "secret_in_lambda_env", "secret_in_iac", "secret_in_code"}


@dataclass
class Facts:
    """Relationships collected by the analysers, used only for correlation."""

    tf_refs: dict[str, set[str]] = field(default_factory=dict)  # address -> referenced addresses
    k8s_sa: dict[str, str] = field(default_factory=dict)  # "Kind/name" -> service account
    admin_sas: set[str] = field(default_factory=set)  # service accounts bound to cluster-admin


def _chain_id(kind: str, ids: list[str]) -> str:
    return "C-" + hashlib.sha256((kind + "|".join(sorted(ids))).encode()).hexdigest()[:8]


def _neighbours(facts: Facts, address: str) -> set[str]:
    out = set(facts.tf_refs.get(address, set()))
    for a, refs in facts.tf_refs.items():
        if address in refs:
            out.add(a)
    return out


def correlate(findings: list[Finding], facts: Facts) -> list[Chain]:
    by_res: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_res[f.resource].append(f)
        # Kubernetes container findings also belong to their workload
        parts = f.resource.split("/")
        if len(parts) == 3:
            by_res["/".join(parts[:2])].append(f)
    chains: list[Chain] = []

    def exposure_of(addr: str) -> list[Finding]:
        hits = [f for f in by_res.get(addr, []) if "internet-exposed" in f.tags]
        for n in _neighbours(facts, addr):
            hits += [f for f in by_res.get(n, []) if "internet-exposed" in f.tags and f.category in
                     ("sg_open_admin", "internet_facing")]
        return hits

    # 1. Internet-reachable compute that carries plaintext credentials
    for addr, fs in by_res.items():
        secrets = [f for f in fs if f.category in ("secret_in_userdata", "secret_in_lambda_env")]
        if not secrets:
            continue
        exp = exposure_of(addr)
        if exp:
            ids = [f.id for f in secrets + exp]
            ports = sorted({f.evidence for f in exp})
            chains.append(Chain(_chain_id("exposed-secret", ids),
                                f"Internet-reachable {addr} carries plaintext credentials", "critical", ids,
                                f"{addr} is reachable from the internet ({'; '.join(ports)}) and its configuration "
                                f"holds {len(secrets)} plaintext credential(s). Anyone who gains a foothold on the "
                                "host, or can read the instance or function configuration, gets those credentials "
                                "and can move into the cloud account.",
                                sorted({addr, *(f.resource for f in exp)})))

    # 2. SSRF to credential theft: internet-facing instance still allowing IMDSv1
    for addr, fs in by_res.items():
        imds = [f for f in fs if f.category == "imdsv1"]
        if imds:
            exp = exposure_of(addr)
            if exp:
                ids = [f.id for f in imds + exp]
                chains.append(Chain(_chain_id("ssrf-imds", ids),
                                    f"SSRF on internet-facing {addr} could steal its role credentials", "high", ids,
                                    f"{addr} accepts internet traffic and still allows IMDSv1, so one server-side "
                                    "request forgery bug in the application would return the instance role's "
                                    "temporary credentials.", sorted({addr, *(f.resource for f in exp)})))

    # 3. Exposed or weakly protected data stores
    for addr, fs in by_res.items():
        cats = {f.category for f in fs}
        public = [f for f in fs if f.category in ("s3_public", "db_public") and f.severity in ("high", "critical")]
        weak = [f for f in fs if f.category in ("s3_encryption", "s3_logging", "db_unencrypted", "secret_in_iac")]
        if public and weak:
            ids = [f.id for f in public + weak]
            chains.append(Chain(_chain_id("public-data", ids),
                                f"Publicly reachable data store {addr} lacks protection or audit trail", "high", ids,
                                f"{addr} is open to the internet and also has: "
                                + ", ".join(sorted(cats & {"s3_encryption", "s3_logging", "db_unencrypted",
                                                           "secret_in_iac"}))
                                + ". A leak would be both likely and hard to investigate.", [addr]))

    # 4. Container escape paths and cluster takeover
    for res, fs in by_res.items():
        if res.count("/") != 1:
            continue
        esc = [f for f in fs if f.category in ESCAPE_CATS and f.severity in ("high", "critical")]
        if not esc:
            continue
        sa = facts.k8s_sa.get(res)
        if sa and sa in facts.admin_sas:
            bind = [f for f in findings if f.rule_id == "K8S-CLUSTER-ADMIN-BINDING"]
            ids = [f.id for f in esc + bind]
            chains.append(Chain(_chain_id("k8s-takeover", ids),
                                f"{res} can escape to the node and its service account is cluster-admin", "critical",
                                ids, f"{res} has {len(esc)} container-escape weakness(es) and runs as service account "
                                     f"'{sa}', which is bound to cluster-admin: compromising this one pod compromises "
                                     "the whole cluster.", [res]))
        elif len({f.category for f in esc}) >= 2:
            ids = [f.id for f in esc]
            chains.append(Chain(_chain_id("k8s-escape", ids),
                                f"{res} combines several container-escape weaknesses", "critical", ids,
                                f"{res} has " + ", ".join(sorted({f.category for f in esc}))
                                + ". Together these make breaking out to the node straightforward for anyone who "
                                  "gets code execution in the container.", [res]))

    # 5. The same credential copied into several places
    by_secret: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        for t in f.tags:
            if t.startswith("secret-id:"):
                by_secret[t].append(f)
    for tag, fs in by_secret.items():
        places = {(f.file, f.resource) for f in fs}
        if len(places) >= 2:
            ids = [f.id for f in fs]
            chains.append(Chain(_chain_id("secret-reuse", ids),
                                f"One credential appears in {len(places)} places", "high", ids,
                                "The same secret value (matched by fingerprint, never stored) is copied into "
                                + ", ".join(sorted(f"{a} ({b})" for a, b in places))
                                + ". Rotating it requires changing every copy, and any one leak exposes all users "
                                  "of it.", sorted({f.resource for f in fs})))
    # de-duplicate identical chains
    uniq = {c.id: c for c in chains}
    return list(uniq.values())


def prioritise(findings: list[Finding], chains: list[Chain]) -> list[Finding]:
    in_chain: dict[str, list[Chain]] = defaultdict(list)
    for c in chains:
        for fid in c.finding_ids:
            in_chain[fid].append(c)
    exposed_res = {f.resource for f in findings if "internet-exposed" in f.tags}
    for c in chains:
        if any(fid in {f.id for f in findings if "internet-exposed" in f.tags} for fid in c.finding_ids):
            exposed_res.update(c.resources)
    for f in findings:
        base = SEVERITY_POINTS[f.severity]
        factors = [f"severity {f.severity} = {base:g}"]
        score = base * CONF_FACTOR[f.confidence]
        if f.confidence != "high":
            factors.append(f"confidence {f.confidence} x{CONF_FACTOR[f.confidence]:g}")
        if f.severity != "info" and (f.resource in exposed_res or "internet-exposed" in f.tags):
            score += 1.0
            factors.append("internet-exposed +1")
        if f.severity != "info" and in_chain.get(f.id):
            score += 1.5
            factors.append(f"part of chain {in_chain[f.id][0].id} +1.5")
        f.score = round(min(score, 10.0), 1)
        f.score_factors = factors
    return sorted(findings, key=lambda f: (-f.score, f.file, f.line))
