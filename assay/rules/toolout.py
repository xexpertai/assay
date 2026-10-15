"""Ingest security-tool output *files* as evidence: nmap XML, nuclei JSONL, trivy JSON.

Assay never runs these tools and never contacts the hosts they mention. The files are read
from the local scope like any other artefact, so observations made by a human or a lab
runner can be correlated with the configuration review (for example "SG opens 22 to the
world" + "nmap saw 22/ssh open on 10.10.0.5"). Hosts outside the active ScopePolicy
allowlist are dropped and the drop is recorded as a decision.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from urllib.parse import urlsplit

from ..models import Finding

ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5900: "VNC", 23: "Telnet"}
DATA_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 27017: "MongoDB", 6379: "Redis",
              9200: "Elasticsearch", 5601: "Kibana", 11211: "Memcached", 2375: "Docker API", 2379: "etcd",
              10250: "kubelet"}
SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
           "unknown": "low", "negligible": "info"}


def kind_of(name: str, head: str) -> str | None:
    """Classify a file head as nmap / nuclei / trivy output, or None."""
    h = head.lstrip()
    if h.startswith("<?xml") and "<nmaprun" in h[:2000]:
        return "nmap"
    if name.endswith((".json", ".jsonl", ".ndjson")):
        first = h.splitlines()[0] if h else ""
        if first.startswith("{") and '"template-id"' in first and '"matched-at"' in first:
            return "nuclei"
        if h.startswith("{") and '"SchemaVersion"' in h[:300] and '"Results"' in h:
            return "trivy"
    return None


def _host_of(url_or_host: str) -> str:
    if "://" in url_or_host:
        return urlsplit(url_or_host).hostname or url_or_host
    return url_or_host.split("/")[0].split(":")[0]


# ---------------------------------------------------------------- nmap
def parse_nmap(text: str) -> list[dict]:
    """[{host, hostnames, port, proto, service, product, version}] for open ports."""
    out = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    for host in root.iter("host"):
        addr = next((a.get("addr") for a in host.findall("address") if a.get("addrtype", "").startswith("ipv")), None)
        if not addr:
            continue
        names = [h.get("name") for h in host.iter("hostname") if h.get("name")]
        for port in host.iter("port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = port.find("service")
            out.append({"host": addr, "hostnames": names, "port": int(port.get("portid", 0)),
                        "proto": port.get("protocol", "tcp"),
                        "service": (svc.get("name") if svc is not None else "") or "",
                        "product": (svc.get("product") if svc is not None else "") or "",
                        "version": (svc.get("version") if svc is not None else "") or ""})
    return out


def _nmap_findings(rel: str, rows: list[dict]) -> list[Finding]:
    out = []
    for r in rows:
        svc = " ".join(x for x in (r["service"], r["product"], r["version"]) if x)
        port = r["port"]
        meta = {"host": r["host"], "hostnames": r["hostnames"], "port": port, "service": r["service"], "source": rel,
                "key": f"{r['host']}:{port}/{r['proto']}"}
        if port in ADMIN_PORTS or port in DATA_PORTS:
            label = ADMIN_PORTS.get(port) or DATA_PORTS.get(port)
            out.append(Finding(rule_id="NMAP-OPEN-ADMIN" if port in ADMIN_PORTS else "NMAP-OPEN-DATA",
                               title=f"{label} ({port}/{r['proto']}) observed open on {r['host']}",
                               severity="high" if port in ADMIN_PORTS else "medium", confidence="high",
                               file=rel, line=1, resource=f"host/{r['host']}",
                               evidence=f"nmap: {port}/{r['proto']} open, service {svc or 'unknown'}",
                               rationale="A remote-administration or database service reachable by the scanner is "
                                         "a direct attack surface; the version banner tells attackers which "
                                         "exploits to try.",
                               remediation="Close the port or restrict it to a VPN/bastion range; confirm the "
                                           "service version is patched.",
                               cwe="CWE-284", category="observed_admin_port",
                               tags=["observed", "network", "internet-exposed"], meta=meta))
        else:
            out.append(Finding(rule_id="NMAP-OPEN-PORT", title=f"Port {port}/{r['proto']} observed open on {r['host']}",
                               severity="info", confidence="high", file=rel, line=1, resource=f"host/{r['host']}",
                               evidence=f"nmap: {port}/{r['proto']} open, service {svc or 'unknown'}",
                               rationale="Inventory of the observed attack surface; not a weakness by itself.",
                               remediation="Confirm the service is intended to be reachable.",
                               category="observed_port", tags=["observed", "network"], meta=meta))
    return out


# ---------------------------------------------------------------- nuclei
def parse_nuclei(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "template-id" in d:
            out.append(d)
    return out


def _nuclei_findings(rel: str, rows: list[dict]) -> list[Finding]:
    out = []
    for d in rows:
        info = d.get("info") or {}
        sev = SEV_MAP.get(str(info.get("severity", "info")).lower(), "low")
        host = _host_of(str(d.get("host") or d.get("matched-at") or ""))
        matched = str(d.get("matched-at") or "")
        matched = re.sub(r"\?.*$", "?…", matched)  # never keep query strings (they may carry tokens)
        out.append(Finding(rule_id=f"NUCLEI-{d['template-id']}", title=f"{info.get('name') or d['template-id']} on {host}",
                           severity=sev, confidence="medium", file=rel, line=1, resource=f"host/{host}",
                           evidence=f"nuclei template {d['template-id']} matched at {matched}",
                           rationale=str(info.get("description") or "A nuclei template matched; nuclei checks are "
                                         "signatures, so confirm the result by hand before acting."),
                           remediation=str(info.get("remediation") or "Patch or reconfigure the affected service; "
                                           "see the template's reference links."),
                           cwe="", category="observed_web_weakness", tags=["observed", "web"],
                           meta={"host": host, "template": d["template-id"], "source": rel,
                                 "key": f"{host}|{matched}"}))
    return out


# ---------------------------------------------------------------- trivy
def parse_trivy(text: str) -> dict | None:
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        return None
    return d if isinstance(d, dict) and "Results" in d else None


def _trivy_findings(rel: str, doc: dict) -> list[Finding]:
    out = []
    order = ["critical", "high", "medium", "low", "info"]
    for res in doc.get("Results") or []:
        target = str(res.get("Target") or doc.get("ArtifactName") or rel)
        by_pkg: dict[str, list[dict]] = defaultdict(list)
        for v in res.get("Vulnerabilities") or []:
            by_pkg[str(v.get("PkgName"))].append(v)
        for pkg, vs in sorted(by_pkg.items()):
            sevs = [SEV_MAP.get(str(v.get("Severity", "unknown")).lower(), "low") for v in vs]
            worst = min(sevs, key=order.index)
            fixable = [v for v in vs if v.get("FixedVersion")]
            ids = sorted({str(v.get("VulnerabilityID")) for v in vs})
            out.append(Finding(rule_id="TRIVY-VULNERABLE-PACKAGE",
                               title=f"{pkg} {vs[0].get('InstalledVersion', '')} has {len(ids)} known vulnerabilit"
                                     f"{'y' if len(ids) == 1 else 'ies'} (worst: {worst})",
                               severity=worst, confidence="high", file=rel, line=1, resource=f"image/{target}",
                               evidence=f"trivy: {', '.join(ids[:3])}{' …' if len(ids) > 3 else ''}; "
                                        f"{len(fixable)} of {len(vs)} have a fixed version",
                               rationale="Known vulnerabilities in installed packages are the first thing an "
                                         "attacker checks once a service banner is visible.",
                               remediation="Upgrade to " + (", ".join(sorted({str(v['FixedVersion']) for v in fixable})[:2])
                                                            if fixable else "a patched base image") + ".",
                               cwe="CWE-1395", category="vulnerable_package", tags=["observed", "supply-chain"],
                               meta={"target": target, "package": pkg, "ids": ids, "source": rel,
                                     "key": f"{target}|{pkg}"}))
        for m in res.get("Misconfigurations") or []:
            if str(m.get("Status", "FAIL")).upper() != "FAIL":
                continue
            sev = SEV_MAP.get(str(m.get("Severity", "unknown")).lower(), "low")
            out.append(Finding(rule_id=f"TRIVY-{m.get('ID', 'MISCONFIG')}", title=str(m.get("Title") or m.get("ID")),
                               severity=sev, confidence="high", file=rel, line=1, resource=f"image/{target}",
                               evidence=f"trivy misconfiguration {m.get('ID')} in {target}",
                               rationale=str(m.get("Description") or "Reported by trivy."),
                               remediation=str(m.get("Resolution") or "See the trivy reference."),
                               cwe="", category="observed_misconfig", tags=["observed"],
                               meta={"target": target, "source": rel, "key": f"{target}|{m.get('ID')}"}))
    return out


def analyse(files: list[tuple[str, str]], facts) -> list[Finding]:
    out: list[Finding] = []
    for rel, txt in files:
        kind = kind_of(rel, txt[:4000])
        if kind == "nmap":
            rows = parse_nmap(txt)
            kept = []
            for r in rows:
                ok, why = facts.policy.permits_host(r["host"], r["hostnames"])
                if ok:
                    kept.append(r)
                    facts.observed.setdefault(r["host"], {})[r["port"]] = r["service"] or r["product"]
                else:
                    facts.dropped.append((rel, r["host"], why))
            out += _nmap_findings(rel, kept)
        elif kind == "nuclei":
            rows = parse_nuclei(txt)
            kept = []
            for d in rows:
                host = _host_of(str(d.get("host") or d.get("matched-at") or ""))
                ok, why = facts.policy.permits_host(host, [])
                (kept.append(d) if ok else facts.dropped.append((rel, host, why)))
            out += _nuclei_findings(rel, kept)
        elif kind == "trivy":
            doc = parse_trivy(txt)
            if doc:
                out += _trivy_findings(rel, doc)
    return out
