"""Terraform rules (AWS, plus a few GCP checks).

Each rule states why the configuration is risky and how to fix it. Rules only read
literal configuration; values that come from variables are not guessed.
"""
from __future__ import annotations

import re

from ..hcl import Block, is_false, is_true, parse, references, unquote
from ..models import Finding
from .secrets import is_placeholder, redact, scan_text, secret_tag

WORLD = ('"0.0.0.0/0"', '"::/0"')
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DATA_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 27017: "MongoDB", 6379: "Redis",
              9200: "Elasticsearch", 5601: "Kibana", 11211: "Memcached"}
INTERP_SECRET_RE = re.compile(
    r"\$\{\s*(?:var|local|data\.[\w-]+|aws_[\w]+)\.[\w.\-]*(?:password|passwd|secret|token|api_?key|private_?key)[\w]*\s*\}",
    re.I)
SECRET_KEY_RE = re.compile(r"(?i)(password|passwd|secret|token|api_?key|access_?key|private_?key)")


def _f(block: Block, rel: str, **kw) -> Finding:
    kw.setdefault("line", block.line)
    kw.setdefault("resource", block.address)
    return Finding(file=rel, **kw)


def _set_fix(block: Block, rel: str, attr: str, value: str) -> dict:
    return {"type": "tf_set_attr", "file": rel, "address": block.address, "block_line": block.line,
            "attr": attr, "value": value}


def _int(v: str | None) -> int | None:
    try:
        return int(unquote(v or ""))
    except ValueError:
        return None


def _port_range(rule: Block) -> tuple[int, int] | None:
    lo, hi = _int(rule.get("from_port")), _int(rule.get("to_port"))
    proto = (unquote(rule.get("protocol")) or "").lower()
    if proto in ("-1", "all"):
        return (0, 65535)
    if lo is None or hi is None:
        return None
    if lo == 0 and hi == 0:
        return (0, 65535) if proto in ("-1", "all") else None
    return (lo, hi)


def _world_open(rule: Block) -> bool:
    text = (rule.get("cidr_blocks") or "") + (rule.get("ipv6_cidr_blocks") or "")
    return any(w in text for w in WORLD)


def _check_ingress(owner: Block, rule: Block, rel: str) -> list[Finding]:
    if not _world_open(rule):
        return []
    pr = _port_range(rule)
    if pr is None:
        return []
    lo, hi = pr
    out: list[Finding] = []
    exposed = {**ADMIN_PORTS, **DATA_PORTS}
    hit = {p: n for p, n in exposed.items() if lo <= p <= hi}
    if hit:
        names = ", ".join(f"{n} ({p})" for p, n in sorted(hit.items()))
        admin = any(p in ADMIN_PORTS for p in hit)
        out.append(_f(owner, rel, line=rule.line,
                      rule_id="TF-AWS-SG-OPEN-ADMIN" if admin else "TF-AWS-SG-OPEN-DATA",
                      title=f"Security group allows the whole internet to reach {names}",
                      severity="high", confidence="high",
                      evidence=f"ingress {lo}-{hi} from " + " ".join((rule.get('cidr_blocks') or rule.get('ipv6_cidr_blocks') or "").split()),
                      rationale="Remote-administration and database ports open to 0.0.0.0/0 are scanned and "
                                "brute-forced within minutes of exposure.",
                      remediation="Restrict the source CIDR to a VPN or bastion range, or use SSM Session Manager "
                                  "instead of opening SSH/RDP.",
                      cwe="CWE-284", category="sg_open_admin", tags=["internet-exposed", "network"]))
    else:
        out.append(_f(owner, rel, line=rule.line, rule_id="TF-AWS-SG-INTERNET-FACING",
                      title=f"Resource is internet-facing on port {lo}" + (f"-{hi}" if hi != lo else ""),
                      severity="info", confidence="high",
                      evidence=f"ingress {lo}-{hi} from 0.0.0.0/0",
                      rationale="Not a vulnerability on its own, but anything attached to this group is reachable "
                                "from the internet, which raises the priority of its other findings.",
                      remediation="Confirm that public exposure is intended (for example a web front end).",
                      cwe="", category="internet_facing", tags=["internet-exposed", "network"]))
    return out


def _embedded_secrets(block: Block, attr: str, rel: str, rule_id: str, category: str, where: str) -> list[Finding]:
    a = block.attrs.get(attr)
    if not a:
        return []
    out = []
    for h in scan_text(a.value):
        out.append(_f(block, rel, line=a.line + h.line_offset, rule_id=rule_id,
                      title=f"Plain-text secret in {where}: {h.kind}",
                      severity="high", confidence=h.confidence, evidence=redact(h.value),
                      rationale=f"{where} is stored in Terraform state, visible in the cloud console and readable by "
                                "anyone who can describe the resource.",
                      remediation="Rotate the credential; use an IAM role (instance profile / execution role) or "
                                  "fetch the value from Secrets Manager or SSM Parameter Store at runtime.",
                      cwe="CWE-798", category=category, tags=["secret", secret_tag(h.value)]))
    hit_lines = {f.line for f in out}
    for i, line in enumerate(a.value.splitlines()):
        m = INTERP_SECRET_RE.search(line)
        if m and a.line + i not in hit_lines:
            out.append(_f(block, rel, line=a.line + i, rule_id=rule_id,
                          title=f"Sensitive value rendered into {where}: {m.group(0)}",
                          severity="high", confidence="medium", evidence=m.group(0),
                          rationale=f"Terraform writes the resolved secret into {where} in plain text, where it is "
                                    "readable from the instance metadata service, the cloud console and state.",
                          remediation="Pass only a secret's name or ARN and have the workload fetch the value from "
                                      "Secrets Manager / SSM Parameter Store using its IAM role.",
                          cwe="CWE-312", category=category, tags=["secret"]))
    return out


def _lambda_env(block: Block, rel: str) -> list[Finding]:
    out = []
    for env in block.children("environment"):
        a = env.attrs.get("variables")
        if not a:
            continue
        found = _embedded_secrets(env, "variables", rel, "TF-AWS-LAMBDA-ENV-SECRET", "secret_in_lambda_env",
                                  "Lambda environment variables")
        lines_hit = {f.line for f in found}
        for i, line in enumerate(a.value.splitlines()):
            m = re.match(r'\s*"?([A-Za-z0-9_]+)"?\s*=\s*"([^"]*)"', line)
            if m and SECRET_KEY_RE.search(m.group(1)) and m.group(2) and not is_placeholder(m.group(2)) \
                    and a.line + i not in lines_hit:
                found.append(_f(block, rel, line=a.line + i, rule_id="TF-AWS-LAMBDA-ENV-SECRET",
                                title=f"Plain-text secret in Lambda environment variable '{m.group(1)}'",
                                severity="high", confidence="medium", evidence=f"{m.group(1)} = {redact(m.group(2))}",
                                rationale="Lambda environment variables are visible to anyone with "
                                          "lambda:GetFunctionConfiguration and are stored in Terraform state.",
                                remediation="Use the function's execution role, or read the value from Secrets "
                                            "Manager at runtime.",
                                cwe="CWE-798", category="secret_in_lambda_env", tags=["secret"]))
        for f in found:
            f.resource = block.address
        out += found
    return out


def _has_companion(all_blocks: list[Block], rtype: str, target: Block) -> bool:
    for b in all_blocks:
        if b.type == "resource" and b.labels and b.labels[0] == rtype and target.address in references(b):
            return True
    return False


def _iam_wildcard(text: str) -> bool:
    t = re.sub(r"\s+", "", text)
    action_star = re.search(r'"?[Aa]ctions?"?[:=]\[?"\*"', t) is not None
    resource_star = re.search(r'"?[Rr]esources?"?[:=]\[?"\*"', t) is not None
    allow = "Deny" not in t
    return action_star and resource_star and allow


def analyse_file(rel: str, text: str, blocks_all: list[tuple[str, Block]] | None = None) -> list[Finding]:
    blocks = parse(text)
    every = [b for _, b in blocks_all] if blocks_all else blocks
    out: list[Finding] = []
    for b in blocks:
        if b.type == "provider":
            for key in ("access_key", "secret_key", "password", "token"):
                v = b.get(key)
                if v and v.startswith('"') and not is_placeholder(unquote(v)):
                    out.append(_f(b, rel, line=b.attrs[key].line, rule_id="TF-PROVIDER-CREDENTIAL",
                                  title=f"Provider credential '{key}' hard-coded", severity="critical",
                                  confidence="high", evidence=f"{key} = {redact(unquote(v))}",
                                  rationale="Cloud provider credentials in code give full account access to anyone "
                                            "who reads the repository.",
                                  remediation="Rotate the key; use environment credentials, SSO or workload identity.",
                                  cwe="CWE-798", category="secret_in_iac", tags=["secret"]))
        if b.type != "resource" or len(b.labels) != 2:
            continue
        rtype = b.labels[0]

        if rtype == "aws_s3_bucket":
            acl = unquote(b.get("acl")) or ""
            if acl in ("public-read", "public-read-write", "authenticated-read"):
                out.append(_f(b, rel, line=b.attrs["acl"].line, rule_id="TF-AWS-S3-PUBLIC-ACL",
                              title=f"S3 bucket ACL is '{acl}'", severity="high", confidence="high",
                              evidence=f'acl = "{acl}"',
                              rationale="A public ACL lets anyone on the internet list or read (or write) objects.",
                              remediation='Set acl = "private" and add an aws_s3_bucket_public_access_block.',
                              cwe="CWE-284", category="s3_public", tags=["internet-exposed", "data-store"],
                              fix={"type": "tf_set_attr", "file": rel, "address": b.address, "block_line": b.line,
                                   "attr": "acl", "value": '"private"'}))
            elif not _has_companion(every, "aws_s3_bucket_public_access_block", b):
                out.append(_f(b, rel, rule_id="TF-AWS-S3-NO-PUBLIC-ACCESS-BLOCK",
                              title="S3 bucket has no public access block", severity="medium", confidence="medium",
                              evidence="no aws_s3_bucket_public_access_block references this bucket",
                              rationale="Without a public access block, a later ACL or bucket-policy change can "
                                        "silently make the data public.",
                              remediation="Add aws_s3_bucket_public_access_block with all four settings true.",
                              cwe="CWE-284", category="s3_public", tags=["data-store"]))
            if not b.children("server_side_encryption_configuration") and \
                    not _has_companion(every, "aws_s3_bucket_server_side_encryption_configuration", b):
                out.append(_f(b, rel, rule_id="TF-AWS-S3-NO-ENCRYPTION",
                              title="S3 bucket does not declare server-side encryption", severity="low",
                              confidence="high", evidence="no server_side_encryption_configuration",
                              rationale="AWS now applies SSE-S3 by default to new objects, but declaring SSE-KMS "
                                        "makes encryption explicit, auditable and key-controlled.",
                              remediation="Add a server-side encryption configuration using a customer-managed KMS key.",
                              cwe="CWE-311", category="s3_encryption", tags=["data-store"]))
            if not b.children("logging") and not _has_companion(every, "aws_s3_bucket_logging", b):
                out.append(_f(b, rel, rule_id="TF-AWS-S3-NO-LOGGING", title="S3 bucket has no access logging",
                              severity="low", confidence="high", evidence="no logging block",
                              rationale="Without access logs there is no record of who read or changed the data, "
                                        "which blocks incident investigation.",
                              remediation="Enable server access logging to a separate log bucket.",
                              cwe="CWE-778", category="s3_logging", tags=["data-store"]))
            ver = b.children("versioning")
            ver_on = any(is_true(v.get("enabled")) for v in ver)
            if not ver_on and not _has_companion(every, "aws_s3_bucket_versioning", b):
                out.append(_f(b, rel, rule_id="TF-AWS-S3-NO-VERSIONING", title="S3 bucket versioning is off",
                              severity="low", confidence="high", evidence="no versioning { enabled = true }",
                              rationale="Without versioning, deleted or ransomware-overwritten objects cannot be "
                                        "recovered.",
                              remediation="Enable versioning (and consider MFA delete for critical buckets).",
                              cwe="CWE-693", category="s3_versioning", tags=["data-store"]))

        elif rtype == "aws_security_group":
            for ing in b.children("ingress"):
                out += _check_ingress(b, ing, rel)
        elif rtype == "aws_security_group_rule" and (unquote(b.get("type")) == "ingress"):
            out += _check_ingress(b, b, rel)

        elif rtype in ("aws_instance", "aws_launch_template", "aws_launch_configuration"):
            out += _embedded_secrets(b, "user_data", rel, "TF-AWS-EC2-USERDATA-SECRET", "secret_in_userdata",
                                     "EC2 user data")
            if is_true(b.get("associate_public_ip_address")):
                out.append(_f(b, rel, line=b.attrs["associate_public_ip_address"].line,
                              rule_id="TF-AWS-EC2-PUBLIC-IP", title="Instance gets a public IP address",
                              severity="info", confidence="high", evidence="associate_public_ip_address = true",
                              rationale="The instance is directly addressable from the internet.",
                              remediation="Place it behind a load balancer in a private subnet if possible.",
                              category="internet_facing", tags=["internet-exposed"]))
            meta = b.children("metadata_options")
            if rtype == "aws_instance" and not any(unquote(m.get("http_tokens")) == "required" for m in meta):
                out.append(_f(b, rel, rule_id="TF-AWS-EC2-IMDSV1",
                              title="Instance metadata service allows IMDSv1", severity="low", confidence="medium",
                              evidence='metadata_options.http_tokens is not "required"',
                              rationale="IMDSv1 lets a server-side request forgery bug steal the instance role "
                                        "credentials.",
                              remediation='Add metadata_options { http_tokens = "required" }.',
                              cwe="CWE-918", category="imdsv1", tags=["credential-access"]))

        elif rtype == "aws_lambda_function":
            out += _lambda_env(b, rel)

        elif rtype == "aws_ebs_volume" and not is_true(b.get("encrypted")):
            out.append(_f(b, rel, rule_id="TF-AWS-EBS-UNENCRYPTED", title="EBS volume is not encrypted",
                          severity="medium", confidence="high", evidence="encrypted is not true",
                          rationale="Unencrypted volumes and every snapshot made from them expose data if a "
                                    "snapshot is shared or copied.",
                          remediation="Set encrypted = true (and kms_key_id), or enable EBS encryption by default.",
                          cwe="CWE-311", category="ebs_unencrypted", tags=["data-store"],
                          fix=_set_fix(b, rel, "encrypted", "true")))
        elif rtype == "aws_ebs_snapshot":
            src = [r for r in references(b) if r.startswith("aws_ebs_volume.")]
            src_blocks = [x for x in every if x.address in src]
            if src_blocks and not any(is_true(x.get("encrypted")) for x in src_blocks):
                out.append(_f(b, rel, rule_id="TF-AWS-EBS-SNAPSHOT-UNENCRYPTED",
                              title="EBS snapshot is taken from an unencrypted volume", severity="medium",
                              confidence="high", evidence=f"source volume {src[0]} has no encrypted = true",
                              rationale="Snapshots inherit the volume's encryption; this one stores data in clear.",
                              remediation="Encrypt the source volume or copy the snapshot with encryption enabled.",
                              cwe="CWE-311", category="ebs_snapshot_unencrypted", tags=["data-store"]))

        elif rtype == "aws_kms_key" and not is_true(b.get("enable_key_rotation")):
            out.append(_f(b, rel, rule_id="TF-AWS-KMS-NO-ROTATION", title="KMS key rotation is disabled",
                          severity="low", confidence="high", evidence="enable_key_rotation is not true",
                          rationale="Automatic rotation limits how much data one compromised key version protects.",
                          remediation="Set enable_key_rotation = true.", cwe="CWE-320",
                          category="kms_rotation", fix=_set_fix(b, rel, "enable_key_rotation", "true")))

        elif rtype in ("aws_db_instance", "aws_rds_cluster", "aws_neptune_cluster", "aws_docdb_cluster"):
            if is_true(b.get("publicly_accessible")):
                out.append(_f(b, rel, line=b.attrs["publicly_accessible"].line, rule_id="TF-AWS-DB-PUBLIC",
                              title="Database is publicly accessible", severity="high", confidence="high",
                              evidence="publicly_accessible = true",
                              rationale="A public endpoint lets anyone on the internet attempt to log in to the "
                                        "database.",
                              remediation="Set publicly_accessible = false and reach it through private networking.",
                              cwe="CWE-284", category="db_public", tags=["internet-exposed", "data-store"],
                              fix=_set_fix(b, rel, "publicly_accessible", "false")))
            if not is_true(b.get("storage_encrypted")):
                out.append(_f(b, rel, rule_id="TF-AWS-DB-UNENCRYPTED", title="Database storage is not encrypted",
                              severity="medium", confidence="high", evidence="storage_encrypted is not true",
                              rationale="Unencrypted database storage and its snapshots expose data at rest.",
                              remediation="Set storage_encrypted = true (requires a new instance or restore).",
                              cwe="CWE-311", category="db_unencrypted", tags=["data-store"],
                              fix=_set_fix(b, rel, "storage_encrypted", "true")))
            for key in ("password", "master_password"):
                v = b.get(key)
                if v and v.startswith('"') and not is_placeholder(unquote(v)):
                    out.append(_f(b, rel, line=b.attrs[key].line, rule_id="TF-AWS-DB-PLAINTEXT-PASSWORD",
                                  title="Database password is hard-coded", severity="high", confidence="high",
                                  evidence=f"{key} = {redact(unquote(v))}",
                                  rationale="The password is in source control and in Terraform state.",
                                  remediation="Use manage_master_user_password = true (Secrets Manager) or a "
                                              "sensitive variable fed from a secret store.",
                                  cwe="CWE-798", category="secret_in_iac", tags=["secret", "data-store"]))

        elif rtype in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
            pol = b.attrs.get("policy")
            if pol and _iam_wildcard(pol.value):
                out.append(_f(b, rel, line=pol.line, rule_id="TF-AWS-IAM-WILDCARD",
                              title="IAM policy allows every action on every resource", severity="high",
                              confidence="high", evidence='Action "*" on Resource "*"',
                              rationale="Whoever holds this identity is effectively an account administrator.",
                              remediation="Grant only the actions and resources the workload needs.",
                              cwe="CWE-269", category="iam_wildcard", tags=["privilege"]))
        elif rtype == "aws_iam_access_key":
            out.append(_f(b, rel, rule_id="TF-AWS-IAM-ACCESS-KEY", title="Long-lived IAM user access key is created",
                          severity="low", confidence="high", evidence="aws_iam_access_key resource",
                          rationale="Static keys leak through logs, laptops and state files; the secret ends up in "
                                    "Terraform state.",
                          remediation="Prefer roles and short-lived credentials (SSO, OIDC federation).",
                          cwe="CWE-798", category="iam_static_key", tags=["credential"]))

        elif rtype == "aws_elasticsearch_domain" or rtype == "aws_opensearch_domain":
            ear = b.children("encrypt_at_rest")
            if not any(is_true(e.get("enabled")) for e in ear):
                out.append(_f(b, rel, rule_id="TF-AWS-ES-UNENCRYPTED", title="Search domain is not encrypted at rest",
                              severity="medium", confidence="high", evidence="encrypt_at_rest.enabled is not true",
                              rationale="Indexed data, often logs with personal data, is stored in clear.",
                              remediation="Enable encrypt_at_rest and node_to_node_encryption.", cwe="CWE-311",
                              category="es_unencrypted", tags=["data-store"]))
        elif rtype == "aws_elb" and not b.children("access_logs"):
            out.append(_f(b, rel, rule_id="TF-AWS-ELB-NO-LOGS", title="Load balancer has no access logs",
                          severity="low", confidence="high", evidence="no access_logs block",
                          rationale="Without access logs, attacks against the public entry point leave no trace.",
                          remediation="Enable access_logs to an S3 bucket.", cwe="CWE-778", category="elb_logging",
                          tags=["internet-exposed"]))
        elif rtype == "aws_ecr_repository":
            scan = b.children("image_scanning_configuration")
            if not any(is_true(s.get("scan_on_push")) for s in scan):
                out.append(_f(b, rel, rule_id="TF-AWS-ECR-NO-SCAN", title="ECR images are not scanned on push",
                              severity="low", confidence="high", evidence="scan_on_push is not true",
                              rationale="Known-vulnerable packages in images go unnoticed.",
                              remediation="Add image_scanning_configuration { scan_on_push = true }.", cwe="CWE-1104",
                              category="ecr_scan"))
        elif rtype == "aws_eks_cluster":
            for vc in b.children("vpc_config"):
                if not is_false(vc.get("endpoint_public_access")):
                    cidrs = vc.get("public_access_cidrs") or ""
                    if not cidrs or '"0.0.0.0/0"' in cidrs:
                        out.append(_f(b, rel, line=vc.line, rule_id="TF-AWS-EKS-PUBLIC-ENDPOINT",
                                      title="EKS API endpoint is open to the internet", severity="medium",
                                      confidence="high", evidence="endpoint_public_access not false, no CIDR limit",
                                      rationale="The Kubernetes control plane is exposed to credential stuffing and "
                                                "any future API-server vulnerability.",
                                      remediation="Disable the public endpoint or restrict public_access_cidrs.",
                                      cwe="CWE-284", category="eks_public", tags=["internet-exposed"]))

        elif rtype == "google_compute_firewall":
            src = b.get("source_ranges") or ""
            if '"0.0.0.0/0"' in src:
                ports_text = " ".join((a.get("ports") or "") for a in b.children("allow"))
                proto_all = any(unquote(a.get("protocol")) == "all" for a in b.children("allow"))
                admin = proto_all or re.search(r'"(22|3389)"', ports_text) or not ports_text
                out.append(_f(b, rel, rule_id="TF-GCP-FIREWALL-OPEN",
                              title="Firewall rule admits the whole internet" + (" to admin ports" if admin else ""),
                              severity="high" if admin else "info", confidence="high",
                              evidence=f"source_ranges include 0.0.0.0/0; ports {ports_text or 'all'}",
                              rationale="Open ingress exposes every matching instance to internet scanning.",
                              remediation="Limit source_ranges and ports to what is needed.", cwe="CWE-284",
                              category="sg_open_admin" if admin else "internet_facing",
                              tags=["internet-exposed", "network"]))
        elif rtype in ("google_storage_bucket_iam_binding", "google_storage_bucket_iam_member"):
            members = (b.get("members") or "") + (b.get("member") or "")
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                out.append(_f(b, rel, rule_id="TF-GCP-GCS-PUBLIC", title="Cloud Storage bucket is public",
                              severity="high", confidence="high", evidence="member allUsers/allAuthenticatedUsers",
                              rationale="Anyone on the internet can read the bucket's objects.",
                              remediation="Remove allUsers/allAuthenticatedUsers; use signed URLs for sharing.",
                              cwe="CWE-284", category="s3_public", tags=["internet-exposed", "data-store"]))
    return out


def parse_all(files: list[tuple[str, str]]) -> list[tuple[str, Block]]:
    blocks: list[tuple[str, Block]] = []
    for rel, text in files:
        blocks += [(rel, b) for b in parse(text)]
    return blocks
