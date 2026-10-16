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
ADMIN_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5985: "WinRM", 5986: "WinRM"}
PLAINTEXT_PORTS = {21: "FTP", 69: "TFTP", 110: "POP3", 143: "IMAP", 161: "SNMP", 445: "SMB", 2375: "Docker API"}
DATA_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 27017: "MongoDB", 6379: "Redis",
              9200: "Elasticsearch", 5601: "Kibana", 11211: "Memcached"}
INTERP_SECRET_RE = re.compile(
    r"\$\{\s*(?:var|local|data\.[\w-]+|aws_[\w]+)\.[\w.\-]*(?:password|passwd|secret|token|api_?key|private_?key)[\w]*\s*\}",
    re.I)
SECRET_KEY_RE = re.compile(r"(?i)(password|passwd|secret|token|api_?key|access_?key|private_?key)")


def _f(block: Block, rel: str, **kw) -> Finding:
    kw.setdefault("line", block.line)
    kw.setdefault("resource", block.address)
    resolved = sorted({a.resolved_from for a in block.attrs.values() if a.resolved_from}
                      | {a.resolved_from for c in block.blocks for a in c.attrs.values() if a.resolved_from})
    f = Finding(file=rel, **kw)
    if resolved:
        f.meta["resolved"] = resolved
        f.evidence += " [resolved: " + "; ".join(resolved) + "]"
    return f


def _set_fix(block: Block, rel: str, attr: str, value: str, attrs: dict | None = None) -> dict:
    fix = {"type": "tf_set_attr", "file": rel, "address": block.address, "block_line": block.line,
           "attr": attr, "value": value}
    if attrs and len(attrs) > 1:
        fix["attrs"] = attrs  # several attributes set in one approved action
    return fix


def _unsure(block: Block, attr: str) -> tuple[str, str] | None:
    """(confidence, evidence) when `attr` is a non-literal expression, else None (literal or absent)."""
    v = block.get(attr)
    if v is None or _literal(v):
        return None
    return "medium", f"{attr} = {' '.join(v.split())} (expression; the resolved value is not known)"


def _dyn(block: Block, name: str) -> bool:
    """A `dynamic "name" { ... }` block: the nested block may or may not be rendered."""
    return any(b.type == "dynamic" and b.labels == [name] for b in block.blocks)


def _int(v: str | None) -> int | None:
    try:
        return int(unquote(v or ""))
    except ValueError:
        return None


def _port_range(rule: Block) -> tuple[int, int] | None:
    lo, hi = _int(rule.get("from_port")), _int(rule.get("to_port"))
    proto = (unquote(rule.get("protocol") or rule.get("ip_protocol")) or "").lower()
    if proto in ("-1", "all"):
        return (0, 65535)
    if lo is None or hi is None:
        return None
    if lo == 0 and hi == 0:
        return (0, 65535) if proto in ("-1", "all") else None
    return (lo, hi)


CIDR_ATTRS = ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6")
LITERAL_RE = re.compile(r'^(?:"[^"$]*"|true|false|-?\d+|\[\s*(?:"[^"$]*"\s*,?\s*)*\])$')


def _cidr_text(rule: Block) -> str:
    return " ".join(rule.get(a) or "" for a in CIDR_ATTRS)


def _world_open(rule: Block) -> bool:
    return any(w in _cidr_text(rule) for w in WORLD)


def _literal(value: str | None) -> bool:
    """True when the expression is a plain string or list literal (no variables, conditionals, loops)."""
    return value is None or LITERAL_RE.match(value.strip()) is not None


def _cidrs(rule: Block) -> str:
    """Human-readable source list: 0.0.0.0/0, ::/0 (not the raw HCL fragment)."""
    found = re.findall(r'"([^"]*)"', _cidr_text(rule))
    return ", ".join(found) or _cidr_text(rule).strip()


def _sg_owner(rule: Block, every: list[Block]) -> str:
    """The security group a standalone rule belongs to, so exposure attaches to the group."""
    for r in references(rule):
        if r.startswith("aws_security_group."):
            return r
    return rule.address


def _check_ingress(owner: Block, rule: Block, rel: str, resource: str | None = None) -> list[Finding]:
    if not _world_open(rule):
        return []
    pr = _port_range(rule)
    if pr is None:
        return []
    lo, hi = pr
    out: list[Finding] = []
    literal = all(_literal(rule.get(a)) for a in CIDR_ATTRS)
    conf = "high" if literal else "medium"
    res = resource or owner.address
    exposed = {**ADMIN_PORTS, **DATA_PORTS, **PLAINTEXT_PORTS}
    hit = {p: n for p, n in exposed.items() if lo <= p <= hi}
    if hit:
        names = ", ".join(f"{n} ({p})" for p, n in sorted(hit.items()))
        admin = any(p in ADMIN_PORTS for p in hit)
        data = any(p in DATA_PORTS for p in hit)
        rule_id = "TF-AWS-SG-OPEN-ADMIN" if admin else "TF-AWS-SG-OPEN-DATA" if data else "TF-AWS-SG-OPEN-PLAINTEXT"
        out.append(_f(owner, rel, line=rule.line, resource=res, rule_id=rule_id,
                      title=f"Security group allows the whole internet to reach {names}",
                      severity="high" if admin or data else "medium", confidence=conf,
                      evidence=f"ingress {lo}-{hi} from {_cidrs(rule)}"
                               + ("" if literal else " (expression, not a literal: confirm the resolved value)"),
                      rationale="Remote-administration and database ports open to 0.0.0.0/0 are scanned and "
                                "brute-forced within minutes of exposure." if admin or data else
                                "Plain-text protocols open to the internet expose credentials in transit and are "
                                "scanned constantly.",
                      remediation="Restrict the source CIDR to a VPN or bastion range, or use SSM Session Manager "
                                  "instead of opening SSH/RDP.",
                      cwe="CWE-284", category="sg_open_admin", tags=["internet-exposed", "network"],
                      meta={"ports": [lo, hi]}))
    else:
        out.append(_f(owner, rel, line=rule.line, resource=res, rule_id="TF-AWS-SG-INTERNET-FACING",
                      title=f"Resource is internet-facing on port {lo}" + (f"-{hi}" if hi != lo else ""),
                      severity="info", confidence=conf,
                      evidence=f"ingress {lo}-{hi} from {_cidrs(rule)}",
                      rationale="Not a vulnerability on its own, but anything attached to this group is reachable "
                                "from the internet, which raises the priority of its other findings.",
                      remediation="Confirm that public exposure is intended (for example a web front end).",
                      cwe="", category="internet_facing", tags=["internet-exposed", "network"],
                      meta={"ports": [lo, hi]}))
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


RESOURCE_POLICY_TYPES = {
    "aws_sqs_queue_policy": "SQS queue", "aws_sns_topic_policy": "SNS topic", "aws_kms_key": "KMS key",
    "aws_ecr_repository_policy": "ECR repository", "aws_secretsmanager_secret_policy": "Secrets Manager secret",
    "aws_glacier_vault": "Glacier vault", "aws_elasticsearch_domain_policy": "OpenSearch domain",
    "aws_opensearch_domain_policy": "OpenSearch domain", "aws_lambda_permission": "Lambda", "aws_efs_file_system_policy": "EFS",
    "aws_ses_identity_policy": "SES identity",
}
PAB_FLAGS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")


def _bucket_of(b: Block) -> str:
    """Address of the aws_s3_bucket a companion resource configures (falls back to the companion itself)."""
    for r in references(b):
        if r.startswith("aws_s3_bucket."):
            return r
    return b.address


def _public_acl_companion(every: list[Block], bucket: Block) -> bool:
    return any(x.type == "resource" and x.labels and x.labels[0] == "aws_s3_bucket_acl"
               and bucket.address in references(x)
               and (unquote(x.get("acl")) or "") in ("public-read", "public-read-write", "authenticated-read")
               for x in every)


def _versioning_companion_on(every: list[Block], bucket: Block) -> bool:
    for x in every:
        if x.type == "resource" and x.labels and x.labels[0] == "aws_s3_bucket_versioning" \
                and bucket.address in references(x):
            for vc in x.children("versioning_configuration"):
                if unquote(vc.get("status")) == "Enabled":
                    return True
    return False


def _statements(text: str) -> list[str]:
    """Split a policy (JSON, jsonencode() or heredoc) into its Statement objects, whitespace removed."""
    t = re.sub(r"\s+", "", text)
    m = re.search(r'"?Statement"?[:=]\[', t)
    if not m:
        return [t]
    out, depth, start = [], 0, None
    for i in range(m.end(), len(t)):
        c = t[i]
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and start is not None:
                out.append(t[start:i + 1])
                start = None
        elif c == "]" and depth == 0:
            break
    return out or [t]


PRINCIPAL_ANY_RE = re.compile(r'"?Principal"?[:=](?:"\*"|\{"?AWS"?[:=](?:"\*"|\["\*"\])\})')


def _principal_any(text: str, every: list[Block] | None = None) -> bool:
    """True if some Allow statement names Principal "*" (or {"AWS": "*"}); follows data.aws_iam_policy_document."""
    for st in _statements(text):
        if re.search(r'"?Effect"?[:=]"Allow"', st) and PRINCIPAL_ANY_RE.search(st):
            return True
    return bool(every) and any(_doc_allows_any(d) for d in _policy_docs(text, every))


def _policy_docs(text: str, every: list[Block]) -> list[Block]:
    """The data.aws_iam_policy_document blocks a policy expression refers to (indexed refs allowed)."""
    names = set(re.findall(r"data\.aws_iam_policy_document\.([A-Za-z_][A-Za-z0-9_\-]*)", text))
    return [b for b in every if b.type == "data" and b.labels[:1] == ["aws_iam_policy_document"]
            and len(b.labels) == 2 and b.labels[1] in names]


def _doc_allows_any(doc: Block) -> bool:
    for st in doc.children("statement"):
        if unquote(st.get("effect") or '"Allow"') != "Allow":
            continue
        for pr in st.children("principals"):
            ids = pr.get("identifiers") or ""
            if unquote(pr.get("type")) in ("AWS", "*") and '"*"' in ids:
                return True
    return False


def _principal_any_conditioned(text: str, every: list[Block] | None = None) -> bool:
    """True if every wildcard-principal Allow statement carries a Condition (which may narrow it)."""
    hits = [st for st in _statements(text) if re.search(r'"?Effect"?[:=]"Allow"', st) and PRINCIPAL_ANY_RE.search(st)]
    for d in _policy_docs(text, every or []):
        for st in d.children("statement"):
            if unquote(st.get("effect") or '"Allow"') == "Allow" and any(
                    unquote(p.get("type")) in ("AWS", "*") and '"*"' in (p.get("identifiers") or "")
                    for p in st.children("principals")):
                hits.append("Condition" if st.children("condition") else "")
    return bool(hits) and all("Condition" in st for st in hits)


def _launch_template_has_role(instance: Block, every: list[Block]) -> bool:
    for r in references(instance):
        if r.startswith("aws_launch_template."):
            for x in every:
                if x.address == r and (x.get("iam_instance_profile") is not None or x.children("iam_instance_profile")):
                    return True
    return False


def _pab_all_true(every: list[Block], bucket_addr: str) -> bool:
    """True when an aws_s3_bucket_public_access_block for the bucket sets all four flags to literal true."""
    for x in every:
        if x.type == "resource" and x.labels and x.labels[0] == "aws_s3_bucket_public_access_block" \
                and bucket_addr in references(x) and all(is_true(x.get(k)) for k in PAB_FLAGS):
            return True
    return False


def _iam_wildcard(text: str) -> bool:
    t = re.sub(r"\s+", "", text)
    action_star = re.search(r'"?[Aa]ctions?"?[:=]\[?"\*"', t) is not None
    resource_star = re.search(r'"?[Rr]esources?"?[:=]\[?"\*"', t) is not None
    allow = "Deny" not in t
    return action_star and resource_star and allow


def analyse_file(rel: str, text: str, blocks_all: list[tuple[str, Block]] | None = None) -> list[Finding]:
    if blocks_all is not None:  # pre-parsed (and variable-resolved) by parse_all
        blocks = [b for r, b in blocks_all if r == rel]
        every = [b for _, b in blocks_all]
    else:
        blocks = parse(text)
        every = blocks
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

        if rtype in RESOURCE_POLICY_TYPES:  # independent of the per-type chain below (aws_kms_key has both)
            pol = b.attrs.get("policy") or b.attrs.get("access_policy")
            if pol and _principal_any(pol.value, every):
                cond = _principal_any_conditioned(pol.value, every)
                target = next((r for r in references(b) if not r.startswith("data.")), b.address)
                out.append(_f(b, rel, line=pol.line, resource=target, rule_id="TF-AWS-RESOURCE-POLICY-PUBLIC",
                              title=f"{RESOURCE_POLICY_TYPES[rtype]} policy grants access to everyone (Principal \"*\")",
                              severity="high", confidence="medium" if cond else "high",
                              evidence='Effect "Allow" with Principal "*"' + (" (a Condition narrows it; check it)"
                                                                            if cond else ""),
                              rationale="A wildcard principal lets any AWS account, and for some services anonymous "
                                        "callers, use this resource: read the queue or topic, use the key, pull the "
                                        "image or read the secret.",
                              remediation="Name the accounts or roles that need access; add aws:SourceAccount / "
                                          "aws:SourceArn conditions for service principals.",
                              cwe="CWE-284", category="resource_policy_public",
                              tags=["internet-exposed", "privilege", "data-store"]))

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
            elif b.get("acl") and not _literal(b.get("acl")):
                out.append(_f(b, rel, line=b.attrs["acl"].line, rule_id="TF-AWS-UNRESOLVED-EXPOSURE",
                              title="S3 bucket ACL comes from a variable", severity="low", confidence="low",
                              evidence=f"acl = {b.get('acl')}",
                              rationale="Assay does not resolve variables, so it cannot tell whether this bucket is "
                                        "public. The value decides the bucket's exposure.",
                              remediation="Use a literal acl = \"private\" plus a public access block, or confirm the "
                                          "variable's value in every workspace.",
                              cwe="CWE-284", category="unresolved", tags=["data-store"]))
            elif not acl and _public_acl_companion(every, b):
                pass  # reported on the aws_s3_bucket_acl resource below
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
                dyn = _dyn(b, "server_side_encryption_configuration")
                out.append(_f(b, rel, rule_id="TF-AWS-S3-NO-ENCRYPTION",
                              title="S3 bucket does not declare server-side encryption", severity="low",
                              confidence="medium" if dyn else "high",
                              evidence="dynamic server_side_encryption_configuration block (may render empty)" if dyn
                              else "no server_side_encryption_configuration",
                              rationale="AWS now applies SSE-S3 by default to new objects, but declaring SSE-KMS "
                                        "makes encryption explicit, auditable and key-controlled.",
                              remediation="Add a server-side encryption configuration using a customer-managed KMS key.",
                              cwe="CWE-311", category="s3_encryption", tags=["data-store"]))
            if not b.children("logging") and not _has_companion(every, "aws_s3_bucket_logging", b):
                dyn = _dyn(b, "logging")
                out.append(_f(b, rel, rule_id="TF-AWS-S3-NO-LOGGING", title="S3 bucket has no access logging",
                              severity="low", confidence="medium" if dyn else "high",
                              evidence="dynamic logging block (may render empty)" if dyn else "no logging block",
                              rationale="Without access logs there is no record of who read or changed the data, "
                                        "which blocks incident investigation.",
                              remediation="Enable server access logging to a separate log bucket.",
                              cwe="CWE-778", category="s3_logging", tags=["data-store"]))
            ver = b.children("versioning")
            ver_on = any(is_true(v.get("enabled")) for v in ver) or _versioning_companion_on(every, b)
            if not ver_on:
                unsure = next((_unsure(v, "enabled") for v in ver if _unsure(v, "enabled")), None)
                out.append(_f(b, rel, rule_id="TF-AWS-S3-NO-VERSIONING", title="S3 bucket versioning is off",
                              severity="low", confidence=unsure[0] if unsure else "high",
                              evidence=unsure[1] if unsure else "no versioning { enabled = true }",
                              rationale="Without versioning, deleted or ransomware-overwritten objects cannot be "
                                        "recovered.",
                              remediation="Enable versioning (and consider MFA delete for critical buckets).",
                              cwe="CWE-693", category="s3_versioning", tags=["data-store"]))

        elif rtype == "aws_s3_bucket_acl":
            acl = unquote(b.get("acl")) or ""
            if acl in ("public-read", "public-read-write", "authenticated-read"):
                out.append(_f(b, rel, line=b.attrs["acl"].line, resource=_bucket_of(b), rule_id="TF-AWS-S3-PUBLIC-ACL",
                              title=f"S3 bucket ACL is '{acl}'", severity="high", confidence="high",
                              evidence=f'aws_s3_bucket_acl {b.labels[1]}: acl = "{acl}"',
                              rationale="A public ACL lets anyone on the internet list or read (or write) objects.",
                              remediation='Set acl = "private" and keep the public access block fully enabled.',
                              cwe="CWE-284", category="s3_public", tags=["internet-exposed", "data-store"],
                              fix=_set_fix(b, rel, "acl", '"private"')))
        elif rtype == "aws_s3_bucket_public_access_block":
            off = [k for k in PAB_FLAGS if is_false(b.get(k))]
            unknown = [k for k in PAB_FLAGS if b.get(k) is not None and not _literal(b.get(k))]
            if off:
                out.append(_f(b, rel, resource=_bucket_of(b), rule_id="TF-AWS-S3-PUBLIC-ACCESS-BLOCK-OFF",
                              title=f"S3 public access block is disabled ({len(off)} of 4 settings false)",
                              severity="medium", confidence="high",
                              evidence=", ".join(f"{k} = false" for k in off),
                              rationale="With these settings off, a public ACL or bucket policy takes effect "
                                        "instead of being blocked by the account-level guard rail.",
                              remediation="Set all four settings to true unless the bucket is a deliberate "
                                          "public website.", cwe="CWE-284", category="s3_public", tags=["data-store"],
                              fix=_set_fix(b, rel, off[0], "true", {k: "true" for k in off})))
            elif unknown:
                out.append(_f(b, rel, resource=_bucket_of(b), rule_id="TF-AWS-S3-PUBLIC-ACCESS-BLOCK-OFF",
                              title="S3 public access block settings come from expressions", severity="low",
                              confidence="low", evidence=", ".join(f"{k} = {b.get(k)}" for k in unknown),
                              rationale="Assay cannot see the resolved value; confirm it is true in every workspace.",
                              remediation="Prefer literal true values for the four public-access-block settings.",
                              cwe="CWE-284", category="s3_public", tags=["data-store"]))
        elif rtype == "aws_s3_bucket_policy":
            pol = b.attrs.get("policy")
            if pol and _principal_any(pol.value, every):
                cond = _principal_any_conditioned(pol.value, every)
                bucket = _bucket_of(b)
                blocked = _pab_all_true(every, bucket)
                sev = "info" if blocked and cond else "low" if blocked else "high"
                ev = 'Effect "Allow" with Principal "*"' + (" (a Condition narrows it; check it)" if cond else "")
                if blocked:
                    ev += "; blocked by the bucket's public access block (all four settings true), so the policy " \
                          "cannot grant public access unless that block is removed"
                out.append(_f(b, rel, line=pol.line, resource=bucket, rule_id="TF-AWS-S3-POLICY-PUBLIC",
                              title="S3 bucket policy grants access to everyone (Principal \"*\")"
                                    + (" but the public access block stops it" if blocked else ""),
                              severity=sev, confidence="medium" if cond else "high",
                              evidence=ev,
                              rationale="A wildcard principal makes the bucket readable (or writable) by any AWS "
                                        "account and, for s3:GetObject, by anonymous internet users.",
                              remediation="Name specific principals, or serve public content through CloudFront "
                                          "with an origin access control.",
                              cwe="CWE-284", category="s3_public",
                              tags=["data-store"] if blocked else ["internet-exposed", "data-store"]))
        elif rtype == "aws_iam_role":
            pol = b.attrs.get("assume_role_policy")
            if pol and _principal_any(pol.value, every):
                out.append(_f(b, rel, line=pol.line, rule_id="TF-AWS-IAM-ROLE-ASSUME-ANY",
                              title="IAM role can be assumed by anyone (Principal \"*\")", severity="critical",
                              confidence="medium" if _principal_any_conditioned(pol.value, every) else "high",
                              evidence='assume_role_policy allows sts:AssumeRole for Principal "*"',
                              rationale="Any AWS account in the world can assume this role and inherit its "
                                        "permissions.",
                              remediation="Restrict the principal to specific accounts, services or an OIDC "
                                          "provider with a subject condition.",
                              cwe="CWE-284", category="iam_wildcard", tags=["privilege", "internet-exposed"]))
        elif rtype == "aws_security_group":
            for ing in b.children("ingress"):
                out += _check_ingress(b, ing, rel)
        elif rtype == "aws_security_group_rule" and (unquote(b.get("type")) == "ingress"):
            out += _check_ingress(b, b, rel, resource=_sg_owner(b, every))
        elif rtype == "aws_vpc_security_group_ingress_rule":
            out += _check_ingress(b, b, rel, resource=_sg_owner(b, every))

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
                literal_optional = any(unquote(m.get("http_tokens")) == "optional" for m in meta)
                has_role = b.get("iam_instance_profile") is not None or _launch_template_has_role(b, every)
                out.append(_f(b, rel, rule_id="TF-AWS-EC2-IMDSV1",
                              title="Instance metadata service allows IMDSv1", severity="low",
                              confidence="high" if literal_optional else "medium",
                              evidence='metadata_options.http_tokens = "optional"' if literal_optional else
                              'no metadata_options.http_tokens = "required" (AWS default allows IMDSv1)',
                              meta={"has_role": has_role},
                              rationale="IMDSv1 lets a server-side request forgery bug steal the instance role "
                                        "credentials.",
                              remediation='Add metadata_options { http_tokens = "required" }.',
                              cwe="CWE-918", category="imdsv1", tags=["credential-access"]))

        elif rtype == "aws_lambda_function":
            out += _lambda_env(b, rel)

        elif rtype == "aws_ebs_volume" and not is_true(b.get("encrypted")):
            u = _unsure(b, "encrypted")
            out.append(_f(b, rel, rule_id="TF-AWS-EBS-UNENCRYPTED", title="EBS volume is not encrypted",
                          severity="medium", confidence=u[0] if u else "high", evidence=u[1] if u else "encrypted is not true",
                          rationale="Unencrypted volumes and every snapshot made from them expose data if a "
                                    "snapshot is shared or copied.",
                          remediation="Set encrypted = true (and kms_key_id), or enable EBS encryption by default.",
                          cwe="CWE-311", category="ebs_unencrypted", tags=["data-store"],
                          fix=_set_fix(b, rel, "encrypted", "true")))
        elif rtype == "aws_ebs_snapshot":
            src = [r for r in references(b) if r.startswith("aws_ebs_volume.")]
            src_blocks = [x for x in every if x.address in src]
            if src_blocks and not any(is_true(x.get("encrypted")) for x in src_blocks):
                u = next((_unsure(x, "encrypted") for x in src_blocks if _unsure(x, "encrypted")), None)
                out.append(_f(b, rel, rule_id="TF-AWS-EBS-SNAPSHOT-UNENCRYPTED",
                              title="EBS snapshot is taken from an unencrypted volume", severity="medium",
                              confidence=u[0] if u else "high",
                              evidence=f"source volume {src[0]}: " + (u[1] if u else "no encrypted = true"),
                              rationale="Snapshots inherit the volume's encryption; this one stores data in clear.",
                              remediation="Encrypt the source volume or copy the snapshot with encryption enabled.",
                              cwe="CWE-311", category="ebs_snapshot_unencrypted", tags=["data-store"]))

        elif rtype == "aws_kms_key" and not is_true(b.get("enable_key_rotation")):
            u = _unsure(b, "enable_key_rotation")
            out.append(_f(b, rel, rule_id="TF-AWS-KMS-NO-ROTATION", title="KMS key rotation is disabled",
                          severity="low", confidence=u[0] if u else "high",
                          evidence=u[1] if u else "enable_key_rotation is not true",
                          rationale="Automatic rotation limits how much data one compromised key version protects.",
                          remediation="Set enable_key_rotation = true.", cwe="CWE-320",
                          category="kms_rotation", fix=_set_fix(b, rel, "enable_key_rotation", "true")))

        elif rtype in ("aws_db_instance", "aws_rds_cluster", "aws_neptune_cluster", "aws_docdb_cluster"):
            if b.get("publicly_accessible") and not _literal(b.get("publicly_accessible")):
                out.append(_f(b, rel, line=b.attrs["publicly_accessible"].line, rule_id="TF-AWS-UNRESOLVED-EXPOSURE",
                              title="Database public exposure depends on a variable", severity="low", confidence="low",
                              evidence=f"publicly_accessible = {b.get('publicly_accessible')}",
                              rationale="Assay does not resolve variables, so it cannot tell whether this database "
                                        "endpoint is public. The value decides the exposure.",
                              remediation="Prefer a literal publicly_accessible = false, or confirm the variable's "
                                          "value in every workspace.",
                              cwe="CWE-284", category="unresolved", tags=["data-store"]))
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
                u = _unsure(b, "storage_encrypted")
                out.append(_f(b, rel, rule_id="TF-AWS-DB-UNENCRYPTED", title="Database storage is not encrypted",
                              severity="medium", confidence=u[0] if u else "high",
                              evidence=u[1] if u else "storage_encrypted is not true",
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
            dyn = _dyn(b, "access_logs")
            out.append(_f(b, rel, rule_id="TF-AWS-ELB-NO-LOGS", title="Load balancer has no access logs",
                          severity="low", confidence="medium" if dyn else "high",
                          evidence="dynamic access_logs block (may render empty)" if dyn else "no access_logs block",
                          rationale="Without access logs, attacks against the public entry point leave no trace.",
                          remediation="Enable access_logs to an S3 bucket.", cwe="CWE-778", category="elb_logging",
                          tags=["internet-exposed"]))
        elif rtype == "aws_ecr_repository":
            scan = b.children("image_scanning_configuration")
            if not any(is_true(s.get("scan_on_push")) for s in scan):
                u = next((_unsure(x, "scan_on_push") for x in scan if _unsure(x, "scan_on_push")), None)
                out.append(_f(b, rel, rule_id="TF-AWS-ECR-NO-SCAN", title="ECR images are not scanned on push",
                              severity="low", confidence=u[0] if u else "high",
                              evidence=u[1] if u else "scan_on_push is not true",
                              rationale="Known-vulnerable packages in images go unnoticed.",
                              remediation="Add image_scanning_configuration { scan_on_push = true }.", cwe="CWE-1104",
                              category="ecr_scan"))
        elif rtype == "aws_eks_cluster":
            for vc in b.children("vpc_config"):
                if not is_false(vc.get("endpoint_public_access")):
                    cidrs = vc.get("public_access_cidrs") or ""
                    u = _unsure(vc, "endpoint_public_access")
                    if not cidrs or '"0.0.0.0/0"' in cidrs:
                        out.append(_f(b, rel, line=vc.line, rule_id="TF-AWS-EKS-PUBLIC-ENDPOINT",
                                      title="EKS API endpoint is open to the internet", severity="medium",
                                      confidence=u[0] if u else "high",
                                      evidence=(u[1] + ", no CIDR limit") if u else "endpoint_public_access not false, no CIDR limit",
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


TFVARS_LINE_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.+?)\s*$')
VAR_REF_RE = re.compile(r"\bvar\.([A-Za-z_][A-Za-z0-9_-]*)\b")
TERNARY_RE = re.compile(r"^\s*(!?)\s*var\.([A-Za-z_][A-Za-z0-9_-]*)\s*\?\s*(.+?)\s*:\s*(.+?)\s*$")


def variable_values(files: list[tuple[str, str]], apply_defaults: bool = True,
                    overrides: dict | None = None) -> dict[str, tuple[str, str]]:
    """name -> (literal value, source) for one module directory.

    Sources, in increasing precedence: `variable "x" { default = ... }`, then terraform.tfvars /
    *.auto.tfvars (what Terraform itself applies automatically). Only literal values are kept, so a
    default that is itself an expression is ignored. Values set on the command line or by TF_VAR_*
    environment variables are unknown to Assay; a resolved value is reported with its source.
    """
    values: dict[str, tuple[str, str]] = {}
    for rel, text in files:
        if rel.endswith(".tf") and apply_defaults:
            for b in parse(text):
                if b.type == "variable" and len(b.labels) == 1:
                    d = b.get("default")
                    if d is not None and _literal(d):
                        values[b.labels[0]] = (d.strip(), f"default in {rel.rsplit('/', 1)[-1]}")
    for rel, text in files:
        name = rel.rsplit("/", 1)[-1]
        if name == "terraform.tfvars" or name.endswith(".auto.tfvars"):
            for line in text.splitlines():
                m = TFVARS_LINE_RE.match(line.split("#")[0].split("//")[0])
                if m and _literal(m.group(2)):
                    values[m.group(1)] = (m.group(2).strip(), name)
    for k, v in (overrides or {}).items():  # values passed by a module caller win; None = known unresolvable
        if v is None:
            values.pop(k, None)
        else:
            values[k] = v
    return values


def _resolve_expr(expr: str, values: dict[str, tuple[str, str]]) -> tuple[str, str] | None:
    """Resolve `var.x`, `!var.x` and `var.x ? a : b` (literal a/b) to a literal; else None."""
    e = expr.strip()
    m = re.fullmatch(r"(!?)\s*var\.([A-Za-z_][A-Za-z0-9_-]*)", e)
    if m and m.group(2) in values:
        v, src = values[m.group(2)]
        if m.group(1):
            if v in ("true", "false"):
                return ("false" if v == "true" else "true"), f"!var.{m.group(2)} ({src})"
            return None
        return v, f"var.{m.group(2)} ({src})"
    m = TERNARY_RE.match(e)
    if m and m.group(2) in values and _literal(m.group(3)) and _literal(m.group(4)):
        v, src = values[m.group(2)]
        if v in ("true", "false"):
            truth = (v == "true") != bool(m.group(1))
            return (m.group(3) if truth else m.group(4)).strip(), f"{m.group(1)}var.{m.group(2)} ? … ({src})"
    # lists and strings that only embed variable references, e.g. cidr_blocks = [var.cidr]
    used = [n for n in VAR_REF_RE.findall(e) if n in values]
    if used:
        sub = VAR_REF_RE.sub(lambda mm: values[mm.group(1)][0] if mm.group(1) in values else mm.group(0), e)
        if sub != e and _literal(sub):
            return sub, ", ".join(f"var.{n} ({values[n][1]})" for n in dict.fromkeys(used))
    return None


def resolve_variables(blocks: list[Block], values: dict[str, tuple[str, str]]) -> int:
    """Substitute resolvable variable references in place; returns how many attributes were resolved."""
    n = 0

    def walk(b: Block) -> None:
        nonlocal n
        if b.type == "variable":
            return
        for a in b.attrs.values():
            if a.resolved_from or "var." not in a.value:
                continue
            r = _resolve_expr(a.value, values)
            if r:
                a.value, a.resolved_from = r
                n += 1
        for c in b.blocks:
            walk(c)

    for b in blocks:
        walk(b)
    return n


def module_target(rel: str, src: str | None) -> str | None:
    """Directory (relative to the scan root, POSIX) a `module` block's local source points at, else None."""
    if not src or not src.startswith("."):
        return None
    base = rel.rsplit("/", 1)[0] if "/" in rel else ""
    stack: list[str] = []
    for p in (base.split("/") if base else []) + src.split("/"):
        if p == "..":
            if stack:
                stack.pop()
        elif p and p != ".":
            stack.append(p)
    return "/".join(stack)


def module_sources(files: list[tuple[str, str]]) -> set[str]:
    """Directories (relative to the scan root, POSIX) that `module` blocks point at with a local source."""
    out = set()
    for rel, text in files:
        if not rel.endswith(".tf"):
            continue
        for b in parse(text):
            if b.type == "module":
                t = module_target(rel, unquote(b.get("source")))
                if t is not None:
                    out.add(t)
    return out


MODULE_META_ARGS = {"source", "version", "count", "for_each", "providers", "depends_on"}


def module_overrides(calls: list[tuple[str, Block]], declared: set[str]) -> tuple[dict, list[tuple[str, str]]]:
    """Variable values for a module directory from the module blocks that call it (one level).

    Returns (overrides, notes). overrides[var] = (literal, source) when every caller passes the same literal,
    or None when callers pass an expression or disagree (the variable must then stay unresolved, even if the
    module declares a default). Variables no caller passes keep their default. notes explain each None.
    """
    seen: dict[str, list[tuple[str, str, Block, str]]] = {}
    for rel, b in calls:
        for k, a in b.attrs.items():
            if k in MODULE_META_ARGS or k not in declared:
                continue
            seen.setdefault(k, []).append((rel, a.value.strip(), b, a.resolved_from))
    ov: dict[str, tuple[str, str] | None] = {}
    notes: list[tuple[str, str]] = []
    for k, items in seen.items():
        vals = {v for _, v, _, _ in items}
        rel, v, b, via = items[0]
        name = ".".join(["module", *b.labels])
        if len(vals) == 1 and _literal(v):
            ov[k] = (v, f"argument of {name} in {rel.rsplit('/', 1)[-1]}" + (f", resolved from {via}" if via else ""))
        else:
            ov[k] = None
            why = "callers pass different values" if len(vals) > 1 else f"it is the expression {v[:60]}"
            notes.append((rel, f"{name} passes {k} to a module Assay analyses, but {why}: the value comes from "
                               f"the module caller and is not followed, so var.{k} stays unresolved"))
    return ov, notes


def parse_all(files: list[tuple[str, str]], resolve: bool = True, apply_defaults: bool = True,
              overrides: dict | None = None) -> list[tuple[str, Block]]:
    """Parse one module directory; resolve tfvars and, for a root module, literal variable defaults.

    A directory that another directory uses as a `module` source gets its real values from the caller,
    which Assay does not follow, so its defaults are NOT applied there (apply_defaults=False keeps the
    expression-based medium/low-confidence findings instead of trusting a possibly overridden default).
    """
    values = variable_values(files, apply_defaults, overrides) if resolve else {}
    blocks: list[tuple[str, Block]] = []
    for rel, text in files:
        if not rel.endswith(".tf"):
            continue
        parsed = parse(text)
        if values:
            resolve_variables(parsed, values)
        blocks += [(rel, b) for b in parsed]
    return blocks
