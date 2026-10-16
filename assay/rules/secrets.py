"""Hard-coded secret detection with redacted evidence.

Assay never prints or stores a full secret value: evidence keeps a 2-4 character
prefix and the length only.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass

from ..models import Finding


@dataclass
class SecretHit:
    kind: str
    value: str
    line_offset: int  # 0-based line inside the scanned text
    confidence: str


PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("AWS access key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "high"),
    ("AWS secret access key",
     re.compile(r"(?i)aws_?secret_?access_?key\W{0,4}[=:]\s*[\"']?([A-Za-z0-9/+=]{40})\b"), "high"),
    ("private key", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"), "high"),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"), "high"),
    ("Slack token", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"), "high"),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), "high"),
    ("Stripe secret key", re.compile(r"\b(sk_live_[0-9A-Za-z]{16,})\b"), "high"),
    ("password in connection URI",
     re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql(?:\+\w+)?|mongodb(?:\+srv)?|redis|amqp|mssql|snowflake|oracle|jdbc:\w+|"
                r"sqlserver|clickhouse|kafka|ftp|smb)://[^:/\s@'\"]+:([^@\s'\"]{4,})@"), "high"),
]

SECRET_NAME = r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|token|private[_-]?key|client[_-]?secret)"
GENERIC_RE = re.compile(
    rf"(?i)\b([A-Za-z0-9_\-]*{SECRET_NAME}[A-Za-z0-9_\-]*)\b[\"']?\s*(?:=|:|=>)\s*"
    rf"(?:[\"']([^\"'\s$]{{6,}})[\"']|([^\"'\s$#,;{{}}()\[\]]{{6,}})(?=\s*(?:[#,;]|$)))"  # quoted, or a bare value ending the line
)
SECRET_NAME_RE = re.compile(rf"(?i){SECRET_NAME}")
NON_SECRET_KEY_RE = re.compile(r"(?i)(_url|_uri|_endpoint|_path|_file|name|_id|_type|_tokens|_length|_ttl|_arn)$")
EXPRESSION_RE = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\[\]\-]+)+|[A-Z][A-Z0-9_]*)$")  # a.b.c or CONSTANT
PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x+|\*+|changeme|change_me|example|placeholder|dummy|redacted|your[_-].*|<.*>|\{\{.*\}\}|null|none|true|false)$"
)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def secret_tag(value: str) -> str:
    """Stable, non-reversible tag so the same secret can be correlated across files."""
    return "secret-id:" + hashlib.sha256(value.encode()).hexdigest()[:10]


def redact(value: str) -> str:
    """Keep a short prefix for recognition only: 4 characters when the value is 12+ long, otherwise 2."""
    if value.startswith("-----BEGIN"):
        return value  # the PEM header itself is not secret
    keep = 4 if len(value) >= 12 else 2
    return f"{value[:keep]}... ({len(value)} chars, redacted)"


def is_placeholder(value: str) -> bool:
    v = value.strip()
    return bool(PLACEHOLDER_RE.match(v)) or v.startswith(("var.", "local.", "${", "data.", "module."))


def scan_text(text: str) -> list[SecretHit]:
    hits: list[SecretHit] = []
    seen: set[tuple[int, str]] = set()
    for i, line in enumerate(text.splitlines()):
        for kind, rx, conf in PATTERNS:
            for m in rx.finditer(line):
                v = m.group(1)
                if is_placeholder(v) or v.startswith(("${", "{{", "%(")):
                    continue
                if (i, v) not in seen:
                    seen.add((i, v))
                    hits.append(SecretHit(kind, v, i, conf))
        for m in GENERIC_RE.finditer(line):
            name, v = m.group(1), m.group(2) or m.group(3)
            if (i, v) in seen or is_placeholder(v) or any(v == h.value for h in hits if h.line_offset == i):
                continue
            if m.group(3) and EXPRESSION_RE.match(v):  # bare reference such as random_password.db.result or API_KEY
                continue
            if NON_SECRET_KEY_RE.search(name):
                continue
            ent = entropy(v)
            classes = sum(bool(re.search(rx, v)) for rx in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
            if ent < 3.0 or classes < 2:
                continue
            seen.add((i, v))
            conf = "high" if ent >= 3.5 and len(v) >= 12 else "medium"
            hits.append(SecretHit(f"hard-coded credential in '{name}'", v, i, conf))
    return hits


def secret_findings(rel: str, text: str, kinds_skip: set[int] | None = None) -> list[Finding]:
    """Generic scan used for every text file in scope."""
    out: list[Finding] = []
    for h in scan_text(text):
        line = h.line_offset + 1
        if kinds_skip and line in kinds_skip:
            continue
        sev = "high" if h.confidence == "high" else "medium"
        if h.kind == "private key":
            sev = "critical" if not rel.endswith((".pub", ".example", ".sample")) else "low"
        out.append(Finding(
            rule_id="SECRET-HARDCODED",
            title=f"Hard-coded secret: {h.kind}",
            severity=sev,
            confidence=h.confidence,
            file=rel,
            line=line,
            resource=rel,
            evidence=redact(h.value),
            rationale="A credential stored in source control is readable by everyone with repo access, is copied into "
                      "every clone and backup, and stays in git history even after it is deleted.",
            remediation="Revoke and rotate the credential first, then load it at runtime from a secret manager "
                        "or environment injection, and add a pre-commit secret scan.",
            cwe="CWE-798",
            category="secret_in_code",
            tags=["secret", secret_tag(h.value)],
        ))
    return out
