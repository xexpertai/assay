"""Core data types shared by every stage of an assessment."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field

SEVERITY_POINTS = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0}
SEVERITIES = list(SEVERITY_POINTS)


@dataclass
class Artifact:
    """A file found during inventory, with the kind the analysers understand."""

    path: str  # relative to the scope root, POSIX separators
    kind: str  # terraform | kubernetes | dockerfile | compose | gha | env | requirements | other
    size: int


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str  # high | medium | low
    file: str
    line: int
    resource: str  # e.g. aws_s3_bucket.data or Deployment/web or Dockerfile
    evidence: str  # already redacted, never contains a full secret
    rationale: str  # why this matters, in plain words
    remediation: str
    cwe: str = ""
    category: str = ""  # used by correlation and evaluation
    tags: list[str] = field(default_factory=list)
    fix: dict | None = None  # optional mechanical fix: {"type": "set_attr", ...}
    id: str = ""
    score: float = 0.0
    score_factors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_POINTS:
            raise ValueError(f"bad severity {self.severity}")
        if not self.id:
            key = f"{self.rule_id}|{self.file}|{self.resource}|{self.line}"
            self.id = "F-" + hashlib.sha256(key.encode()).hexdigest()[:8]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Chain:
    """Several findings that together form a more serious attack path."""

    id: str
    title: str
    severity: str
    finding_ids: list[str]
    narrative: str  # deterministic explanation built from the findings
    resources: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Decision:
    """One logged agent decision: what it chose to do and why."""

    stage: str
    action: str
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)
