"""Stage 5: propose remediation actions and gate them behind explicit human approval.

Nothing is ever changed during a scan. A scan writes `plan.json` with proposed patches.
A person approves specific action IDs (`assay approve`), which records the plan hash.
`assay apply` refuses unless the approval matches the exact plan, the files are unchanged
since the scan, and every target file is inside the scanned scope. Every step is written
to a hash-chained audit log.
"""
from __future__ import annotations

import difflib
import getpass
import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .models import Finding
from .scope import Scope


class ApprovalError(RuntimeError):
    pass


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ---------------------------------------------------------------- audit log
class AuditLog:
    def __init__(self, path: Path):
        self.path = path

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        lines = self.path.read_text().strip().splitlines()
        return json.loads(lines[-1])["hash"] if lines else "0" * 64

    def write(self, stage: str, event: str, **data) -> None:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "stage": stage, "event": event, "data": data,
               "prev": self._last_hash()}
        rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
        with self.path.open("a") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")

    def verify(self) -> tuple[bool, int]:
        prev = "0" * 64
        n = 0
        for line in self.path.read_text().strip().splitlines():
            rec = json.loads(line)
            h = rec.pop("hash")
            if rec["prev"] != prev or hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest() != h:
                return False, n
            prev = h
            n += 1
        return True, n


# ---------------------------------------------------------------- patches
def _block_span(lines: list[str], start: int) -> tuple[int, int] | None:
    """0-based (open_line, close_line) of the block whose header is on line `start` (1-based)."""
    depth = 0
    opened = False
    in_str = False
    for i in range(start - 1, len(lines)):
        line = lines[i]
        j = 0
        while j < len(line):
            c = line[j]
            if in_str:
                if c == "\\":
                    j += 1
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "#" or line.startswith("//", j):
                break
            elif c == "{":
                depth += 1
                opened = True
            elif c == "}":
                depth -= 1
                if opened and depth == 0:
                    return start - 1, i
            j += 1
    return None


def tf_set_attr(text: str, block_line: int, attr: str, value: str) -> str | None:
    lines = text.splitlines(keepends=True)
    span = _block_span(lines, block_line)
    if not span:
        return None
    open_i, close_i = span
    depth = 0
    for i in range(open_i, close_i + 1):
        stripped = lines[i].strip()
        if i > open_i and depth == 1 and (stripped.startswith(attr + " ") or stripped.startswith(attr + "=")):
            indent = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
            lines[i] = f"{indent}{attr} = {value}\n"
            return "".join(lines)
        depth += lines[i].count("{") - lines[i].count("}")
    nxt = lines[open_i + 1] if open_i + 1 < len(lines) else "  "
    indent = nxt[: len(nxt) - len(nxt.lstrip())] or "  "
    lines.insert(open_i + 1, f"{indent}{attr} = {value}\n")
    return "".join(lines)


@dataclass
class Action:
    id: str
    finding_id: str
    file: str
    description: str
    diff: str
    file_sha256: str
    new_text_sha256: str

    def to_dict(self) -> dict:
        return asdict(self)


def propose(findings: list[Finding], scope: Scope) -> list[Action]:
    actions: list[Action] = []
    # group fixes per file so several patches to one file compose into a single diff each
    for f in findings:
        fix = f.fix
        if not fix or fix.get("type") != "tf_set_attr":
            continue
        path = scope.root / fix["file"]
        original = path.read_text()
        new = tf_set_attr(original, fix["block_line"], fix["attr"], fix["value"])
        if new is None or new == original:
            continue
        diff = "".join(difflib.unified_diff(original.splitlines(keepends=True), new.splitlines(keepends=True),
                                            f"a/{fix['file']}", f"b/{fix['file']}", n=2))
        actions.append(Action(f"A-{len(actions) + 1:02d}", f.id, fix["file"],
                              f"{fix['address']}: set {fix['attr']} = {fix['value']} (fixes {f.rule_id})", diff,
                              sha256_file(path), hashlib.sha256(new.encode()).hexdigest()))
    return actions


def plan_hash(plan: dict) -> str:
    return hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()


# ---------------------------------------------------------------- approval + apply
def approve(run_dir: Path, action_ids: list[str], approver: str | None = None) -> dict:
    plan = json.loads((run_dir / "plan.json").read_text())
    known = {a["id"] for a in plan["actions"]}
    unknown = [a for a in action_ids if a not in known]
    if unknown:
        raise ApprovalError(f"unknown action id(s): {', '.join(unknown)}")
    rec = {"plan_sha256": plan_hash(plan), "approved": sorted(action_ids),
           "approver": approver or getpass.getuser(), "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    (run_dir / "approval.json").write_text(json.dumps(rec, indent=2))
    AuditLog(run_dir / "audit.jsonl").write("approve", "actions_approved", approver=rec["approver"],
                                             actions=rec["approved"], plan_sha256=rec["plan_sha256"])
    return rec


def apply(run_dir: Path) -> list[str]:
    log = AuditLog(run_dir / "audit.jsonl")
    plan = json.loads((run_dir / "plan.json").read_text())
    appr_path = run_dir / "approval.json"
    if not appr_path.exists():
        log.write("apply", "refused", reason="no approval recorded")
        raise ApprovalError("refused: no approval recorded. Run `assay approve` first.")
    appr = json.loads(appr_path.read_text())
    if appr["plan_sha256"] != plan_hash(plan):
        log.write("apply", "refused", reason="plan changed after approval")
        raise ApprovalError("refused: the plan changed after it was approved.")
    scope = Scope.from_target(plan["scope_root"])
    applied: list[str] = []
    by_file: dict[str, list[dict]] = {}
    for a in plan["actions"]:
        if a["id"] in appr["approved"]:
            by_file.setdefault(a["file"], []).append(a)
    for rel, acts in by_file.items():
        path = scope.root / rel
        if not scope.contains(path):
            log.write("apply", "refused", reason="target outside scope", file=rel)
            raise ApprovalError(f"refused: {rel} is outside the approved scope")
        if sha256_file(path) != acts[0]["file_sha256"]:
            log.write("apply", "refused", reason="file changed since scan", file=rel)
            raise ApprovalError(f"refused: {rel} changed since the scan; re-run the scan.")
        text = path.read_text()
        # apply bottom-up so earlier line numbers stay valid
        for a in sorted(acts, key=lambda x: -x["fix"]["block_line"]):
            fx = a["fix"]
            new = tf_set_attr(text, fx["block_line"], fx["attr"], fx["value"])
            if new is None:
                raise ApprovalError(f"could not apply {a['id']}")
            text = new
        path.write_text(text)
        for a in acts:
            applied.append(a["id"])
            log.write("apply", "action_applied", action=a["id"], file=rel, approver=appr["approver"])
    return applied
