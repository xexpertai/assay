"""Dockerfile, GitHub Actions and dependency-manifest rules."""
from __future__ import annotations

import json
import re

import yaml

from ..models import Finding
from .secrets import is_placeholder, redact

SECRET_NAME_RE = re.compile(r"(?i)(password|passwd|secret|token|api_?key|access_?key|private_?key)")
PIPE_SH_RE = re.compile(r"(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b")
UNTRUSTED_CTX_RE = re.compile(
    r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)"
    r"[\w.\[\]*]*\.(title|body|message|name|label|ref|email|default_branch)|head_ref)\s*\}\}"
)
SECRET_FILE_RE = re.compile(
    r"(?i)(?:\bid_(?:rsa|dsa|ecdsa|ed25519)\b|[\w.-]*secret[\w.-]*|[\w.-]+\.(?:pem|key|p12|pfx|jks)\b|"
    r"\.env\b|credentials(?:\.json)?\b|\.npmrc\b|\.pypirc\b|\.netrc\b)")
SHA_RE = re.compile(r"@[0-9a-f]{40}$")


def _logical_lines(text: str):
    """Yield (line_no, instruction) joining backslash continuations."""
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf:
            start = i
            if not line.strip() or line.lstrip().startswith("#"):
                continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        yield start, buf.strip()
        buf = ""
    if buf:
        yield start, buf.strip()


def analyse_dockerfile(rel: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    user_root = True
    last_from = 1
    stages = 0

    def mk(line, **kw):
        return Finding(file=rel, line=line, resource=rel, **kw)

    for ln, ins in _logical_lines(text):
        op, _, arg = ins.partition(" ")
        op = op.upper()
        if op == "FROM":
            stages += 1
            last_from = ln
            user_root = True
            image = arg.split()[0] if arg.split() else ""
            tail = image.rsplit("/", 1)[-1]
            if image.lower() != "scratch" and "$" not in image and "@sha256:" not in image and \
                    (":" not in tail or tail.endswith(":latest")):
                out.append(mk(ln, rule_id="DF-BASE-UNPINNED", title=f"Base image is not pinned: {image}",
                              severity="low", confidence="high", evidence=ins,
                              rationale="An unpinned base image changes without review and makes builds "
                                        "non-reproducible.",
                              remediation="Pin a version tag or digest.", cwe="CWE-1104", category="unpinned_image"))
        elif op == "USER":
            u = arg.strip().split(":")[0]
            user_root = u in ("root", "0")
        elif op == "RUN" and PIPE_SH_RE.search(arg):
            out.append(mk(ln, rule_id="DF-CURL-PIPE-SHELL", title="Remote script piped straight into a shell",
                          severity="medium", confidence="high", evidence=ins[:160],
                          rationale="The build runs whatever the remote server returns, with no integrity check.",
                          remediation="Download, verify a checksum or signature, then execute.", cwe="CWE-494",
                          category="supply_chain"))
        elif op in ("ENV", "ARG"):
            for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*[= ]\s*\"?([^\"\s]+)\"?", arg):
                name, val = m.group(1), m.group(2)
                if SECRET_NAME_RE.search(name) and val and not is_placeholder(val) and not val.startswith("$"):
                    out.append(mk(ln, rule_id="DF-SECRET-IN-IMAGE", title=f"Secret baked into image via {op} {name}",
                                  severity="high", confidence="medium", evidence=f"{op} {name}={redact(val)}",
                                  rationale="ENV and ARG values are stored in image layers and history; anyone who "
                                            "pulls the image can read them.",
                                  remediation="Use BuildKit secrets (RUN --mount=type=secret) or runtime injection.",
                                  cwe="CWE-798", category="secret_in_code", tags=["secret"]))
        elif op == "ADD" and re.match(r"\s*https?://", arg):
            out.append(mk(ln, rule_id="DF-ADD-REMOTE", title="ADD fetches a remote URL", severity="low",
                          confidence="high", evidence=ins[:160],
                          rationale="Remote ADD has no integrity verification.",
                          remediation="Use curl with checksum verification, or ADD --checksum.", cwe="CWE-494",
                          category="supply_chain"))
        elif op in ("ADD", "COPY") and SECRET_FILE_RE.search(arg) and not arg.lstrip().startswith("--from"):
            later_rm = re.search(r"\brm\s+(-\w+\s+)*\S*" + re.escape(SECRET_FILE_RE.search(arg).group(0)), text)
            out.append(mk(ln, rule_id="DF-SECRET-FILE-IN-LAYER",
                          title=f"Secret-looking file copied into the image: {SECRET_FILE_RE.search(arg).group(0)}",
                          severity="high", confidence="medium", evidence=ins[:160],
                          rationale="Every ADD/COPY creates an image layer. "
                                    + ("Deleting the file in a later RUN does not remove it: it can still be "
                                       "extracted from the earlier layer." if later_rm else
                                       "Anyone who can pull the image can read the file."),
                          remediation="Do not copy secrets into images; use BuildKit secret mounts or runtime "
                                      "injection, and rotate the exposed secret.",
                          cwe="CWE-538", category="secret_in_code", tags=["secret"]))
        elif op == "EXPOSE" and re.search(r"\b22\b", arg):
            out.append(mk(ln, rule_id="DF-EXPOSE-SSH", title="Image exposes SSH (22)", severity="medium",
                          confidence="high", evidence=ins,
                          rationale="An SSH daemon inside a container widens the attack surface and is rarely needed.",
                          remediation="Remove sshd; use kubectl exec / docker exec for debugging.", cwe="CWE-284",
                          category="container_ssh"))
    if stages and user_root:
        out.append(mk(last_from, rule_id="DF-RUNS-AS-ROOT", title="Final image runs as root", severity="medium",
                      confidence="high", evidence="no non-root USER after the last FROM",
                      rationale="If the application is compromised, the attacker is root inside the container, "
                                "which makes escapes and tampering easier.",
                      remediation="Create an unprivileged user and add USER <name> before CMD.", cwe="CWE-250",
                      category="container_root"))
    return out


def _yaml_line_of(text: str, needle: str) -> int:
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return 1


def analyse_workflow(rel: str, text: str) -> list[Finding]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(doc, dict):
        return []
    out: list[Finding] = []
    on = doc.get("on", doc.get(True))  # PyYAML parses bare `on` as True
    triggers = set(on) if isinstance(on, (dict, list)) else ({on} if isinstance(on, str) else set())

    def mk(line, **kw):
        return Finding(file=rel, line=line, resource=rel, **kw)

    perms = doc.get("permissions")
    if perms == "write-all":
        out.append(mk(_yaml_line_of(text, "write-all"), rule_id="GHA-WRITE-ALL",
                      title="Workflow token has write-all permissions", severity="medium", confidence="high",
                      evidence="permissions: write-all",
                      rationale="Any compromised step can push code, create releases or alter settings.",
                      remediation="Set permissions to the minimum (e.g. contents: read).", cwe="CWE-269",
                      category="ci_permissions"))
    for jname, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            uses = str(step.get("uses", ""))
            run = str(step.get("run", ""))
            if uses:
                ref = (step.get("with") or {}).get("ref", "") if isinstance(step.get("with"), dict) else ""
                if "pull_request_target" in triggers and uses.startswith("actions/checkout") and \
                        "pull_request.head" in str(ref):
                    out.append(mk(_yaml_line_of(text, str(ref)), rule_id="GHA-PRT-CHECKOUT",
                                  title="pull_request_target checks out untrusted PR code", severity="critical",
                                  confidence="high", evidence=f"ref: {ref}",
                                  rationale="The job runs fork code with the base repo's secrets and write token "
                                            "(a 'pwn request').",
                                  remediation="Use pull_request for untrusted code, or never build the PR head in a "
                                              "pull_request_target job.", cwe="CWE-829", category="ci_injection"))
                owner = uses.split("/")[0]
                if not uses.startswith("./") and owner not in ("actions", "github") and not SHA_RE.search(uses) \
                        and not uses.startswith("docker://"):
                    out.append(mk(_yaml_line_of(text, uses), rule_id="GHA-UNPINNED-ACTION",
                                  title=f"Third-party action not pinned to a commit: {uses}", severity="low",
                                  confidence="high", evidence=f"uses: {uses}",
                                  rationale="A moved tag can inject new code into your pipeline with your secrets.",
                                  remediation="Pin to a full commit SHA.", cwe="CWE-829", category="supply_chain"))
            m = UNTRUSTED_CTX_RE.search(run)
            if m:
                out.append(mk(_yaml_line_of(text, m.group(0)), rule_id="GHA-SCRIPT-INJECTION",
                              title=f"Untrusted input interpolated into a shell step (job {jname})", severity="high",
                              confidence="high", evidence=m.group(0),
                              rationale="An attacker controls this text (e.g. an issue title) and it is pasted into "
                                        "a shell script before it runs, enabling command injection.",
                              remediation="Pass it through an env: variable and quote it (\"$TITLE\").",
                              cwe="CWE-78", category="ci_injection"))
    return out


def analyse_requirements(rel: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    if rel.endswith("package.json"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return []
        for section in ("dependencies", "devDependencies"):
            for name, ver in (doc.get(section) or {}).items():
                if str(ver).strip() in ("*", "latest", ""):
                    out.append(Finding(file=rel, line=_yaml_line_of(text, f'"{name}"'), resource=rel,
                                       rule_id="DEP-UNPINNED", title=f"Dependency '{name}' accepts any version",
                                       severity="low", confidence="high", evidence=f'"{name}": "{ver}"',
                                       rationale="Any future (possibly malicious) release is installed automatically.",
                                       remediation="Pin a version range and commit a lockfile.", cwe="CWE-1104",
                                       category="supply_chain"))
        return out
    for i, line in enumerate(text.splitlines(), 1):
        s = line.split("#")[0].strip()
        if not s:
            continue
        if re.match(r"--(extra-)?index-url\s+http://", s):
            out.append(Finding(file=rel, line=i, resource=rel, rule_id="DEP-INSECURE-INDEX",
                               title="Package index over plain HTTP", severity="medium", confidence="high",
                               evidence=s, rationale="Packages can be swapped in transit (no TLS).",
                               remediation="Use an https:// index.", cwe="CWE-319", category="supply_chain"))
        elif not s.startswith("-") and re.match(r"^[A-Za-z0-9_.\-\[\]]+$", s):
            out.append(Finding(file=rel, line=i, resource=rel, rule_id="DEP-UNPINNED",
                               title=f"Dependency '{s}' has no version constraint", severity="low",
                               confidence="high", evidence=s,
                               rationale="Builds pick up whatever is newest, including compromised releases.",
                               remediation="Pin versions (==) and use hashes (--require-hashes) for production.",
                               cwe="CWE-1104", category="supply_chain"))
    return out
