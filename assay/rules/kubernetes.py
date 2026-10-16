"""Kubernetes manifest and docker-compose rules."""
from __future__ import annotations

import re

import yaml

from ..models import Finding
from .secrets import is_placeholder, redact

WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "ReplicationController"}
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "ALL", "NET_RAW"}
SENSITIVE_HOST_PATHS = ("/var/run/docker.sock", "/run/containerd", "/", "/etc", "/proc", "/root", "/var/lib/kubelet")
SECRET_NAME_RE = re.compile(r"(?i)(password|passwd|secret|token|api_?key|access_?key|private_?key)")


class _LineLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader, node, deep=False):
    m = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
    m["__line__"] = node.start_mark.line + 1
    return m


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


RBAC_KINDS = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}
ANALYSED_KINDS = WORKLOADS | RBAC_KINDS


def _expand(doc: dict) -> list[dict]:
    """`kind: List` (kubectl get -o yaml, kustomize, some Helm output) carries the real objects in items:."""
    if doc.get("kind") == "List" and isinstance(doc.get("items"), list):
        out = []
        for item in doc["items"]:
            if isinstance(item, dict):
                out += _expand(item)
        return out
    return [doc]


def load_docs(text: str) -> list[dict]:
    try:
        docs = [d for d in yaml.load_all(text, Loader=_LineLoader) if isinstance(d, dict)]
    except yaml.YAMLError:
        return []
    out: list[dict] = []
    for d in docs:
        out += _expand(d)
    return out


def unanalysed_kinds(docs: list[dict]) -> list[str]:
    """Kinds present in a file that no rule looks at (reported as a plan decision, never silently dropped)."""
    return sorted({str(d.get("kind")) for d in docs if d.get("kind") and d.get("kind") not in ANALYSED_KINDS})


def _pod_spec(doc: dict) -> dict | None:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    if kind in WORKLOADS:
        return (spec.get("template") or {}).get("spec")
    return None


def _ln(obj, default: int) -> int:
    return obj.get("__line__", default) if isinstance(obj, dict) else default


def _mk(rel, res, line, **kw) -> Finding:
    return Finding(file=rel, resource=res, line=line, **kw)


def analyse_workload(rel: str, doc: dict) -> list[Finding]:
    spec = _pod_spec(doc)
    if not isinstance(spec, dict):
        return []
    name = ((doc.get("metadata") or {}).get("name")) or "unnamed"
    res = f"{doc.get('kind')}/{name}"
    base = _ln(doc, 1)
    out: list[Finding] = []
    for key in ("hostPID", "hostIPC", "hostNetwork"):
        if spec.get(key) is True:
            out.append(_mk(rel, res, _ln(spec, base), rule_id="K8S-HOST-NAMESPACE",
                           title=f"Pod shares the node's namespace ({key}: true)", severity="high",
                           confidence="high", evidence=f"{key}: true",
                           rationale="Sharing host namespaces lets the container see or signal node processes or "
                                     "sniff node traffic, a common first step of container escape.",
                           remediation=f"Remove {key} unless this is a vetted node agent.", cwe="CWE-250",
                           category="k8s_host_namespace", tags=["escape"]))
    for vol in spec.get("volumes") or []:
        hp = (vol or {}).get("hostPath") if isinstance(vol, dict) else None
        if isinstance(hp, dict):
            path = str(hp.get("path", ""))
            sensitive = path in SENSITIVE_HOST_PATHS or path.startswith(("/var/run/docker", "/run/containerd"))
            out.append(_mk(rel, res, _ln(vol, base), rule_id="K8S-HOSTPATH",
                           title=f"Pod mounts host path {path}", severity="critical" if "docker.sock" in path or path == "/" else ("high" if sensitive else "medium"),
                           confidence="high", evidence=f"hostPath: {path}",
                           rationale="A hostPath mount gives the container direct access to node files; the "
                                     "container runtime socket or root filesystem means full node takeover.",
                           remediation="Use a PersistentVolume, ConfigMap or projected volume instead.",
                           cwe="CWE-668", category="k8s_hostpath", tags=["escape"]))
    pod_sc = spec.get("securityContext") or {}
    containers = list(spec.get("containers") or []) + list(spec.get("initContainers") or [])
    for c in containers:
        if not isinstance(c, dict):
            continue
        cname = c.get("name", "?")
        cl = _ln(c, base)
        sc = c.get("securityContext") or {}
        cres = f"{res}/{cname}"
        if sc.get("privileged") is True:
            out.append(_mk(rel, cres, _ln(sc, cl), rule_id="K8S-PRIVILEGED", title="Container runs privileged",
                           severity="critical", confidence="high", evidence="securityContext.privileged: true",
                           rationale="A privileged container has every capability and all host devices; escaping to "
                                     "the node is trivial.",
                           remediation="Drop privileged; grant only the specific capability needed.", cwe="CWE-250",
                           category="k8s_privileged", tags=["escape"]))
        caps = {str(x).upper() for x in ((sc.get("capabilities") or {}).get("add") or [])}
        bad = sorted(caps & DANGEROUS_CAPS)
        if bad:
            out.append(_mk(rel, cres, _ln(sc, cl), rule_id="K8S-DANGEROUS-CAPS",
                           title=f"Container adds dangerous capabilities: {', '.join(bad)}", severity="high",
                           confidence="high", evidence=f"capabilities.add: {bad}",
                           rationale="These capabilities allow kernel-level actions that break container isolation.",
                           remediation="Drop ALL capabilities and add back only narrowly required ones.",
                           cwe="CWE-250", category="k8s_caps", tags=["escape"]))
        non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot")) is True or \
            (isinstance(sc.get("runAsUser", pod_sc.get("runAsUser")), int) and sc.get("runAsUser", pod_sc.get("runAsUser")) > 0)
        no_esc = sc.get("allowPrivilegeEscalation") is False
        if not (non_root and no_esc) and sc.get("privileged") is not True:
            missing = [m for m, ok in (("runAsNonRoot", non_root), ("allowPrivilegeEscalation: false", no_esc)) if not ok]
            out.append(_mk(rel, cres, cl, rule_id="K8S-HARDENING-MISSING",
                           title="Container lacks basic hardening", severity="low", confidence="high",
                           evidence="missing " + ", ".join(missing),
                           rationale="Running as root with privilege escalation allowed makes any code-execution bug "
                                     "far more damaging.",
                           remediation="Set runAsNonRoot: true and allowPrivilegeEscalation: false.", cwe="CWE-250",
                           category="k8s_hardening"))
        image = str(c.get("image", ""))
        tail = image.rsplit("/", 1)[-1]
        if image and "@sha256:" not in image and (":" not in tail or tail.endswith(":latest")):
            out.append(_mk(rel, cres, cl, rule_id="K8S-IMAGE-UNPINNED", title=f"Image is not pinned: {image}",
                           severity="low", confidence="high", evidence=f"image: {image}",
                           rationale="A floating tag can change under you, so the running code is not reproducible "
                                     "or reviewable.",
                           remediation="Pin a version tag, ideally an immutable digest.", cwe="CWE-1104",
                           category="unpinned_image"))
        if not ((c.get("resources") or {}).get("limits")):
            out.append(_mk(rel, cres, cl, rule_id="K8S-NO-LIMITS", title="Container has no resource limits",
                           severity="low", confidence="high", evidence="resources.limits missing",
                           rationale="One compromised or buggy pod can starve the node (denial of service).",
                           remediation="Set CPU and memory limits.", cwe="CWE-770", category="k8s_limits"))
        for e in c.get("env") or []:
            if isinstance(e, dict) and "value" in e and SECRET_NAME_RE.search(str(e.get("name", ""))):
                v = str(e.get("value"))
                if v and not is_placeholder(v):
                    out.append(_mk(rel, cres, _ln(e, cl), rule_id="K8S-ENV-SECRET",
                                   title=f"Secret passed as plain env value '{e.get('name')}'", severity="high",
                                   confidence="medium", evidence=f"{e.get('name')}: {redact(v)}",
                                   rationale="The value is visible to anyone who can read the manifest or describe "
                                             "the pod.",
                                   remediation="Use valueFrom.secretKeyRef with a Kubernetes Secret or external "
                                               "secret store.", cwe="CWE-798", category="secret_in_code",
                                   tags=["secret"]))
    return out


def analyse_rbac(rel: str, doc: dict) -> list[Finding]:
    kind = doc.get("kind")
    name = ((doc.get("metadata") or {}).get("name")) or "unnamed"
    res = f"{kind}/{name}"
    out: list[Finding] = []
    if kind in ("ClusterRole", "Role"):
        for r in doc.get("rules") or []:
            if not isinstance(r, dict):
                continue
            verbs, resources = r.get("verbs") or [], r.get("resources") or []
            if "*" in verbs and "*" in resources:
                out.append(_mk(rel, res, _ln(r, _ln(doc, 1)), rule_id="K8S-RBAC-WILDCARD",
                               title=f"{kind} grants every verb on every resource", severity="high",
                               confidence="high", evidence="verbs: ['*'], resources: ['*']",
                               rationale="Any subject bound to this role controls the namespace or cluster.",
                               remediation="List only the verbs and resources needed.", cwe="CWE-269",
                               category="k8s_rbac", tags=["privilege"]))
            elif "secrets" in resources and set(verbs) & {"get", "list", "*", "watch"}:
                out.append(_mk(rel, res, _ln(r, _ln(doc, 1)), rule_id="K8S-RBAC-SECRETS",
                               title=f"{kind} can read Secrets", severity="medium", confidence="high",
                               evidence=f"resources: secrets, verbs: {verbs}",
                               rationale="Reading secrets usually yields credentials for other systems.",
                               remediation="Restrict to named secrets (resourceNames) or remove.", cwe="CWE-269",
                               category="k8s_rbac", tags=["privilege"]))
    if kind in ("ClusterRoleBinding", "RoleBinding"):
        ref = doc.get("roleRef") or {}
        if ref.get("name") == "cluster-admin":
            subj = ", ".join(f"{s.get('kind')}/{s.get('name')}" for s in doc.get("subjects") or [] if isinstance(s, dict))
            out.append(_mk(rel, res, _ln(doc, 1), rule_id="K8S-CLUSTER-ADMIN-BINDING",
                           title=f"cluster-admin is bound to {subj or 'a subject'}", severity="high",
                           confidence="high", evidence="roleRef.name: cluster-admin",
                           rationale="The bound identity can do anything in the cluster; if it is a pod's service "
                                     "account, any compromise of that pod owns the cluster.",
                           remediation="Bind a least-privilege Role instead.", cwe="CWE-269", category="k8s_rbac",
                           tags=["privilege"]))
    return out


def analyse_file(rel: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    for doc in load_docs(text):
        out += analyse_workload(rel, doc)
        out += analyse_rbac(rel, doc)
    return out


def analyse_compose(rel: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    for doc in load_docs(text):
        for name, svc in (doc.get("services") or {}).items():
            if not isinstance(svc, dict):
                continue
            line = _ln(svc, 1)
            res = f"service/{name}"
            if svc.get("privileged") is True:
                out.append(_mk(rel, res, line, rule_id="COMPOSE-PRIVILEGED", title="Compose service runs privileged",
                               severity="critical", confidence="high", evidence="privileged: true",
                               rationale="Privileged containers can take over the Docker host.",
                               remediation="Remove privileged; add specific capabilities only if required.",
                               cwe="CWE-250", category="k8s_privileged", tags=["escape"]))
            for v in svc.get("volumes") or []:
                if "docker.sock" in str(v):
                    out.append(_mk(rel, res, line, rule_id="COMPOSE-DOCKER-SOCK",
                                   title="Compose service mounts the Docker socket", severity="critical",
                                   confidence="high", evidence=str(v),
                                   rationale="Access to the Docker socket is root on the host.",
                                   remediation="Avoid mounting the socket; use a restricted proxy if unavoidable.",
                                   cwe="CWE-668", category="k8s_hostpath", tags=["escape"]))
            if svc.get("network_mode") == "host":
                out.append(_mk(rel, res, line, rule_id="COMPOSE-HOST-NETWORK", title="Compose service uses host network",
                               severity="medium", confidence="high", evidence="network_mode: host",
                               rationale="The container shares the host's network stack and can reach local-only "
                                         "services.",
                               remediation="Use a bridge network and publish only needed ports.", cwe="CWE-668",
                               category="k8s_host_namespace"))
    return out
