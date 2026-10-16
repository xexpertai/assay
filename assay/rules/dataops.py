"""DataOps configuration rules: Airflow, dbt, SQL grants and users, Kafka broker settings.

Pipelines carry credentials and grants in plain files more often than infrastructure code does.
These rules read: Airflow DAG files and airflow.cfg / webserver_config.py; dbt profiles.yml;
.sql files (GRANT, CREATE/ALTER USER); Kafka server.properties. Connection URIs with embedded
passwords are detected everywhere by the secret scan (rules/secrets.py).
"""
from __future__ import annotations

import re

from ..models import Finding
from .secrets import is_placeholder, redact

AIRFLOW_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+airflow\b", re.M)
AIRFLOW_CFG_RE = re.compile(r"^\s*\[(?:core|webserver|api|scheduler)\]", re.M)
DBT_PROFILE_RE = re.compile(r"^\s*outputs:\s*$", re.M)
KAFKA_RE = re.compile(r"^\s*(?:listeners|broker\.id|zookeeper\.connect|process\.roles)\s*=", re.M)
SQL_GRANT_RE = re.compile(r"(?i)^\s*(GRANT|CREATE\s+USER|ALTER\s+USER|CREATE\s+ROLE|ALTER\s+ROLE)\b", re.M)

ENV_VAR_RE = re.compile(r"env_var\(|\{\{\s*env_var|\$\{?[A-Z_]{3,}\}?|os\.environ|Variable\.get|conn_id=|BaseHook|Secret\(")
SECRET_KEY_RE = re.compile(r"(?i)^(password|passwd|pwd|secret|token|api_?key|private_?key|keyfile_json|client_secret)$")


def kind_of(name: str, head: str) -> str | None:
    if name == "airflow.cfg" or (name == "webserver_config.py"):
        return "airflow-config"
    if name.endswith(".py") and AIRFLOW_IMPORT_RE.search(head):
        return "airflow-dag"
    if name in ("profiles.yml", "profiles.yaml") and DBT_PROFILE_RE.search(head):
        return "dbt-profile"
    if name.endswith(".sql") and SQL_GRANT_RE.search(head):
        return "sql"
    if name.endswith(".properties") and KAFKA_RE.search(head):
        return "kafka"
    return None


def _mk(rel: str, line: int, resource: str, **kw) -> Finding:
    return Finding(file=rel, line=line, resource=resource, **kw)


# ---------------------------------------------------------------- Airflow
def analyse_airflow_config(rel: str, text: str) -> list[Finding]:
    out = []
    section = ""
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        m = re.match(r"^\[([^\]]+)\]", line)
        if m:
            section = m.group(1).lower()
            continue
        kv = re.match(r"^([A-Za-z_]+)\s*=\s*(.*)$", line)
        if not kv:
            # webserver_config.py style
            if re.match(r"^AUTH_ROLE_PUBLIC\s*=\s*['\"]Admin['\"]", line):
                out.append(_mk(rel, i, "airflow/webserver", rule_id="AIRFLOW-PUBLIC-ADMIN",
                               title="Airflow UI gives anonymous visitors the Admin role", severity="critical",
                               confidence="high", evidence="AUTH_ROLE_PUBLIC = 'Admin'",
                               rationale="Anyone who can reach the webserver can run, edit and delete every DAG and "
                                         "read every connection.",
                               remediation="Remove AUTH_ROLE_PUBLIC or set it to 'Viewer' at most; require login.",
                               cwe="CWE-306", category="dataops_unauth", tags=["internet-exposed", "privilege"]))
            continue
        key, val = kv.group(1).lower(), kv.group(2).strip()
        low = val.lower()
        if section == "webserver" and key == "expose_config" and low in ("true", "non-sensitive-only"):
            out.append(_mk(rel, i, "airflow/webserver", rule_id="AIRFLOW-EXPOSE-CONFIG",
                           title="Airflow exposes its configuration in the UI", severity="medium", confidence="high",
                           evidence=f"[webserver] expose_config = {val}",
                           rationale="The configuration page can reveal connection strings, the Fernet key and "
                                     "secret backends to any UI user.",
                           remediation="Set expose_config = False.", cwe="CWE-200", category="dataops_exposure"))
        elif section == "webserver" and key == "authenticate" and low == "false":
            out.append(_mk(rel, i, "airflow/webserver", rule_id="AIRFLOW-NO-AUTH",
                           title="Airflow webserver authentication is disabled", severity="critical", confidence="high",
                           evidence="[webserver] authenticate = False",
                           rationale="Unauthenticated users can trigger DAGs and read connections.",
                           remediation="Enable authentication (RBAC / an auth backend).", cwe="CWE-306",
                           category="dataops_unauth", tags=["internet-exposed", "privilege"]))
        elif section == "api" and key == "auth_backends" and "default" in low and "session" not in low \
                and "basic_auth" not in low:
            out.append(_mk(rel, i, "airflow/api", rule_id="AIRFLOW-API-OPEN",
                           title="Airflow REST API accepts unauthenticated requests", severity="critical",
                           confidence="high", evidence=f"[api] auth_backends = {val}",
                           rationale="airflow.api.auth.backend.default allows every request without credentials.",
                           remediation="Use basic_auth, session or a token backend.", cwe="CWE-306",
                           category="dataops_unauth", tags=["internet-exposed", "privilege"]))
        elif section == "core" and key == "load_examples" and low == "true":
            out.append(_mk(rel, i, "airflow/core", rule_id="AIRFLOW-LOAD-EXAMPLES",
                           title="Airflow loads example DAGs", severity="low", confidence="high",
                           evidence="[core] load_examples = True",
                           rationale="Example DAGs include a BashOperator anyone with DAG rights can repurpose, and "
                                     "they reveal the deployment is unhardened.",
                           remediation="Set load_examples = False in production.", cwe="CWE-1188",
                           category="dataops_hardening"))
        elif section == "core" and key == "fernet_key" and not val:
            out.append(_mk(rel, i, "airflow/core", rule_id="AIRFLOW-NO-FERNET-KEY",
                           title="Airflow stores connections and variables unencrypted (empty fernet_key)",
                           severity="high", confidence="high", evidence="[core] fernet_key =",
                           rationale="Without a Fernet key every connection password sits in clear text in the "
                                     "metadata database.",
                           remediation="Generate a Fernet key and keep it in a secret store.", cwe="CWE-312",
                           category="dataops_plaintext", tags=["data-store"]))
        elif key in ("sql_alchemy_conn", "broker_url", "result_backend") and re.search(r"://[^:/\s]+:[^@\s]+@", val):
            out.append(_mk(rel, i, f"airflow/{section or 'core'}", rule_id="AIRFLOW-CONN-PASSWORD",
                           title=f"Database/broker password in airflow.cfg ({key})", severity="high", confidence="high",
                           evidence=f"{key} = {_redact_uri(val)}",
                           rationale="The metadata database password is readable by everyone with the file.",
                           remediation=f"Use {key.upper()}_CMD / _SECRET or an environment variable.",
                           cwe="CWE-798", category="secret_in_code", tags=["secret"]))
    return out


def _redact_uri(val: str) -> str:
    return re.sub(r"://([^:/@\s]+):[^@\s]+@", lambda m: f"://{m.group(1)}:<redacted>@", val)


DAG_SECRET_RE = re.compile(r"(?i)\b([A-Za-z0-9_]*(?:password|passwd|secret|token|api_?key|access_?key|private_?key)[A-Za-z0-9_]*)"
                           r"\s*[:=]\s*['\"]([^'\"]{6,})['\"]")


def analyse_airflow_dag(rel: str, text: str) -> list[Finding]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if ENV_VAR_RE.search(line):
            continue
        m = DAG_SECRET_RE.search(line)
        if m and not is_placeholder(m.group(2)):
            out.append(_mk(rel, i, rel, rule_id="AIRFLOW-DAG-SECRET",
                           title=f"Credential literal in a DAG file ('{m.group(1)}')", severity="high",
                           confidence="medium", evidence=f"{m.group(1)} = {redact(m.group(2))}",
                           rationale="DAG files are shared code: every author and every worker can read the value, "
                                     "and it is rendered into task logs.",
                           remediation="Store it as an Airflow Connection or Variable backed by a secrets backend "
                                       "and reference it by conn_id.",
                           cwe="CWE-798", category="secret_in_code", tags=["secret"]))
        if re.search(r"\bBashOperator\(", line) or re.search(r"bash_command\s*=", line):
            if re.search(r"(?i)(curl|wget)\b[^|]*\|\s*(ba)?sh\b", line):
                out.append(_mk(rel, i, rel, rule_id="AIRFLOW-PIPE-TO-SHELL",
                               title="DAG task pipes a download into a shell", severity="high", confidence="high",
                               evidence=line.strip()[:100],
                               rationale="The worker executes whatever the remote serves; no pin, no checksum.",
                               remediation="Download, verify a checksum, then execute a pinned artefact.",
                               cwe="CWE-494", category="supply_chain"))
        if re.search(r"(?i)(schedule_interval|schedule)\s*=\s*['\"]@continuous['\"]", line):
            pass
        if re.search(r"\bPythonVirtualenvOperator\(|\bKubernetesPodOperator\(", line) and re.search(
                r"privileged\s*=\s*True", text):
            out.append(_mk(rel, i, rel, rule_id="AIRFLOW-PRIVILEGED-POD",
                           title="DAG runs a privileged pod", severity="high", confidence="medium",
                           evidence="KubernetesPodOperator with privileged=True",
                           rationale="A privileged task container can take over the worker node.",
                           remediation="Drop privileged; add only the capabilities the task needs.", cwe="CWE-250",
                           category="k8s_privileged", tags=["escape"]))
            break
    return out


# ---------------------------------------------------------------- dbt
def analyse_dbt_profile(rel: str, text: str) -> list[Finding]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*([A-Za-z_]+)\s*:\s*(.+?)\s*$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip().strip("'\"")
        if SECRET_KEY_RE.match(key) and val and not ENV_VAR_RE.search(val) and not is_placeholder(val) and \
                not val.startswith("{{"):
            out.append(_mk(rel, i, "dbt/profiles", rule_id="DBT-PROFILE-SECRET",
                           title=f"dbt profile stores '{key}' in plain text", severity="high", confidence="high",
                           evidence=f"{key}: {redact(val)}",
                           rationale="profiles.yml is copied to every developer machine and CI runner; a warehouse "
                                     "password here is a warehouse password everywhere.",
                           remediation='Use "{{ env_var(\'DBT_PASSWORD\') }}" and inject the value at run time.',
                           cwe="CWE-798", category="secret_in_code", tags=["secret"]))
        if key == "threads" and val.isdigit() and int(val) > 64:
            out.append(_mk(rel, i, "dbt/profiles", rule_id="DBT-THREADS-HIGH", title=f"dbt threads = {val}",
                           severity="info", confidence="high", evidence=f"threads: {val}",
                           rationale="Very high parallelism can exhaust warehouse connection limits.",
                           remediation="Keep threads within the warehouse's connection quota.", category="dataops_hardening"))
    return out


# ---------------------------------------------------------------- SQL grants and users
SQL_STATEMENT_RE = re.compile(r"[^;]+;?", re.S)


def analyse_sql(rel: str, text: str) -> list[Finding]:
    out = []
    pos = 0
    for stmt in re.split(r";", text):
        # first real line of the statement: skip blank and comment lines after the previous ';'
        lead = 0
        for ln in stmt.splitlines(keepends=True):
            if ln.strip() and not ln.strip().startswith("--"):
                break
            lead += len(ln)
        start_line = text.count("\n", 0, pos + lead) + 1
        pos += len(stmt) + 1
        body = "\n".join(ln for ln in stmt.splitlines() if not ln.strip().startswith("--"))
        s = " ".join(body.split())
        if not s:
            continue
        up = s.upper()
        if up.startswith("GRANT"):
            to_public = re.search(r"\bTO\s+PUBLIC\b", up) is not None
            all_priv = re.search(r"\bGRANT\s+ALL(\s+PRIVILEGES)?\b", up) is not None
            on_everything = re.search(r"\bON\s+(\*\.\*|ALL\s+TABLES\s+IN\s+SCHEMA|DATABASE\s+\*)", up) is not None \
                or re.search(r"\bON\s+\*\.\*", up) is not None
            grant_option = "WITH GRANT OPTION" in up or "WITH ADMIN OPTION" in up
            if to_public:
                out.append(_mk(rel, start_line, "sql/grant", rule_id="SQL-GRANT-PUBLIC",
                               title="Privileges granted to PUBLIC", severity="high", confidence="high", evidence=s[:120],
                               rationale="PUBLIC means every present and future database user, including service "
                                         "accounts that should see nothing.",
                               remediation="Grant to named roles; REVOKE ... FROM PUBLIC.", cwe="CWE-732",
                               category="db_overgrant", tags=["privilege", "data-store"]))
            if all_priv and on_everything:
                out.append(_mk(rel, start_line, "sql/grant", rule_id="SQL-GRANT-ALL-GLOBAL",
                               title="ALL PRIVILEGES granted on every object", severity="high", confidence="high",
                               evidence=s[:120],
                               rationale="The grantee is effectively a database administrator.",
                               remediation="Grant only the statements and schemas the workload needs.", cwe="CWE-250",
                               category="db_overgrant", tags=["privilege", "data-store"]))
            if grant_option:
                out.append(_mk(rel, start_line, "sql/grant", rule_id="SQL-GRANT-OPTION",
                               title="Grant can be delegated (WITH GRANT/ADMIN OPTION)", severity="medium",
                               confidence="high", evidence=s[:120],
                               rationale="The grantee can hand its privileges to anyone, defeating reviews of grants.",
                               remediation="Remove WITH GRANT OPTION unless the role administers the schema.",
                               cwe="CWE-269", category="db_overgrant", tags=["privilege"]))
        if re.search(r"^(CREATE|ALTER)\s+(USER|ROLE)\b", up):
            m = re.search(r"(?i)(?:IDENTIFIED\s+BY|PASSWORD)\s+'([^']+)'", s)
            if m and not is_placeholder(m.group(1)):
                out.append(_mk(rel, start_line, "sql/user", rule_id="SQL-USER-PASSWORD-LITERAL",
                               title="Database user password written in the SQL script", severity="high",
                               confidence="high", evidence=(s[:m.start(1)] + redact(m.group(1)) + s[m.end(1):])[:90],
                               rationale="Migration scripts live in git and CI logs; the password is public to the team.",
                               remediation="Create users with a placeholder and set the password out of band, or use "
                                           "IAM / managed authentication.", cwe="CWE-798", category="secret_in_code",
                               tags=["secret", "data-store"]))
            if re.search(r"\b(SUPERUSER|WITH\s+ADMIN|SYSADMIN|ACCOUNTADMIN)\b", up):
                out.append(_mk(rel, start_line, "sql/user", rule_id="SQL-SUPERUSER",
                               title="Script creates or promotes a superuser", severity="high", confidence="high",
                               evidence=s[:120],
                               rationale="Superusers bypass row-level security, grants and audit filters.",
                               remediation="Use a scoped role; keep superuser for break-glass only.", cwe="CWE-250",
                               category="db_overgrant", tags=["privilege", "data-store"]))
    return out


# ---------------------------------------------------------------- Kafka
def analyse_kafka(rel: str, text: str) -> list[Finding]:
    out = []
    props = {}
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        props[k.strip()] = (v.strip(), i)
    if "allow.everyone.if.no.acl.found" in props and props["allow.everyone.if.no.acl.found"][0].lower() == "true":
        v, i = props["allow.everyone.if.no.acl.found"]
        out.append(_mk(rel, i, "kafka/broker", rule_id="KAFKA-ALLOW-EVERYONE",
                       title="Kafka allows every client when no ACL matches", severity="high", confidence="high",
                       evidence="allow.everyone.if.no.acl.found=true",
                       rationale="Any topic without an explicit ACL is readable and writable by anyone who can connect.",
                       remediation="Set it to false and define ACLs per principal.", cwe="CWE-284",
                       category="db_overgrant", tags=["privilege", "data-store"]))
    lst = props.get("listeners") or props.get("advertised.listeners")
    if lst and re.search(r"(?i)\bPLAINTEXT://(?!localhost|127\.0\.0\.1)", lst[0]):
        out.append(_mk(rel, lst[1], "kafka/broker", rule_id="KAFKA-PLAINTEXT-LISTENER",
                       title="Kafka listener is unauthenticated and unencrypted (PLAINTEXT)", severity="high",
                       confidence="high", evidence=f"listeners={lst[0]}",
                       rationale="Records and credentials cross the network in clear and no client is authenticated.",
                       remediation="Use SASL_SSL (or SSL with client certificates) and disable PLAINTEXT.",
                       cwe="CWE-319", category="dataops_plaintext", tags=["network", "data-store"]))
    if "authorizer.class.name" not in props and "allow.everyone.if.no.acl.found" not in props and lst:
        out.append(_mk(rel, lst[1], "kafka/broker", rule_id="KAFKA-NO-AUTHORIZER",
                       title="Kafka broker has no authorizer configured", severity="medium", confidence="medium",
                       evidence="no authorizer.class.name",
                       rationale="Without an authorizer there are no ACLs at all.",
                       remediation="Set authorizer.class.name and ACLs.", cwe="CWE-862", category="db_overgrant",
                       tags=["privilege"]))
    return out


def analyse(files: list[tuple[str, str]], facts) -> list[Finding]:
    out: list[Finding] = []
    for rel, txt in files:
        kind = kind_of(rel.rsplit("/", 1)[-1], txt[:4000])
        if kind == "airflow-config":
            out += analyse_airflow_config(rel, txt)
        elif kind == "airflow-dag":
            out += analyse_airflow_dag(rel, txt)
        elif kind == "dbt-profile":
            out += analyse_dbt_profile(rel, txt)
        elif kind == "sql":
            out += analyse_sql(rel, txt)
        elif kind == "kafka":
            out += analyse_kafka(rel, txt)
    return out
