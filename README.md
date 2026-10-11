# Assay: an explainable, approval-gated security assessment agent

Assay reviews a repository's infrastructure-as-code, container, CI and dependency files. It works like a careful human assessor:

1. it maps what is in scope;
2. it decides which checks apply;
3. it collects evidence;
4. it **correlates** separate weaknesses into attack paths;
5. it ranks them with a score you can read and check;
6. it writes a report that a manager and an engineer can both use.

It **proposes** fixes as patches. It never changes anything until a named person approves specific action IDs, and every step is written to a tamper-evident audit log.

It runs fully offline on a laptop. No cloud API and no paid model are needed. An optional local model (any llama.cpp server, for example Gemma 4 E2B on a CPU) can write the plain-language briefing. Its text is checked against the facts before it is used.

> **Safety by design.**
> - Assay reads local files only. It refuses URLs, IP addresses and host:port targets, and it never opens a connection to a target.
> - It ignores symlinks that point outside the scope.
> - It redacts every secret (first 4 characters plus the length).
> - It cannot apply a change without an approval that matches the exact plan and unchanged files.
>
> Use it only on code you own or are licensed to assess.

## What it checks (55 rule IDs across 6 analysers)

| Area | Examples |
|---|---|
| Terraform (AWS, plus GCP basics) | public S3 ACLs and missing public-access blocks, SSH/RDP/database ports open to `0.0.0.0/0`, secrets in EC2 user data and Lambda env vars (including `${var.password}` rendered into user data), public or unencrypted databases, wildcard IAM, unencrypted EBS and snapshots, KMS rotation, IMDSv1, public EKS endpoint, open GCP firewalls, public GCS |
| Kubernetes | privileged containers, hostPath (docker.sock, `/`), host namespaces, dangerous capabilities, plain-text secret env values, wildcard RBAC, cluster-admin bindings, missing limits and hardening, unpinned images |
| Dockerfile / compose | root user, unpinned base, `curl \| sh`, secrets in ENV/ARG, secret files copied into a layer (even if deleted later), privileged compose services, docker.sock mounts |
| GitHub Actions | `pull_request_target` checking out PR code, script injection from `${{ github.event.issue.title }}` and similar, unpinned third-party actions, `write-all` tokens |
| Dependencies | unpinned requirements, plain-HTTP package index, `*`/`latest` npm versions |
| Secrets (all text files) | AWS keys, private keys, GitHub/Slack/Google tokens, high-entropy credentials assigned to secret-like names |

## How the agent works

```
scope guard ─► recon (inventory + file classification)
           ─► plan (choose analysers from what recon found; every choice logged with a reason)
           ─► analyse (rules → findings with evidence, CWE, rationale, remediation)
           ─► correlate (follow Terraform references, k8s service-account bindings, secret fingerprints)
           ─► prioritise (score = severity × confidence, +1 internet-exposed, +1.5 part of a chain; factors shown)
           ─► propose actions (mechanical Terraform patches as diffs; nothing applied)
           ─► report (Markdown, JSON, SARIF 2.1.0) + hash-chained audit log
human ─► assay approve RUN A-01 ...  ─► assay apply RUN  (refuses if the plan or files changed)
```

The correlation step is what turns a list of findings into an assessment. Examples taken from the evaluation runs below:

- **Internet-reachable `aws_instance.web_host` carries plaintext credentials** (critical): a security group opens SSH to the world, and the instance's user data contains AWS keys.
- **SSRF on internet-facing `aws_instance.db_app` could steal its role credentials** (high): the instance is internet-facing and IMDSv1 is still allowed.
- **`Deployment/system-monitor-deployment` combines several container-escape weaknesses** (critical): it is privileged, mounts the host's `/` and shares a host namespace.
- A workload with an escape weakness whose service account is bound to `cluster-admin` becomes **"compromising this one pod compromises the whole cluster"** (tested in `tests/test_agent_safety.py`).

## Quick start

```bash
uv sync                                    # Python 3.11+, one dependency (PyYAML)
uv run assay scan path/to/your/repo --out runs/myrepo
less runs/myrepo/report.md                 # also findings.json, report.sarif, plan.json, audit.jsonl
uv run assay approve runs/myrepo A-01 --by "your name"
uv run assay apply runs/myrepo             # applies only A-01, refuses if anything changed since the scan
uv run assay verify-log runs/myrepo        # checks the audit hash chain
# optional: local-model briefing (any llama.cpp llama-server)
uv run assay scan path/to/repo --llm --llm-url http://127.0.0.1:8080
```

## Evaluation (numbers come from `eval/run_eval.py`; outputs are in `eval/results/`)

```bash
scripts/get-samples.sh            # public, intentionally vulnerable repos, pinned commits
uv run python -m eval.run_eval    # writes eval/results/*.json and SUMMARY.md
uv run pytest -q                  # 58 tests
```

| Test set | Result |
|---|---|
| **TerraGoat** (Bridgecrew, Apache-2.0, commit `729f8da`): weaknesses its authors annotated with comments. Assay strips comments before analysis. | **17/17** detected for the clouds Assay covers (AWS). 17/29 over all clouds: the 12 misses are Alibaba Cloud, Oracle Cloud and Azure resources, which have no rules yet. 65 findings, 5 attack chains, 14 proposed patches, about 1–2 s. |
| **Kubernetes Goat** (MIT, commit `723a0db`): scenarios whose weakness is visible statically | **6/6** detected (DIND, container escape, resource DoS, RBAC misconfiguration, hidden in layers, Helm tiller pwnchart). 110 findings, 6 chains. |
| **Rule conformance suite** (`eval/fixtures/`, 39 cases: 25 vulnerable, 14 safe look-alikes) | 39/39 exact; 14/14 safe cases produce no false finding. |
| **Safety checks** | 13/13. They cover: refusing 4 kinds of network target; a scan changes no files; apply is refused without approval and refused after the plan is edited; only approved actions are applied; a patch removes its finding on re-scan; the audit chain verifies and tampering is detected; no output contains a full secret. |

**Read these numbers honestly:**
- The fixture suite was written by the builder alongside the rules. It shows the rules behave as designed; it is not an independent accuracy benchmark. While it was being built it found 2 real bugs: a false positive on `http_tokens = "required"`, and an invalid-YAML fixture. Both were fixed.
- The TerraGoat annotations were visible while the rules were written, so this is not a blind test. Every rule is a generic best-practice check (no resource names or file paths are hard-coded).
- Assay reported 31 AWS findings beyond TerraGoat's annotations. They are listed in `eval/results/terragoat.json` and are **not** counted as true or false positives. A spot check against the configuration found each of them literally true, for example the 9 `aws_rds_cluster` resources without `storage_encrypted`. Some are judgment calls, such as access logging on the log bucket itself.
- The Kubernetes Goat scenario-to-rule mapping (`eval/k8sgoat_scenarios.json`) was written by the builder.

## Limitations
- This is a static configuration review. It does not find vulnerabilities in application code or verify exploitability.
- Terraform values that come from variables or modules are not resolved.
- Cloud coverage is AWS plus a few GCP checks. Azure, Alibaba Cloud and Oracle Cloud are not covered yet.
- Helm templates (files containing `{{`) are skipped; render them first.
- The optional model briefing is validated for IDs, numbers and invented actions, but not for every paraphrase: in our TerraGoat run Gemma 4 E2B called the instance `aws_instance.db_app` a "database" (`eval/results/llm_briefing.json`). The deterministic template is the default, and the report always names the author of the briefing. Each model briefing took about 36 s on a busy laptop CPU.
- Dependency checks cover pinning hygiene only. There is no vulnerability database lookup (offline by design).

## Project layout
`assay/` contains the agent:
- `scope.py`, `inventory.py`, `hcl.py` (dependency-free Terraform parser), `rules/`;
- `correlate.py`, `actions.py` (approval gate and audit log), `narrate.py` (optional local model, grounded), `report.py`, `agent.py`, `cli.py`.

`eval/` holds the fixtures, labels and runner. `tests/` holds the unit and safety tests.

## Disclosure
- **AI assistance:** this project was built with AI coding assistance (Claude Code). All rules, numbers and claims were checked by running the code; the evaluation outputs are committed.
- **Timeline:** this core was written before the DataOps Innovation Hackathon's problem statement was released (31 Oct 2026), and the git history shows its dates. Any work for the event's specific problem statement is added on top in clearly separate commits.
- **Third-party material:** sample repositories are downloaded at evaluation time and are not included here: TerraGoat © Bridgecrew, Apache-2.0; Kubernetes Goat © Madhu Akula, MIT. The fake credentials in `eval/fixtures/` are AWS's published documentation examples or random strings.

## Licence
MIT © 2026 Harsha Shinde
