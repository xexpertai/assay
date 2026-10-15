# Assay: an explainable, approval-gated security assessment agent

Assay reviews a repository's infrastructure-as-code, container, CI and dependency files, and reads security-tool output files (nmap, nuclei, trivy) as evidence. It works like a careful human assessor:

1. it maps what is in scope;
2. it decides which checks apply, and logs every run and every skip with a reason;
3. it collects evidence;
4. it **correlates** separate weaknesses into attack paths, including "the configuration says this port is open to the world, and a scan file saw it open";
5. it ranks them with a score you can read and check;
6. it writes a report that a manager and an engineer can both use, and can **explain** any finding, chain or action in one screen.

It **proposes** fixes as patches. It never changes anything until a named person approves specific action IDs, and every step is written to a keyed (HMAC), hash-chained audit log.

It runs fully offline on a laptop. No cloud API and no paid model are needed. An optional local model (any llama.cpp server, for example Gemma 4 E2B on a CPU) can write the plain-language briefing; its text is checked against the facts before it is used.

> **Safety by design.**
> - Assay reads local files only. It refuses URLs, IP addresses and host:port targets, and it never opens a connection to a target. It ships no scanner runners.
> - Its scope policy is `files-only` by default. A `lab-allowlist` policy can be loaded from a lab file that names the lab, its owner, an expiry date and the allowed hosts or networks; evidence about any other host is dropped and the drop is logged. Any future active step must pass `ScopePolicy.authorise_active()`, which refuses unless the policy is a lab allowlist, the host is listed and a named human approval is recorded.
> - It ignores symlinks that point outside the scope.
> - It redacts every secret (a 2-4 character prefix plus the length) and never keeps query strings from tool output.
> - It cannot apply a change without an approval that matches the exact plan and unchanged files.
>
> Use it only on code you own or are licensed to assess, and on evidence gathered inside an authorised lab.

## What it checks (59 rule IDs across 8 analysers)

| Area | Examples |
|---|---|
| Terraform (AWS, plus GCP basics) | public S3 ACLs and policies (inline, `aws_s3_bucket_acl`/`_policy` companions, `data.aws_iam_policy_document`), public access blocks switched off, SSH/RDP/Telnet/VNC, database and plain-text-protocol ports open to `0.0.0.0/0` (inline `ingress`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`), secrets in EC2 user data and Lambda env vars, public or unencrypted databases, wildcard IAM and roles anyone can assume, unencrypted EBS and snapshots, KMS rotation, IMDSv1, public EKS endpoint, open GCP firewalls, public GCS |
| Kubernetes | privileged containers, hostPath (docker.sock, `/`), host namespaces, dangerous capabilities, plain-text secret env values, wildcard RBAC, cluster-admin bindings, missing limits and hardening, unpinned images |
| Dockerfile / compose | root user, unpinned base, `curl \| sh`, secrets in ENV/ARG, secret files copied into a layer, privileged compose services, docker.sock mounts |
| GitHub Actions | `pull_request_target` checking out PR code, script injection from `${{ github.event.issue.title }}` and similar, unpinned third-party actions, `write-all` tokens |
| Dependencies | unpinned requirements, plain-HTTP package index, `*`/`latest` npm versions |
| Secrets (all text files) | AWS keys, private keys, GitHub/Slack/Google tokens, high-entropy credentials assigned to secret-like names |
| Tool output files | nmap XML (open admin/database ports per host), nuclei JSONL (template matches with their severity), trivy JSON (vulnerable packages aggregated per package, failed misconfiguration checks) |

Values that come from variables are not guessed. When a security-relevant value is an expression (`var.x ? false : true`, `!var.x`, a `dynamic` block), the finding is reported at **medium** confidence with the expression shown; when it is a bare variable deciding public exposure, a low-confidence "depends on a variable" finding says so.

## How the agent works

```
scope guard + policy ─► recon (inventory + file classification)
           ─► plan (analyser registry: every run and skip logged with a reason; plugins via entry points)
           ─► analyse (rules → findings with evidence, CWE, rationale, remediation, structured facts)
           ─► correlate (Terraform references, k8s service-account bindings, secret fingerprints,
                         observed ports from tool output vs configured exposure)
           ─► prioritise (score = severity × confidence, +1 internet-exposed, +1.5 part of a chain; factors shown)
           ─► propose actions (mechanical Terraform patches as diffs; nothing applied)
           ─► report (Markdown, HTML with chain diagrams, JSON, SARIF 2.1.0) + keyed audit log
human ─► assay explain RUN C-xxxx  ─► assay approve RUN A-01 --by "Name"  ─► assay apply RUN  ─► assay verify-log RUN
```

Examples of chains from the evaluation runs:

- **Internet-reachable `aws_instance.web_host` carries plaintext credentials** (critical): a security group opens SSH to the world, and the instance's user data contains AWS keys.
- **Configured exposure on `aws_security_group.bastion` is confirmed by observation and the host holds credentials** (critical): the configuration opens 22 to the world, an nmap file saw 22/ssh open on the lab host, and the instance's user data holds AWS keys. The narrative says the match is by port number, so a person confirms the host belongs to that resource.
- **`Deployment/system-monitor-deployment` combines several container-escape weaknesses** (critical): privileged, mounts the host's `/`, shares a host namespace.
- A workload with an escape weakness whose service account is bound to `cluster-admin` becomes **"compromising this one pod compromises the whole cluster"**.

## Quick start

```bash
uv sync                                    # Python 3.11+, one runtime dependency (PyYAML)
uv run assay scan path/to/your/repo --out runs/myrepo
open runs/myrepo/report.html               # also report.md, findings.json, report.sarif, plan.json, audit.jsonl
uv run assay explain runs/myrepo C-1a2b3c4d          # or F-… (finding) or A-01 (action)
uv run assay approve runs/myrepo A-01 --by "Your Name"
uv run assay apply runs/myrepo             # applies only A-01; refuses if anything changed since the scan
uv run assay verify-log runs/myrepo        # hash chain + HMAC under the per-run key in ~/.config/assay/keys
uv run assay scan lab-repo --lab lab.json  # lab allowlist: see docs/lab.example.json
uv run assay scan path/to/repo --llm --llm-url http://127.0.0.1:8080   # optional local-model briefing
scripts/demo.sh                            # refusal → scan → explain → approve → apply → verify-log, ~2 s
```

Writing an analyser plugin: implement `name`, `kinds` and `analyse(files, facts)` (see `assay/plugins.py`) and register it under the `assay.analysers` entry-point group. The plan lists it with its origin.

## Evaluation (numbers come from `eval/run_eval.py`; outputs are in `eval/results/`)

```bash
scripts/get-samples.sh            # public, intentionally vulnerable repos, pinned commits
uv run python -m eval.run_eval    # writes eval/results/*.json and SUMMARY.md
uv run pytest -q                  # 95 tests
```

| Test set | Result |
|---|---|
| **sadcloud, blind** (NCC Group, Apache-2.0, commit `f538652`): 84 misconfiguration flags, labelled *after* the first run; the rules were frozen before the repository was opened (git tag `rules-frozen-for-blind-sample`). | **18/23** flags detected where Assay had a rule and the value was visible in the code (`eval/results/sadcloud_blind_frozen.json`). Misses: an indexed reference (`[0].id`), two `data.aws_iam_policy_document` policies, FTP/Telnet ports. 57 of the 84 flags need rules Assay does not have (CloudTrail, password policy, Redshift, SQS/SNS/SES policies, and so on). |
| **sadcloud after the post-blind fixes** (no longer blind) | 23/23 in coverage; 3/4 bare-variable values now reported as "depends on a variable". 61 findings, 3 chains. |
| **TerraGoat** (Bridgecrew, Apache-2.0, commit `729f8da`): weaknesses its authors annotated with comments. Assay strips comments before analysis. | **16/16** detected for the clouds Assay covers (AWS); one "bucket is public" annotation is stale at that commit (no ACL or policy in the code) and is excluded rather than credited. 16/29 over all clouds: the misses are Alibaba Cloud, Oracle Cloud and Azure resources, which have no rules. 65 findings, 5 chains, 14 proposed patches, under a second. |
| **Kubernetes Goat** (MIT, commit `723a0db`): scenarios whose weakness is visible statically | **6/6** detected. 112 findings, 6 chains. |
| **Rule conformance suite** (`eval/fixtures/`, 54 cases: 36 vulnerable, 18 safe look-alikes, including provider-v4 Terraform, conditional values, indexed references and tool-output files) | 54/54 exact, including expected confidence levels; 18/18 safe cases produce no false finding. |
| **Safety checks** | 16/16: refusing 4 kinds of network target; a scan changes no files; apply refused without approval, after a plan edit, and without a named approver; only approved actions applied; a patch removes its finding on re-scan; the audit chain verifies; an in-place edit is detected; a chain regenerated without the run key is detected (HMAC); the key is stored outside the run directory; no output contains a full secret. |

**Read these numbers honestly:**
- The sadcloud blind number (18/23) is the one independent figure. Everything that followed it was tuned with sadcloud visible, so 23/23 is a regression test, not a second blind result. The flag-to-rule mapping (`eval/sadcloud_labels.json`) was written by the builder after reading each module; it states for every flag whether the value is literal, conditional, a bare variable or outside Assay's rules.
- The fixture suite was written by the builder alongside the rules. It shows the rules behave as designed; it is not an independent accuracy benchmark.
- The TerraGoat annotations were visible while the rules were written, so that test is not blind. Assay reported 32 AWS findings beyond the annotations; they are listed in `eval/results/terragoat.json` and are not counted as true or false positives. A spot check found each literally true.
- The Kubernetes Goat scenario-to-rule mapping was written by the builder.
- Precision on real repositories is not measured. A probe on a well-configured module (encrypted RDS, `var.db_password`, 443-only group, Deny-wildcard IAM, pbkdf2 hash) produced no false finding, but that is one probe.

## Limitations
- Static configuration review plus ingestion of evidence files. Assay does not run scanners, does not test running systems and does not prove exploitability. The "confirmed by observation" chain matches by port number; it does not know which host a Terraform resource became.
- Terraform variables and modules are not resolved; expressions lower confidence rather than being evaluated.
- Cloud coverage is AWS plus a few GCP checks. Azure, Alibaba Cloud and Oracle Cloud are not covered. CloudTrail, IAM password policy, Redshift, SQS/SNS/SES/KMS/ECR resource policies and ELBv2 have no rules yet.
- Helm templates (files containing `{{`) are skipped; render them first.
- The optional model briefing is validated for IDs, numbers and invented actions, but not for every paraphrase: in the TerraGoat run Gemma 4 E2B called `aws_instance.db_app` a "database" (`eval/results/llm_briefing.json`). The deterministic template is the default, and the report always names the author of the briefing. Each model briefing took about 36 s on a busy laptop CPU.
- Dependency checks cover pinning hygiene only; trivy output supplies vulnerability data when present. No vulnerability database lookup (offline by design).
- nmap XML is parsed with the standard library parser; only feed it files you produced or trust.

## Project layout
`assay/` contains the agent:
- `scope.py` (scope guard, `ScopePolicy`), `inventory.py`, `hcl.py` (dependency-free Terraform parser), `plugins.py` (analyser registry), `rules/` (`terraform.py`, `kubernetes.py`, `misc.py`, `secrets.py`, `toolout.py`);
- `correlate.py`, `actions.py` (approval gate, keyed audit log), `explain.py`, `narrate.py` (optional local model, grounded), `report.py`, `html.py`, `agent.py`, `cli.py`.

`eval/` holds the fixtures, labels and runner. `tests/` holds the unit, safety and policy tests. `templates/event-repo/` is the provenance-first skeleton for a project that depends on Assay. `docs/` has the write-up, the video storyboard and a lab-file example.

## Disclosure
- **AI assistance:** this project was built with AI coding assistance (Claude Code). All rules, numbers and claims were checked by running the code; the evaluation outputs are committed.
- **Timeline:** this library was written before the DataOps Innovation Hackathon's problem statement was released (31 Oct 2026); the git history and tags are dated. Any work for the event's specific problem is a separate repository that depends on a tagged release of this one, with a provenance table.
- **Third-party material:** sample repositories are downloaded at evaluation time and are not included here: TerraGoat © Bridgecrew, Apache-2.0; Kubernetes Goat © Madhu Akula, MIT; sadcloud © NCC Group, Apache-2.0. `tests/data/sarif-2.1.0.json` is the OASIS SARIF 2.1.0 JSON schema (used only by the test suite). The fake credentials in `eval/fixtures/` are AWS's published documentation examples or random strings; lab addresses are private-range placeholders.

## Licence
MIT © 2026 Harsha Shinde
