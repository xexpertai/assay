# Assay: project write-up (DataOps Innovation Hackathon 2026)

## One line
Assay is a security assessment agent for infrastructure and pipeline code. It reasons through the stages of an assessment, links separate weaknesses into real attack paths, explains each conclusion, and changes nothing without a named human's approval.

## Problem
Configuration scanners produce long, flat lists. In our TerraGoat run, a single repository gave 65 findings. Teams then have three problems:
- they do not know which findings actually matter;
- they cannot see why a tool reached its verdict;
- they distrust "auto-fix" tools that write into their code.

Meanwhile the most damaging problems are *combinations*: an open SSH port **plus** AWS keys in the same instance's user data, or a privileged pod **plus** a cluster-admin service account.

## What Assay does
1. **Scope guard and policy:** local files only. Assay refuses URLs, IPs and host:port targets, ignores symlinks that leave the scope, and makes no network calls to targets. Its policy is files-only by default; a lab allowlist (named lab, named owner, expiry date, listed hosts or networks) is the only way to bring hosts into scope, and any active step must pass a gate that also demands a named human approval. No scanner runners ship with the library.
2. **Recon:** inventories and classifies files (Terraform, Kubernetes, Dockerfile, compose, GitHub Actions, dependency manifests, env files, and nmap / nuclei / trivy output files read as evidence).
3. **Plan:** an analyser registry (plugins via entry points) chooses analysers from what recon found, and logs every run/skip decision with its reason.
4. **Analyse:** 59 deterministic rules. Each finding carries evidence (file, line, redacted value), a CWE, a plain-language "why it matters", a concrete fix and structured facts. Values that come from expressions lower the confidence instead of being guessed.
5. **Correlate:** follows Terraform resource references (including indexed ones), Kubernetes service-account bindings, secret fingerprints and observed ports from tool output to build attack chains, each listing the findings it was built from. "Open to the world in the configuration and seen open in a scan file" is one chain.
6. **Prioritise:** an explained score (severity × confidence, +1 if internet-exposed, +1.5 if part of a chain). The factors are printed next to every score.
7. **Act safely:** proposes mechanical patches as diffs. `assay approve` records who approved which action IDs, bound to a hash of the plan. `assay apply` refuses if there is no approval, if the plan was edited, or if a file changed since the scan.
8. **Report and explain:** Markdown and a single-file HTML report with chain diagrams for people, SARIF 2.1.0 (schema-validated) for tools, JSON for automation, and an HMAC-keyed, hash-chained audit log of every decision whose key lives outside the run directory. `assay explain RUN ID` shows, for any finding, chain or action, the rule, evidence, score derivation, chain membership, the decision that ran the analyser and the proposed patch.
9. **Optional local AI briefing:** a local open-weight model (llama.cpp) writes a short manager summary under a JSON schema whose IDs are restricted to real findings. A validator rejects invented numbers, unknown IDs or claims of actions that never happened, and the report says who wrote the text (the model or the template).

## Results (reproducible: `scripts/get-samples.sh && uv run python -m eval.run_eval`)
- **Blind sample, sadcloud (NCC Group):** rules frozen before the repository was opened, 84 misconfiguration flags labelled after the first run: 18/23 detected where a rule existed and the value was visible in the code. The five misses were then fixed (indexed references, `data.aws_iam_policy_document` policies, FTP/Telnet ports); the post-fix 23/23 is a regression figure, not a second blind result. 57 of the 84 flags are outside Assay's rules.
- **TerraGoat:** 16/16 author-annotated weaknesses detected within Assay's rule coverage (AWS); one stale annotation is excluded rather than credited. 16/29 across all clouds: the misses are Alibaba Cloud, Oracle Cloud and Azure, which have no rules yet. 5 attack chains, including two critical "internet-reachable instance carries plaintext credentials" paths.
- **Kubernetes Goat:** 6/6 statically visible scenarios detected, with 6 container-escape chains.
- **Rule conformance:** 54/54 fixture cases exact (including expected confidence levels), and 18/18 safe look-alike configurations produce no false finding.
- **Safety checks:** 16/16, covering network-target refusal, read-only scan, the approval gate (including a named approver), in-place tamper detection, detection of a chain regenerated without the run key, key storage outside the run directory, and secret redaction.
- **Tests:** 95 automated tests. A full scan of any sample repo takes under a second on a laptop CPU. The deterministic core needs no GPU and no cloud.

## Limits (stated plainly)
- This is a static review plus ingestion of evidence files: Assay does not run scanners, test running systems or prove exploitability. The observed-vs-configured chain matches by port number and says so.
- Variables and modules are not resolved; expressions lower confidence instead.
- Cloud coverage is AWS plus basic GCP; many AWS services (CloudTrail, password policy, Redshift, queue/topic policies) have no rules.
- The fixture suite was written alongside the rules, so it shows behaviour, not independent accuracy.
- The TerraGoat annotations were visible during development, so that test is not blind. The sadcloud 18/23 figure is the only blind number.

## Built with
Python 3, PyYAML, a dependency-free Terraform parser written for this project, and optionally llama.cpp with Gemma 4 E2B. Built with AI coding assistance (Claude Code), which is disclosed in the README. MIT licence.
