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
1. **Scope guard:** local files only. Assay refuses URLs, IPs and host:port targets, ignores symlinks that leave the scope, and makes no network calls to targets.
2. **Recon:** inventories and classifies files (Terraform, Kubernetes, Dockerfile, compose, GitHub Actions, dependency manifests, env files).
3. **Plan:** chooses analysers from what recon found, and logs every run/skip decision with its reason.
4. **Analyse:** 55 deterministic rules. Each finding carries evidence (file, line, redacted value), a CWE, a plain-language "why it matters" and a concrete fix.
5. **Correlate:** follows Terraform resource references, Kubernetes service-account bindings and secret fingerprints to build attack chains, each listing the findings it was built from.
6. **Prioritise:** an explained score (severity × confidence, +1 if internet-exposed, +1.5 if part of a chain). The factors are printed next to every score.
7. **Act safely:** proposes mechanical patches as diffs. `assay approve` records who approved which action IDs, bound to a hash of the plan. `assay apply` refuses if there is no approval, if the plan was edited, or if a file changed since the scan.
8. **Report:** Markdown for people, SARIF 2.1.0 for tools, JSON for automation, and a hash-chained audit log of every decision.
9. **Optional local AI briefing:** a local open-weight model (llama.cpp) writes a short manager summary under a JSON schema whose IDs are restricted to real findings. A validator rejects invented numbers, unknown IDs or claims of actions that never happened, and the report says who wrote the text (the model or the template).

## Results (reproducible: `scripts/get-samples.sh && uv run python -m eval.run_eval`)
- **TerraGoat:** 17/17 author-annotated weaknesses detected within Assay's rule coverage (AWS). 17/29 across all clouds: the misses are Alibaba Cloud, Oracle Cloud and Azure, which have no rules yet. The run produced 5 attack chains, including two critical "internet-reachable instance carries plaintext credentials" paths.
- **Kubernetes Goat:** 6/6 statically visible scenarios detected, with 6 container-escape chains.
- **Rule conformance:** 39/39 fixture cases exact, and 14/14 safe look-alike configurations produce no false finding.
- **Safety checks:** 13/13, covering network-target refusal, read-only scan, the approval gate, tamper detection and secret redaction.
- **Tests:** 58 automated tests. A full scan of either sample repo takes about 1–2 seconds on a laptop CPU. The deterministic core needs no GPU and no cloud.

## Limits (stated plainly)
- This is a static review: Assay does not test running systems or prove exploitability.
- Variables and modules are not resolved.
- Cloud coverage is AWS plus basic GCP.
- The fixture suite was written alongside the rules, so it shows behaviour, not independent accuracy.
- The TerraGoat annotations were visible during development, so that test is not blind.

## Built with
Python 3, PyYAML, a dependency-free Terraform parser written for this project, and optionally llama.cpp with Gemma 4 E2B. Built with AI coding assistance (Claude Code), which is disclosed in the README. MIT licence.
