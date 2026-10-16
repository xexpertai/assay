# Event playbook: bending Assay to an unknown problem statement in five days

Assay is a kernel: **scope/policy gate → recon → plan (analyser registry) → analyse (plugins) → correlate → prioritise → propose → approval-gated act → explain / report / audit.** During the event the kernel does not change; only inputs, rules, runners and the report skin do. The event solution lives in a **new repository** that depends on a tagged `assay` release (see `templates/event-repo/`).

## Hour 0–2: map the statement
Fill `templates/event-repo/STATEMENT-MAP.md`: every requirement → exists (file) / build / out of scope; GO/NO-GO; the smallest end-to-end path for day 1; the list of active steps, each needing the lab allowlist and a named approval.

## Extension points (in order of effort)
| Need | Mechanism | Where |
|---|---|---|
| New input format (log export, config format, tool output) | an `Analyser` plugin: `name`, `kinds`, `analyse(files, facts)`; classify the file in `inventory.classify` or a `kind_of()` sniffer | `assay/plugins.py`, `assay/rules/toolout.py`, `assay/rules/events.py` (generic JSON/JSONL/CSV event mapping with `FIELD_ALIASES` or an explicit `mapping`) |
| New rules | a function returning `Finding`s with evidence, rationale, remediation, CWE, `category`, `tags`, `meta` | any `assay/rules/*.py` |
| New cross-source reasoning | add a numbered block in `correlate()` that reads `Facts` (`tf_refs`, `k8s_sa`, `observed`, `actors`, …) and emits a `Chain` listing its member finding IDs | `assay/correlate.py` |
| Active step against a lab host | a `PROFILES` entry (fixed argv, `{host}`/`{out}` only) run through `DryRunRunner` first, then `CommandRunner`; output lands in `evidence/` and is ingested by the normal file analysers | `assay/runners.py` |
| Hosts in scope | `lab.json` (name, authorised_by, expires, hosts/networks) → `--lab` | `assay/scope.py` |
| LLM as planner or narrator | `narrate.py` pattern: JSON schema with enums bound to real IDs, validator rejects invented numbers/IDs/actions, template fallback, author named in the report | `assay/narrate.py` |
| Required output format | a new `to_<format>()` next to `report.py`/`html.py`; keep `findings.json` as the source of truth | `assay/report.py` |
| Pipeline / repeat runs | `--baseline` + `--fail-on` | `assay/baseline.py` |

## Theme sketches (what exists, what to build first)
- **Lab recon and assessment:** lab.json → `assay step plan` / `approve` / `run` (see `scripts/demo-lab.sh`; approval is bound to the exact command and logged) → `CommandRunner` profiles for the allowed tools → evidence files → `NMAP-*`/`NUCLEI-*` findings → confirmed-exposure chains → `explain`. Build first: profiles and the lab file; never a host outside the allowlist.
- **Cloud / IaC posture:** existing 87 rules; build first: whatever resource types the statement names (reuse `_principal_any`, `_unsure`, companions).
- **Log / event analysis:** `events.py` with a `mapping` for the given schema; build first: the mapping and the one or two rules the statement stresses; actor chains and the log-actor to IAM match already exist in `correlate_events.py`; extend `STAGE` for new categories.
- **DataOps pipeline configs (Airflow, dbt, Kafka, SQL grants):** new analyser kind + rules (connections with passwords, `GRANT ALL`, public topics, unmasked PII); the secrets scan already covers any text.
- **Kubernetes lab export:** `kubectl get -o yaml` is `kind: List`, already ingested; build first: runtime facts if provided.
- **Agentic assistant required:** LLM chooses analysers/runners from the registry; every choice is a logged decision, every action still goes through the approval gate.

## Rules of the week
No spend. Lab allowlist only. Every active step dry-run first, then approved by name, then logged. Demo data labelled. No invented numbers. Commit at least hourly with real messages; `EVENT-LOG.md` written as work happens; `scripts/provenance.sh` output committed before submission.
