# <Event project name> (DataOps Innovation Hackathon 2026, 2–7 Nov)

> Template. Copy this folder to the new, empty event repository at 14:00 IST on 2 Nov, replace every `<…>`, and keep the provenance table truthful. Delete this note.

**Team:** Harsha Shinde (solo). **Problem statement:** <paste the official title; link>.

## Provenance (what existed before the event, what was built during it)

| Component | Origin | Public since | Licence | What it does |
|---|---|---|---|---|
| `assay` <version> | pre-existing library, <https://github.com/xexpertai/assay>, tag `v<version>` | <date> | MIT | explainable, approval-gated assessment core: scope guard, analysers, correlation, scoring, audit log |
| everything in this repository | built during the event, 2 Nov 14:00 – 7 Nov 23:59 IST | — | MIT | <problem-specific agent, lab runners, report format> |

`scripts/provenance.sh` prints, for every source file, whether it comes from the `assay` dependency (with its tag and date) or from this repository (with its first-commit date). Its output is committed as `PROVENANCE.txt` before submission.

## Disclosure
- Built with AI coding assistance (Claude Code). Every rule, number and claim was checked by running the code; evaluation outputs are committed.
- All security testing ran only inside the organiser's designated lab, under `assay`'s lab-allowlist policy (`lab.json`, authorised by <name>, expires <date>), with a named human approval recorded before every active step.
- Demo data is labelled Replay, Live or Template. No numbers are invented.

## Run
```bash
uv sync
uv run <entrypoint> --lab lab.json <target>
```

## Event log
See `EVENT-LOG.md` (timestamped, written as the work happened).
