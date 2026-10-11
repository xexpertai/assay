# Demo video script (about 2:30; produce only if the official format asks for a video)

The voice-over uses a synthetic voice (Kokoro). The screen shows a terminal and the Markdown report only, with no third-party logos. Every number on screen comes from a real run. Sample repositories are named with their licence.

| Time | Screen | Voice-over |
|---|---|---|
| 0:00–0:15 | Title card: "Assay: a security assessment agent that explains itself and asks before it acts" | "Security scanners give you a long list. Assay gives you an assessment: what matters, why, and what to do. It changes nothing until a person approves." |
| 0:15–0:35 | `assay scan https://example.com` gives the refusal message | "First, safety. Assay only reviews local files you own or are licensed to test. Give it a URL or an IP address and it refuses, before any work starts." |
| 0:35–1:05 | `assay scan samples/terragoat` output, then the report's "Agent decisions" table | "Here it assesses TerraGoat, an intentionally vulnerable open-source project. It takes an inventory of the files, decides which checks apply, and logs every decision with a reason." |
| 1:05–1:40 | The report's "Attack chains" section; highlight the critical web_host chain and its 'Built from' IDs | "Then it links findings together. An SSH port open to the internet, plus AWS keys in the same instance's start-up script, becomes one critical attack path. Each chain lists the findings it was built from, so you can check every step." |
| 1:40–2:00 | The findings table with scores; one finding's details, including the score factors | "Every score is explained: severity, confidence, internet exposure, and whether the finding is part of a chain. Secrets are always redacted." |
| 2:00–2:20 | `assay apply` refused, then `assay approve ... A-01`, `assay apply`, `assay verify-log` | "Fixes are proposed as diffs. Applying without approval is refused. A named person approves one action, only that action is applied, and the audit log proves the order of events." |
| 2:20–2:30 | The `eval/results/SUMMARY.md` numbers | "On TerraGoat it found all 17 annotated weaknesses in the clouds it covers, and all 6 static Kubernetes Goat scenarios. All 13 safety checks pass. Open source, MIT licence." |

QA before showing the video: check frames every 2 s at 1000 px or wider, loudness of −14 LUFS, true peak of −1 dBTP or lower, and no silence longer than 0.6 s.
