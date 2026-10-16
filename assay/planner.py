"""Optional LLM planner (local llama.cpp server only, $0): the model orders the analysers and proposes follow-up
active steps. It decides; the kernel disposes.

What the model can and cannot do:
- It sees the inventory counts and the analyser list with the deterministic plan's run/skip verdicts.
- Its output is constrained by a JSON schema whose enums are the real analyser names, the declared tool profiles
  and the permitted hosts, and it is validated again afterwards. Anything invalid -> the deterministic plan is
  used and the rejection is logged.
- It can reorder analysers and give a reason for each. It can NOT enable an analyser the deterministic plan
  skipped, drop one that has files, or move the secret scan from last place (it relies on the others' results).
  Reordering does not change which findings exist; what it adds is a logged, explained plan.
- After the analysis it may PROPOSE up to 3 active steps, only with a declared profile and only for hosts the lab
  allowlist permits. A proposal is written with `plan_step` (nothing runs); a named human still has to run
  `assay step approve`, and the approval is bound to the exact command.
Every model call is recorded in the audit log with the sha256 of the prompt and of the raw answer.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request

from .models import Decision
from .narrate import NUM_RE, _post
from .plugins import ALL_TEXT
from .runners import PROFILES

SYSTEM = (
    "You are the planning step of a security assessment agent. You get JSON: the file kinds found in scope and the "
    "analysers available, each with the verdict of the deterministic plan (run or skip).\n"
    "Rules:\n"
    "- order: list the analysers you want to run, most valuable first, using only names from the list that have "
    "verdict run. Put analysers whose file kinds suggest the highest-impact weaknesses first.\n"
    "- reasons: one short reason per analyser in your order, using only facts from the input (file counts, kinds).\n"
    "- Never invent file names, numbers or findings. You are planning, not reporting results."
)
STEP_SYSTEM = (
    "You are the follow-up step of a security assessment agent. You get JSON: finding counts, hosts the lab "
    "allowlist permits (with open ports seen in evidence files, if any) and the tool profiles you may propose. "
    "Propose 0 to 3 active steps that would add evidence for the most serious findings. Use only listed hosts and "
    "tools. Each needs a short reason from the input. A human must approve every step; you cannot run anything."
)


def _sha(x: str) -> str:
    return hashlib.sha256(x.encode()).hexdigest()


def _ask(url: str, system: str, facts: dict, schema: dict, timeout: float, n_predict: int = 400) -> tuple[dict, dict]:
    user = json.dumps(facts, separators=(",", ":"), sort_keys=True)
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    prompt = _post(url, "/apply-template", {"messages": msgs, "chat_template_kwargs": {"enable_thinking": False}}, 30)["prompt"]
    t = time.perf_counter()
    d = _post(url, "/completion", {"prompt": prompt, "json_schema": schema, "n_predict": n_predict,
                                   "temperature": 0.1, "cache_prompt": True}, timeout)
    raw = d.get("content", "")
    return json.loads(raw), {"prompt_sha256": _sha(prompt), "output_sha256": _sha(raw),
                             "wall_s": round(time.perf_counter() - t, 1)}


def _url(url: str | None) -> str:
    return (url or os.environ.get("ASSAY_LLM_URL", "http://127.0.0.1:8088")).rstrip("/")


def _timeout() -> float:
    return float(os.environ.get("ASSAY_LLM_TIMEOUT", "600"))


def _numbers_ok(text: str, facts: dict) -> list[str]:
    allowed = set(NUM_RE.findall(json.dumps(facts)))
    return [f"number {n} not in facts" for n in NUM_RE.findall(text) if n not in allowed]


def order_analysers(analysers, entries, kinds, url, log, decisions):
    """Return (analysers, entries) reordered by the model, or unchanged with the reason logged."""
    runnable = [e.analyser for e in entries if e.run]
    if not url or len(runnable) < 2:
        return analysers, entries
    facts = {"kinds": dict(kinds), "analysers": [{"name": e.analyser, "verdict": "run" if e.run else "skip",
                                                    "files": e.files, "why": e.reason} for e in entries]}
    schema = {"type": "object", "required": ["order", "reasons"], "properties": {
        "order": {"type": "array", "minItems": 1, "maxItems": len(runnable), "items": {"type": "string", "enum": runnable}},
        "reasons": {"type": "array", "minItems": 1, "maxItems": len(runnable), "items": {
            "type": "object", "required": ["analyser", "why"], "properties": {
                "analyser": {"type": "string", "enum": runnable}, "why": {"type": "string", "minLength": 5, "maxLength": 160}}}}}}
    url = _url(url)
    try:
        out, meta = _ask(url, SYSTEM, facts, schema, _timeout())
    except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError, KeyError, OSError) as e:
        why = f"model unavailable or invalid output ({type(e).__name__}); deterministic plan used"
        decisions.append(Decision("plan", "llm planner not used", why))
        if log:
            log.write("plan", "llm_plan_rejected", reason=why)
        return analysers, entries
    problems = []
    order = out.get("order", [])
    if not order:
        problems.append("empty order")
    if len(set(order)) != len(order):
        problems.append("duplicate analyser in order")
    reasons = {r["analyser"]: r["why"] for r in out.get("reasons", [])}
    problems += _numbers_ok(" ".join(reasons.values()), facts)
    if problems:
        why = "; ".join(problems) + "; deterministic plan used"
        decisions.append(Decision("plan", "llm plan rejected", why))
        if log:
            log.write("plan", "llm_plan_rejected", reason=why, **meta)
        return analysers, entries
    # the model's order first, then anything it left out in the original order; the secret scan stays last
    by_name = {e.analyser: (a, e) for a, e in zip(analysers, entries)}
    names = [n for n in order if n in by_name] + [e.analyser for e in entries if e.analyser not in order]
    last = [n for n in names if ALL_TEXT in by_name[n][0].kinds]
    names = [n for n in names if n not in last] + last
    decisions.append(Decision("plan", "llm planner chose the analyser order", " > ".join(names)))
    for n in names:
        if n in reasons:
            decisions.append(Decision("plan", f"llm: {n}", reasons[n]))
    if log:
        log.write("plan", "llm_plan_accepted", order=names, reasons=reasons, **meta)
    return [by_name[n][0] for n in names], [by_name[n][1] for n in names]


def propose_steps(policy, observed, findings, out_dir, scope_root, url, log, decisions) -> list[dict]:
    """Ask the model for follow-up active steps; write each valid one as a PLANNED step (nothing runs)."""
    if not url:
        return []
    if policy.mode != "lab-allowlist" or not out_dir:
        decisions.append(Decision("act", "llm step proposals skipped",
                                  "no lab allowlist (policy files-only): no host can be targeted"))
        return []
    from .steps import StepError, plan_step
    hosts = {h: sorted(observed.get(h, {})) for h in sorted(set(policy.hosts) | set(observed))
             if policy.permits_host(h)[0]}
    if not hosts:
        decisions.append(Decision("act", "llm step proposals skipped", "the allowlist names no concrete host and no "
                                  "evidence file names one"))
        return []
    sev: dict[str, int] = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    facts = {"findings_by_severity": sev, "permitted_hosts": [{"host": h, "open_ports_seen": p} for h, p in hosts.items()],
             "tools": sorted(PROFILES)}
    schema = {"type": "object", "required": ["steps"], "properties": {"steps": {
        "type": "array", "maxItems": 3, "items": {"type": "object", "required": ["tool", "host", "why"], "properties": {
            "tool": {"type": "string", "enum": sorted(PROFILES)}, "host": {"type": "string", "enum": sorted(hosts)},
            "why": {"type": "string", "minLength": 5, "maxLength": 160}}}}}}
    try:
        out, meta = _ask(_url(url), STEP_SYSTEM, facts, schema, _timeout(), 300)
    except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError, KeyError, OSError) as e:
        decisions.append(Decision("act", "llm step proposals not used", f"model unavailable or invalid ({type(e).__name__})"))
        return []
    made = []
    seen = set()
    for s in out.get("steps", [])[:3]:
        why_bad = _numbers_ok(s.get("why", ""), facts)
        if s.get("tool") not in PROFILES or s.get("host") not in hosts or (s["tool"], s["host"]) in seen or why_bad:
            decisions.append(Decision("act", f"llm proposal rejected: {s.get('tool')} on {s.get('host')}",
                                      "; ".join(why_bad) or "unknown tool or host, or a duplicate"))
            continue
        seen.add((s["tool"], s["host"]))
        try:
            st = plan_step(out_dir, scope_root, policy.source, s["tool"], s["host"], requested_by="llm-planner")
        except StepError as e:
            decisions.append(Decision("act", f"llm proposal refused by the gate: {s['tool']} on {s['host']}", str(e)))
            continue
        made.append({"step_id": st["step_id"], "tool": s["tool"], "host": s["host"], "why": s["why"]})
        decisions.append(Decision("act", f"llm proposed step {st['step_id']}: {s['tool']} on {s['host']}",
                                  f"{s['why']} (planned only; needs `assay step approve` by a named person)"))
    if log:
        log.write("act", "llm_steps_proposed", steps=made, **meta)
    return made
