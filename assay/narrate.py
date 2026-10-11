"""Optional plain-language briefing written by a local model, with strict grounding checks.

The model (any llama.cpp `llama-server`, e.g. Gemma 4 E2B on a laptop CPU) only sees the
top findings and chains as JSON. Its output is constrained by a JSON schema whose enums
are the real finding and chain IDs, and then validated again: every number it writes must
appear in the facts. If the model is unavailable or fails validation, a deterministic
template is used instead, and the report always says which one wrote the text.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

from .models import Chain, Finding

SYSTEM = (
    "You are a security assessment assistant writing for an engineering manager. You get JSON facts: counts, the "
    "highest-priority findings and the attack chains found by deterministic rules. Write a short briefing.\n"
    "Rules:\n"
    "- Use only the facts. Never invent resources, numbers, CVEs, companies or attacks not in the facts.\n"
    "- summary: 2-3 plain sentences: overall risk and the most serious path. No marketing words.\n"
    "- first_steps: the 3 most valuable fixes, each with the finding_id it addresses and one short reason.\n"
    "- Do not claim anything was fixed, exploited or tested; this is a static configuration review."
)

NUM_RE = re.compile(r"\b\d+(?:\.\d+)?\b")


def facts_for(findings: list[Finding], chains: list[Chain], counts: dict) -> dict:
    top = [f for f in findings if f.severity != "info"][:5]
    return {
        "counts": counts,
        "chains": [{"id": c.id, "title": c.title, "severity": c.severity} for c in chains[:3]],
        "top_findings": [{"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource,
                          "score": f.score} for f in top],
    }


def schema_for(facts: dict) -> dict:
    ids = [f["id"] for f in facts["top_findings"]] or ["none"]
    return {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "minLength": 20, "maxLength": 600},
            "first_steps": {
                "type": "array", "minItems": 1, "maxItems": 3,
                "items": {"type": "object", "properties": {
                    "finding_id": {"type": "string", "enum": ids},
                    "why": {"type": "string", "minLength": 5, "maxLength": 200}},
                    "required": ["finding_id", "why"]},
            },
        },
        "required": ["summary", "first_steps"],
    }


def validate(out: dict, facts: dict) -> list[str]:
    problems = []
    ids = {f["id"] for f in facts["top_findings"]}
    allowed_nums = set(NUM_RE.findall(json.dumps(facts)))
    text = out.get("summary", "") + " " + " ".join(s.get("why", "") for s in out.get("first_steps", []))
    for n in NUM_RE.findall(text):
        if n not in allowed_nums:
            problems.append(f"number {n} not in facts")
    for s in out.get("first_steps", []):
        if s.get("finding_id") not in ids:
            problems.append(f"unknown finding id {s.get('finding_id')}")
    if re.search(r"(?i)\b(fixed|exploited|we tested|penetrat)", text):
        problems.append("claims an action that did not happen")
    return problems


def template(facts: dict) -> dict:
    c = facts["counts"]
    sev = ", ".join(f"{c['by_severity'][s]} {s}" for s in ("critical", "high", "medium", "low")
                    if c["by_severity"].get(s))
    parts = [f"The review found {c['findings']} issues ({sev or 'none above info'}) across {c['files']} files."]
    if facts["chains"]:
        parts.append(f"The most serious path: {facts['chains'][0]['title']}.")
    steps = [{"finding_id": f["id"], "why": f"{f['title']} on {f['resource']} (score {f['score']})."}
             for f in facts["top_findings"][:3]]
    return {"summary": " ".join(parts), "first_steps": steps}


def _post(url: str, path: str, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def narrate(findings: list[Finding], chains: list[Chain], counts: dict, use_llm: bool,
            url: str | None = None, timeout: float | None = None) -> dict:
    facts = facts_for(findings, chains, counts)
    result = {"author": "deterministic template", "text": template(facts), "validation": [], "stats": {}}
    if not use_llm or not facts["top_findings"]:
        return result
    url = (url or os.environ.get("ASSAY_LLM_URL", "http://127.0.0.1:8088")).rstrip("/")
    timeout = timeout or float(os.environ.get("ASSAY_LLM_TIMEOUT", "600"))
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": json.dumps(facts, separators=(",", ":"))}]
    try:
        t = time.perf_counter()
        prompt = _post(url, "/apply-template", {"messages": messages,
                                                "chat_template_kwargs": {"enable_thinking": False}}, 30)["prompt"]
        d = _post(url, "/completion", {"prompt": prompt, "json_schema": schema_for(facts), "n_predict": 320,
                                       "temperature": 0.2, "cache_prompt": True}, timeout)
        wall = round(time.perf_counter() - t, 1)
        out = json.loads(d.get("content", ""))
        try:
            with urllib.request.urlopen(url + "/v1/models", timeout=5) as r:
                model = os.path.basename(json.loads(r.read().decode())["data"][0]["id"]).removesuffix(".gguf")
        except Exception:
            model = "local model"
    except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError, KeyError) as e:
        result["validation"] = [f"local model unavailable or invalid output: {type(e).__name__}"]
        return result
    problems = validate(out, facts)
    result["stats"] = {"wall_s": wall, "output_tokens": (d.get("timings") or {}).get("predicted_n")}
    if problems:
        result["validation"] = problems + ["model text rejected; template used"]
        return result
    result.update(author=f"{model} (local, llama.cpp), checked against the facts", text=out)
    return result
