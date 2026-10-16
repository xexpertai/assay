"""Read-only local web page over a run directory: findings, chains, pending approvals, decisions, audit status.

Standard library only, one HTML page and one JSON endpoint. It binds to 127.0.0.1, serves nothing from the
file system by path, and answers every non-GET request with 405: it cannot approve, apply or run anything.
Approvals stay in the CLI (`assay approve`, `assay step approve`), where a named person types them.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .actions import AuditLog


def _steps(run_dir: Path) -> list[dict]:
    log = run_dir / "audit.jsonl"
    events: dict[str, list[str]] = {}
    approver: dict[str, str] = {}
    if log.exists():
        for line in log.read_text().splitlines():
            r = json.loads(line)
            sid = r.get("data", {}).get("step_id")
            if sid:
                events.setdefault(sid, []).append(r["event"])
                if r["event"] == "step_approved":
                    approver[sid] = r["data"].get("approver", "")
    out = []
    for p in sorted((run_dir / "steps").glob("S-*/step.json")) if (run_dir / "steps").exists() else []:
        s = json.loads(p.read_text())
        ev = events.get(s["step_id"], [])
        status = ("finished" if "step_run_finished" in ev else "failed" if "step_run_failed" in ev
                  else "running or interrupted" if "step_run_started" in ev
                  else "approved, waiting to run" if "step_approved" in ev else "waiting for approval")
        out.append({"id": s["step_id"], "status": status, "command": " ".join(s["core"]["argv"]),
                    "host": s["core"]["host"], "lab": s["core"]["lab_name"], "requested_by": s["requested_by"],
                    "approver": approver.get(s["step_id"], ""), "refusals": ev.count("step_refused"),
                    "approve_with": f'assay step approve {run_dir} {s["step_id"]} --by "Full Name"'})
    return out


def build_state(run_dir: Path) -> dict:
    data = json.loads((run_dir / "findings.json").read_text())
    plan = json.loads((run_dir / "plan.json").read_text()) if (run_dir / "plan.json").exists() else {"actions": []}
    appr = json.loads((run_dir / "approval.json").read_text()) if (run_dir / "approval.json").exists() else None
    approved = set(appr["approved"]) if appr else set()
    actions = [{"id": a["id"], "description": a["description"], "file": a["file"], "diff": a["diff"],
                "status": "approved by " + appr["approver"] if a["id"] in approved else "waiting for approval",
                "approve_with": f'assay approve {run_dir} {a["id"]} --by "Full Name"'} for a in plan["actions"]]
    audit = {"records": 0, "status": "no audit log"}
    if (run_dir / "audit.jsonl").exists():
        v = AuditLog(run_dir / "audit.jsonl").verify_full()
        audit = {"records": v["records"], "status": "intact and authenticated" if v["chain_ok"] and v["mac_ok"] else
                 "TAMPERED" if not v["chain_ok"] or v["mac_ok"] is False else "chain intact, key not on this machine"}
    return {"version": data.get("assay_version"), "scope_root": data["scope_root"], "counts": data["counts"],
            "policy": data["policy"], "findings": data["findings"], "chains": data["chains"],
            "decisions": data["decisions"], "actions": actions, "steps": _steps(run_dir), "audit": audit,
            "briefing": data.get("narrative", {}).get("summary") or data.get("narrative", {}).get("text", "")}


PAGE = """<!doctype html><html lang="en"><meta charset="utf-8"><title>Assay</title>
<style>
:root{--bg:#0d1117;--fg:#e6edf3;--mut:#9da7b3;--line:#30363d;--card:#161b22;--acc:#58a6ff}
body{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0}
header{padding:14px 24px;border-bottom:1px solid var(--line);display:flex;gap:24px;align-items:baseline;flex-wrap:wrap}
h1{margin:0;font-size:20px}.mut{color:var(--mut)}nav{display:flex;gap:4px;padding:0 24px;border-bottom:1px solid var(--line)}
nav button{background:none;border:0;color:var(--mut);padding:10px 14px;font:inherit;cursor:pointer;border-bottom:2px solid transparent}
nav button.on{color:var(--fg);border-color:var(--acc)}main{padding:18px 24px;max-width:1200px}
.card p{white-space:pre-line}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:10px 0}
.sev{padding:0 8px;border-radius:10px;color:#fff;font-size:12px;font-weight:600}
.critical{background:#b3261e}.high{background:#d9480f}.medium{background:#9a6700}.low{background:#2b6cb0}.info{background:#5f6368}
pre{background:#010409;padding:10px;border-radius:6px;overflow:auto;font-size:13px}code{font-size:13px}
.stat{display:inline-block;margin-right:22px}.stat b{font-size:22px;display:block}
.pend{border-left:4px solid #d29922}.ok{border-left:4px solid #3fb950}
button.f{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:3px 10px;cursor:pointer;margin-right:4px}
button.f.on{border-color:var(--acc)}
</style>
<header><h1>Assay</h1><span class="mut" id="meta"></span><span id="audit"></span></header>
<nav id="tabs"></nav><main id="main"></main>
<script>
const TABS=["Findings","Chains","Pending approvals","Decisions"];let S=null,tab="Findings",sev="all";
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e};
function sevb(s){return el("span","sev "+s,s)}
function render(){
  const m=document.getElementById("main");m.replaceChildren();
  const t=document.getElementById("tabs");t.replaceChildren();
  TABS.forEach(n=>{const b=el("button",n==tab?"on":"",n+(n=="Pending approvals"?" ("+pend().length+")":n=="Findings"?" ("+S.findings.length+")":n=="Chains"?" ("+S.chains.length+")":""));b.onclick=()=>{tab=n;render()};t.append(b)});
  ({"Findings":findings,"Chains":chains,"Pending approvals":approvals,"Decisions":decisions})[tab](m)}
function pend(){return S.actions.filter(a=>a.status.startsWith("waiting")).concat(S.steps.filter(s=>s.status.startsWith("waiting")||s.status.startsWith("approved")))}
function findings(m){
  const bar=el("div");["all","critical","high","medium","low","info"].forEach(s=>{const b=el("button","f"+(s==sev?" on":""),s);b.onclick=()=>{sev=s;render()};bar.append(b)});m.append(bar);
  const chainOf={};S.chains.forEach(c=>c.finding_ids.forEach(i=>(chainOf[i]=chainOf[i]||[]).push(c.id)));
  S.findings.filter(f=>sev=="all"||f.severity==sev).forEach(f=>{
    const d=el("details","card");const s=el("summary");s.append(sevb(f.severity),el("span",null," "+f.title+" "),el("span","mut",f.file+":"+f.line+"  score "+f.score));d.append(s);
    d.append(el("p",null,f.rationale),el("pre",null,f.evidence),el("p",null,"Fix: "+f.remediation),el("p","mut",f.rule_id+"  "+f.id+"  "+f.cwe+"  confidence "+f.confidence+(chainOf[f.id]?"  in chain "+chainOf[f.id].join(", "):"")));m.append(d)})}
function chains(m){if(!S.chains.length)m.append(el("p","mut","No chains."));
  S.chains.forEach(c=>{const d=el("div","card");const h=el("h3");h.append(sevb(c.severity),el("span",null," "+c.title));d.append(h,el("p",null,c.narrative),el("p","mut","built from "+c.finding_ids.length+" findings: "+c.finding_ids.join(", ")));m.append(d)})}
function approvals(m){
  m.append(el("p","mut","This page is read-only. Approving happens on the command line, by a named person, for exactly one action or step."));
  S.steps.forEach(s=>{const d=el("div","card "+(s.status=="finished"?"ok":"pend"));d.append(el("h3",null,"Active step "+s.id+": "+s.status),el("pre",null,s.command),el("p","mut","host "+s.host+", lab "+s.lab+(s.requested_by?", requested by "+s.requested_by:"")+(s.approver?", approved by "+s.approver:"")+(s.refusals?", "+s.refusals+" refused attempt(s)":"")));
    if(s.status.startsWith("waiting"))d.append(el("pre",null,s.approve_with));m.append(d)});
  S.actions.forEach(a=>{const w=a.status.startsWith("waiting");const d=el("div","card "+(w?"pend":"ok"));d.append(el("h3",null,"Patch "+a.id+": "+a.status),el("p",null,a.description),el("pre",null,a.diff));if(w)d.append(el("pre",null,a.approve_with));m.append(d)});
  if(!S.steps.length&&!S.actions.length)m.append(el("p","mut","Nothing proposed."))}
function decisions(m){S.decisions.forEach(d=>{const c=el("div","card");c.append(el("b",null,d.stage+": "+d.action),el("div","mut",d.reason));m.append(c)})}
fetch("/api/state").then(r=>r.json()).then(s=>{S=s;
  document.getElementById("meta").textContent="v"+s.version+"  "+s.scope_root+"  policy "+s.policy.mode;
  document.getElementById("audit").textContent="audit log: "+s.audit.records+" records, "+s.audit.status;
  const c=document.getElementById("meta");render()});
</script></html>"""


def make_handler(run_dir: Path):
    class H(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; "
                             "script-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path in ("/", "/index.html"):
                self._send(200, PAGE.encode(), "text/html; charset=utf-8")
            elif self.path == "/api/state":
                self._send(200, json.dumps(build_state(run_dir)).encode(), "application/json")
            else:
                self._send(404, b"not found", "text/plain")

        def _no(self):
            self._send(405, b"read-only", "text/plain")

        do_POST = do_PUT = do_DELETE = do_PATCH = _no  # noqa: N815

        def log_message(self, *a):  # quiet
            pass

    return H


def serve(run_dir: Path, port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(run_dir))
