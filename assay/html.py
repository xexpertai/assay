"""Stage 6b: a single-file HTML report (no external assets, no scripts) with the attack chains drawn as inline SVG."""
from __future__ import annotations

import html

from . import __version__
from .report import SEV_ORDER

SEV_COLOUR = {"critical": "#b3261e", "high": "#d9480f", "medium": "#b7791f", "low": "#2b6cb0", "info": "#5f6368"}

CSS = """
:root{--bg:#fff;--fg:#1f2328;--muted:#57606a;--line:#d0d7de;--card:#f6f8fa;--code:#eff1f3}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9da7b3;--line:#30363d;--card:#161b22;--code:#1f2630}}
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--fg);background:var(--bg);margin:0 auto;max-width:1100px;padding:24px}
h1{font-size:1.6rem;margin:.2em 0}h2{font-size:1.2rem;border-bottom:1px solid var(--line);padding-bottom:.2em;margin-top:2em}
h3{font-size:1rem;margin:.6em 0 .3em}code,pre{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);border-radius:4px}
code{padding:1px 4px}pre{padding:10px;overflow:auto}table{border-collapse:collapse;width:100%;margin:.5em 0}
th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}th{background:var(--card)}
.sev{display:inline-block;padding:0 7px;border-radius:10px;color:#fff;font-size:12px;font-weight:600;line-height:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:10px 0}
.muted{color:var(--muted)}details>summary{cursor:pointer;font-weight:600}
svg text{font:12px system-ui,sans-serif;fill:var(--fg)}svg .box{fill:var(--card);stroke:var(--line)}
svg .edge{stroke:var(--muted);fill:none;marker-end:url(#arrow)}svg .chain{stroke-width:2}
.diff ins{background:#d4f5d4;color:#1a5d1a;text-decoration:none}.diff del{background:#ffd9d9;color:#8a1f1f;text-decoration:none}
@media (prefers-color-scheme:dark){.diff ins{background:#1d3b25;color:#9be39b}.diff del{background:#4a1e1e;color:#ff9b9b}}
"""


def _e(s) -> str:
    return html.escape(str(s), quote=True)


def _sev(s: str) -> str:
    return f'<span class="sev" style="background:{SEV_COLOUR[s]}">{_e(s)}</span>'


def _wrap(text: str, width: int = 34) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width and cur:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines[:3]


def chain_svg(chain, by_id: dict) -> str:
    """One chain as a left-to-right diagram: member findings -> the chain they form."""
    members = [by_id[i] for i in chain.finding_ids if i in by_id]
    row_h, box_w, box_h, gap = 64, 300, 50, 40
    n = max(len(members), 1)
    height = n * row_h + 20
    width = box_w * 2 + gap * 3
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" '
             f'aria-label="Attack chain {_e(chain.id)}: {_e(chain.title)}">',
             '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto">'
             '<path d="M0,0 L10,5 L0,10 z" fill="#8b949e"/></marker></defs>']
    cy_chain = height / 2
    for k, f in enumerate(members):
        y = 10 + k * row_h
        parts.append(f'<rect class="box" x="{gap}" y="{y}" width="{box_w}" height="{box_h}" rx="6" '
                     f'style="stroke:{SEV_COLOUR[f.severity]}"/>')
        parts.append(f'<text x="{gap + 8}" y="{y + 18}" font-weight="600">{_e(f.id)} <tspan fill="{SEV_COLOUR[f.severity]}">'
                     f'{_e(f.severity)}</tspan></text>')
        lines = _wrap(f.title, 46)
        parts.append(f'<text x="{gap + 8}" y="{y + 34}">{_e(lines[0])}</text>')
        if len(lines) > 1:
            parts.append(f'<text x="{gap + 8}" y="{y + 46}" class="muted">{_e(lines[1])}</text>')
        parts.append(f'<path class="edge" d="M{gap + box_w},{y + box_h / 2} C{gap + box_w + gap / 2},{y + box_h / 2} '
                     f'{gap * 2 + box_w - gap / 2},{cy_chain} {gap * 2 + box_w},{cy_chain}"/>')
    x2 = gap * 2 + box_w
    parts.append(f'<rect class="box chain" x="{x2}" y="{cy_chain - 32}" width="{box_w}" height="64" rx="8" '
                 f'style="stroke:{SEV_COLOUR[chain.severity]}"/>')
    parts.append(f'<text x="{x2 + 10}" y="{cy_chain - 12}" font-weight="700">{_e(chain.id)} '
                 f'<tspan fill="{SEV_COLOUR[chain.severity]}">{_e(chain.severity)}</tspan></text>')
    for j, ln in enumerate(_wrap(chain.title, 44)[:3]):
        parts.append(f'<text x="{x2 + 10}" y="{cy_chain + 6 + j * 14}">{_e(ln)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _diff_html(diff: str) -> str:
    out = []
    for ln in diff.rstrip().splitlines():
        if ln.startswith("+") and not ln.startswith("+++"):
            out.append(f"<ins>{_e(ln)}</ins>")
        elif ln.startswith("-") and not ln.startswith("---"):
            out.append(f"<del>{_e(ln)}</del>")
        else:
            out.append(_e(ln))
    return '<pre class="diff">' + "\n".join(out) + "</pre>"


def to_html(res) -> str:
    c, n = res.counts, res.narrative
    by_id = {f.id: f for f in res.findings}
    pol = res.policy or {}
    H = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
         f"<title>Assay report: {_e(res.scope_root.rsplit('/', 1)[-1])}</title><style>{CSS}</style></head><body>",
         "<h1>Assay security assessment report</h1>",
         f"<p class='muted'>Assay {_e(__version__)} · scope <code>{_e(res.scope_root.rsplit('/', 1)[-1])}</code> "
         f"({c['files']} files) · policy <code>{_e(pol.get('mode', 'files-only'))}</code>"
         + (f" (lab '{_e(pol.get('name'))}', authorised by {_e(pol.get('authorised_by'))} until {_e(pol.get('expires'))})"
            if pol.get("mode") == "lab-allowlist" else "")
         + " · static review of local files: no host was contacted, no code was executed, nothing was changed.</p>",
         "<table><tr>" + "".join(f"<th>{s}</th>" for s in SEV_ORDER) + "<th>chains</th><th>proposed patches</th></tr><tr>"
         + "".join(f"<td>{c['by_severity'].get(s, 0)}</td>" for s in SEV_ORDER)
         + f"<td>{c['chains']}</td><td>{len(res.actions)} (0 applied)</td></tr></table>",
         "<h2>Briefing</h2>", f"<div class='card'><p>{_e(n['text']['summary'])}</p><p><b>First steps</b></p><ol>"]
    for s in n["text"]["first_steps"]:
        f = by_id.get(s["finding_id"])
        H.append(f"<li><code>{_e(s['finding_id'])}</code>" + (f" <span class='muted'>{_e(f.file)}:{f.line}</span>" if f else "")
                 + f": {_e(s['why'])}</li>")
    H.append(f"</ol><p class='muted'>Written by: {_e(n['author'])}.</p></div>")
    H.append("<h2>Attack chains (correlated findings)</h2>")
    if not res.chains:
        H.append("<p>No multi-step chains were found.</p>")
    for ch in res.chains:
        H.append(f"<div class='card'><h3>{_sev(ch.severity)} {_e(ch.id)} {_e(ch.title)}</h3>{chain_svg(ch, by_id)}"
                 f"<p>{_e(ch.narrative)}</p><p class='muted'>Built from: "
                 + ", ".join(f"<code>{_e(i)}</code>" for i in ch.finding_ids) + "</p></div>")
    H.append("<h2>Findings by priority</h2><table><tr><th>Score</th><th>Severity</th><th>ID</th><th>Finding</th><th>Location</th></tr>")
    for f in res.findings:
        H.append(f"<tr><td>{f.score}</td><td>{_sev(f.severity)}</td><td><a href='#{_e(f.id)}'><code>{_e(f.id)}</code></a></td>"
                 f"<td>{_e(f.title)}</td><td><code>{_e(f.file)}:{f.line}</code> <span class='muted'>{_e(f.resource)}</span></td></tr>")
    H.append("</table><h2>Finding details</h2>")
    for f in res.findings:
        if f.severity == "info":
            continue
        H.append(f"<details id='{_e(f.id)}' class='card'><summary>{_sev(f.severity)} <code>{_e(f.id)}</code> {_e(f.title)}</summary>"
                 f"<p><b>Rule</b> {_e(f.rule_id)}{(' (' + _e(f.cwe) + ')') if f.cwe else ''} · confidence {_e(f.confidence)} · "
                 f"score {f.score} = {_e('; '.join(f.score_factors))}</p>"
                 f"<p><b>Where</b> <code>{_e(f.file)}:{f.line}</code>, {_e(f.resource)}</p>"
                 f"<p><b>Evidence</b> <code>{_e(f.evidence)}</code></p><p><b>Why it matters</b> {_e(f.rationale)}</p>"
                 f"<p><b>Fix</b> {_e(f.remediation)}</p></details>")
    if res.diff:
        d = res.diff
        H.append(f"<h2>Changes since baseline</h2><p>Compared with <code>{_e(d['baseline'])}</code> ({d['baseline_findings']} "
                 f"findings): <b>{len(d['new'])} new</b>, <b>{len(d['fixed'])} fixed</b>, {d['unchanged']} unchanged, "
                 f"{d['moved']} moved (same weakness, new line).</p>")
        for label, items in (("New", d["new"]), ("Fixed", d["fixed"])):
            if items:
                H.append(f"<p><b>{label}</b></p><ul>" + "".join(
                    f"<li>{_sev(i['severity'])} <code>{_e(i['id'])}</code> {_e(i['title'])} "
                    f"<span class='muted'>{_e(i['file'])}:{i['line']}</span></li>" for i in items) + "</ul>")
    H.append("<h2>Proposed actions (awaiting human approval)</h2>")
    if not res.actions:
        H.append("<p>No mechanical patches proposed; the fixes above are manual.</p>")
    else:
        H.append("<p>Nothing has been applied. Approve specific IDs with <code>assay approve &lt;run-dir&gt; A-01 --by \"Name\"</code>, "
                 "then <code>assay apply &lt;run-dir&gt;</code>; apply refuses if the plan or a file changed.</p>")
        for a in res.actions:
            H.append(f"<details class='card'><summary>{_e(a.id)}: {_e(a.description)}</summary>{_diff_html(a.diff)}</details>")
    H.append("<h2>Agent decisions</h2><table><tr><th>Stage</th><th>Decision</th><th>Reason</th></tr>")
    for d in res.decisions:
        H.append(f"<tr><td>{_e(d.stage)}</td><td>{_e(d.action)}</td><td>{_e(d.reason)}</td></tr>")
    H.append("</table><p class='muted'>Secrets are shown redacted (a 2-4 character prefix and the length). Findings come from "
             "deterministic rules; a person should confirm them before acting. The audit log for this run is keyed (HMAC) and "
             "hash-chained; check it with <code>assay verify-log</code>.</p></body></html>")
    return "\n".join(H)
