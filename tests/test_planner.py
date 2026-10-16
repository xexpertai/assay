"""Judge R3 fix 4: the LLM planner is validated, logged, and cannot bypass the deterministic plan or the gate."""
import json
import threading
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from assay.agent import run


class _Fake:
    """Stands in for llama-server: /apply-template echoes the user text, /completion returns canned JSON."""

    def __init__(self):
        self.replies = []  # list of dicts (or raw strings) popped per /completion call
        self.prompts = []
        fake = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/apply-template":
                    out = {"prompt": body["messages"][-1]["content"]}
                else:
                    fake.prompts.append(body["prompt"])
                    r = fake.replies.pop(0)
                    out = {"content": r if isinstance(r, str) else json.dumps(r)}
                data = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"


@pytest.fixture
def fake():
    f = _Fake()
    yield f
    f.srv.shutdown()
    f.srv.server_close()


@pytest.fixture(autouse=True)
def _keys(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("ASSAY_KEYSTORE", str(tmp_path_factory.mktemp("keys")))


def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.tf").write_text('resource "aws_s3_bucket" "x" { bucket = "x" }\n')
    (repo / "airflow.cfg").write_text("[api]\nauth_backends = airflow.api.auth.backend.default\n")
    (repo / "notes.env").write_text("TOKEN=ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\n")
    return repo


def _names(res):
    return [e["analyser"] for e in res.plan_entries]


def test_model_order_is_applied_logged_and_secret_scan_stays_last(tmp_path, fake):
    base = run(str(_repo(tmp_path)))
    names = _names(base)
    runnable = [e["analyser"] for e in base.plan_entries if e["run"]]
    pick = list(reversed(runnable))
    fake.replies.append({"order": pick, "reasons": [{"analyser": n, "why": f"{n} has matching files in scope"} for n in pick]})
    out = tmp_path / "out"
    res = run(str(tmp_path / "repo"), out, planner_url=fake.url)
    got = [e["analyser"] for e in res.plan_entries]
    assert set(got) == set(names)
    assert got[-1] == next(a for a in names if "secret" in a.lower()) or "secret" in got[-1].lower()
    assert any(d.action == "llm planner chose the analyser order" for d in res.decisions)
    log = [json.loads(l) for l in (out / "audit.jsonl").read_text().splitlines()]
    acc = [r for r in log if r["event"] == "llm_plan_accepted"]
    assert len(acc) == 1 and len(acc[0]["data"]["prompt_sha256"]) == 64 and len(acc[0]["data"]["output_sha256"]) == 64
    assert {f.id for f in res.findings} == {f.id for f in base.findings}  # ordering never changes the findings


def test_invalid_or_unavailable_model_falls_back_to_the_deterministic_plan(tmp_path, fake):
    repo = _repo(tmp_path)
    base = run(str(repo))
    fake.replies.append("not json at all")
    res = run(str(repo), tmp_path / "o1", planner_url=fake.url)
    assert [e["analyser"] for e in res.plan_entries] == [e["analyser"] for e in base.plan_entries]
    assert any(d.action == "llm planner not used" for d in res.decisions)
    res2 = run(str(repo), tmp_path / "o2", planner_url="http://127.0.0.1:9")  # nothing listens
    assert any(d.action == "llm planner not used" for d in res2.decisions)
    assert len(res2.findings) == len(base.findings)


def test_invented_numbers_in_reasons_are_rejected(tmp_path, fake):
    repo = _repo(tmp_path)
    base = run(str(repo))
    runnable = [e["analyser"] for e in base.plan_entries if e["run"]]
    fake.replies.append({"order": runnable, "reasons": [{"analyser": runnable[0], "why": "found 4242 risky files here"}]})
    res = run(str(repo), tmp_path / "o", planner_url=fake.url)
    assert any(d.action == "llm plan rejected" for d in res.decisions)


def _lab(tmp_path, hosts):
    p = tmp_path / "lab.json"
    p.write_text(json.dumps({"name": "lab", "authorised_by": "Owner", "hosts": hosts,
                             "expires": (date.today() + timedelta(days=3)).isoformat()}))
    return p


def test_steps_are_planned_only_for_permitted_hosts_and_never_approved(tmp_path, fake):
    from assay.scope import ScopePolicy
    repo = _repo(tmp_path)
    lab = _lab(tmp_path, ["db.lab.internal"])
    fake.replies.append({"order": [], "reasons": []})  # first call (order) invalid: min items -> JSON still parses
    fake.replies.append({"steps": [
        {"tool": "nmap-top-ports", "host": "db.lab.internal", "why": "open admin config found"},
        {"tool": "nmap-top-ports", "host": "evil.example.com", "why": "extra host"},      # not permitted
        {"tool": "rm-rf", "host": "db.lab.internal", "why": "bad tool"}]})                 # undeclared profile
    out = tmp_path / "out"
    res = run(str(repo), out, policy=ScopePolicy.from_lab_file(lab), planner_url=fake.url)
    assert len(res.proposed_steps) == 1 and res.proposed_steps[0]["host"] == "db.lab.internal"
    assert sum(d.action.startswith("llm proposal rejected") for d in res.decisions) == 2
    events = [json.loads(l)["event"] for l in (out / "audit.jsonl").read_text().splitlines()]
    assert "step_planned" in events and "llm_steps_proposed" in events
    assert "step_approved" not in events and "step_run_started" not in events
    from assay.steps import StepError, run_step
    with pytest.raises(StepError, match="no approval"):
        run_step(out, res.proposed_steps[0]["step_id"])


def test_no_step_proposals_without_a_lab(tmp_path, fake):
    res = run(str(_repo(tmp_path)), tmp_path / "o", planner_url=fake.url)
    assert not res.proposed_steps
    assert any(d.action == "llm step proposals skipped" for d in res.decisions)
