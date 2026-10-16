"""Judge R3 fix 6: the web page is read-only, local and shows pending approvals."""
import json
import threading
import urllib.error
import urllib.request

from assay.agent import run
from assay.ui import build_state, serve


def _run(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.tf").write_text('resource "aws_s3_bucket_public_access_block" "b" {\n  bucket = "x"\n  block_public_acls = false\n}\n'
                                  'resource "aws_s3_bucket" "x" { bucket = "x" }\n')
    (repo / "t.json").write_text(json.dumps({"Records": [{"eventTime": "2026-10-02T10:00:00Z", "eventName": "StopLogging",
        "userIdentity": {"arn": "arn:aws:iam::1:user/a"}, "sourceIPAddress": "1.2.3.4"}]}))
    out = tmp_path / "run"
    run(str(repo), out)
    return out


def test_state_has_pending_patches_and_audit_status(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSAY_KEYSTORE", str(tmp_path / "keys"))
    out = _run(tmp_path)
    s = build_state(out)
    assert s["findings"] and s["audit"]["status"] == "intact and authenticated"
    assert all(a["status"] == "waiting for approval" for a in s["actions"])
    assert any(a["approve_with"].startswith("assay approve") for a in s["actions"])


def test_server_serves_page_and_state_but_refuses_writes(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSAY_KEYSTORE", str(tmp_path / "keys"))
    out = _run(tmp_path)
    srv = serve(out, 0)
    port = srv.server_address[1]
    assert srv.server_address[0] == "127.0.0.1"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{port}"
        assert b"<title>Assay</title>" in urllib.request.urlopen(base + "/").read()
        assert json.load(urllib.request.urlopen(base + "/api/state"))["counts"]["findings"] > 0
        for path in ("/../../etc/passwd", "/findings.json", "/audit.jsonl"):
            try:
                urllib.request.urlopen(base + path)
                raise AssertionError("served " + path)
            except urllib.error.HTTPError as e:
                assert e.code == 404
        req = urllib.request.Request(base + "/api/state", data=b"{}", method="POST")
        try:
            urllib.request.urlopen(req)
            raise AssertionError("POST accepted")
        except urllib.error.HTTPError as e:
            assert e.code == 405
    finally:
        srv.shutdown()
        srv.server_close()
