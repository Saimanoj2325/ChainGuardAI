import json
import os

from fastapi.testclient import TestClient

from chainguard_contract.analyzer import AnalyzerError
from chainguard_contract.models import ErrorResponse, Job

from app.analyzers import AnalyzerRegistry
from app.analyzers.heuristic import HeuristicAnalyzer
from app.main import create_app
from tests.conftest import make_settings, submit, wait_done


def _err(r, status, code=None):
    assert r.status_code == status, r.text
    e = ErrorResponse.model_validate(r.json())
    if code:
        assert e.error == code
    return e


def test_oversized_413_in_handler(tmp_path):
    with TestClient(create_app(make_settings(tmp_path, max_upload_bytes=100))) as c:
        _err(submit(c, "contract A {}" + " " * 200), 413, "payload_too_large")


def test_oversized_413_by_content_length(client):
    _err(submit(client, "a" * (600 * 1024)), 413, "payload_too_large")


def test_wrong_extension(client):
    _err(submit(client, "contract A {}", "a.txt"), 400, "invalid_file_type")


def test_traversal_filename_sanitized(client):
    r = submit(client, "contract A {}", "../../evil.sol")
    assert r.status_code == 202 and r.json()["contract"]["filename"] == "evil.sol"


def test_empty_and_whitespace(client):
    _err(submit(client, b""), 400, "empty_file")
    _err(submit(client, b"   \n"), 400, "empty_file")


def test_invalid_utf8_and_nul(client):
    _err(submit(client, b"\xc3\x28 contract"), 400, "invalid_encoding")
    _err(submit(client, b"contract\x00A{}"), 400, "invalid_content")


def test_missing_file_field_422(client):
    _err(client.post("/api/v1/analyses", data={"x": "y"}), 422, "validation_error")


def test_bad_severity_422(client):
    jid = submit(client).json()["job_id"]
    _err(client.get(f"/api/v1/analyses/{jid}/findings", params={"severity": "huge"}), 422)


def test_unknown_job_404(client):
    _err(client.get("/api/v1/analyses/nope"), 404, "job_not_found")
    _err(client.get("/api/v1/analyses/nope/findings"), 404)
    _err(client.get("/api/v1/analyses/nope/report"), 404)


def test_verify_requires_input_and_valid_hash(client):
    _err(client.post("/api/v1/reports/verify", json={}), 400, "missing_input")
    _err(client.post("/api/v1/reports/verify", json={"report_hash": "xyz"}), 400, "invalid_hash")


class Boom:
    name, version, stage = "boom", "1", "static_analysis"
    def available(self): return True
    def analyze(self, inp): raise AnalyzerError("synthetic analyzer failure")


class Crash(Boom):
    name = "crash"
    def analyze(self, inp): raise ZeroDivisionError("bug")


def test_analyzer_error_recorded_job_completes(tmp_path):
    reg = AnalyzerRegistry()
    reg.register(Boom()); reg.register(Crash()); reg.register(HeuristicAnalyzer())
    with TestClient(create_app(make_settings(tmp_path), analyzers=reg)) as c:
        jid = submit(c).json()["job_id"]
        job = Job.model_validate(wait_done(c, jid))
        assert job.status.value == "completed"
        failed = [e for e in job.events if e.status == "failed"]
        assert any("boom: synthetic analyzer failure" in (e.message or "") for e in failed)
        assert any("crash: unexpected ZeroDivisionError" in (e.message or "") for e in failed)
        assert any(e.stage.value == "static_analysis" and e.status == "completed" for e in job.events)
        assert job.analyzers == ["heuristic@0.1.0"]


def test_all_static_analyzers_fail_degraded(tmp_path):
    reg = AnalyzerRegistry(); reg.register(Boom())
    with TestClient(create_app(make_settings(tmp_path), analyzers=reg)) as c:
        jid = submit(c).json()["job_id"]
        job = wait_done(c, jid)
        assert job["status"] == "completed" and "static analysis failed" in job["error"]
        assert any(e["stage"] == "static_analysis" and e["status"] == "failed" and e["message"] == "all static analyzers failed"
                   for e in job["events"])
        assert c.get(f"/api/v1/analyses/{jid}/report").json()["findings"] == []


def test_pipeline_crash_fails_job_cleanly(tmp_path, monkeypatch):
    s = make_settings(tmp_path)
    app_ = create_app(s)
    import app.pipeline as pl
    monkeypatch.setattr(pl, "merge_findings", lambda fs: (_ for _ in ()).throw(RuntimeError("merge exploded")))
    with TestClient(app_) as c:
        jid = submit(c).json()["job_id"]
        job = wait_done(c, jid)
        assert job["status"] == "failed" and "evidence" in job["error"] and "merge exploded" in job["error"]
        _err(c.get(f"/api/v1/analyses/{jid}/report"), 404, "report_not_ready")


def test_auth_required_when_key_set(tmp_path):
    with TestClient(create_app(make_settings(tmp_path, api_key="s3cret"))) as c:
        assert c.get("/api/v1/health").status_code == 200
        _err(submit(c), 401, "unauthorized")
        _err(c.get("/api/v1/analyses/x"), 401)
        _err(c.post("/api/v1/reports/verify", json={}, headers={"X-API-Key": "wrong"}), 401)
        h = {"X-API-Key": "s3cret"}
        r = submit(c, headers=h)
        assert r.status_code == 202
        assert wait_done(c, r.json()["job_id"], headers=h)["status"] == "completed"


def test_restart_recovery(tmp_path):
    s = make_settings(tmp_path)
    a1 = create_app(s, start_workers=False)
    with TestClient(a1) as c:  # no workers → jobs stay queued
        q = submit(c).json()["job_id"]
        r = submit(c).json()["job_id"]
    a1.state.db.update_job(r, status="running", stage="static_analysis")
    a1.state.db.close()
    with TestClient(create_app(s)) as c:
        assert wait_done(c, q)["status"] == "completed"
        jr = c.get(f"/api/v1/analyses/{r}").json()
        assert jr["status"] == "failed" and "restart" in jr["error"]


def test_job_file_stored_by_job_id(tmp_path):
    s = make_settings(tmp_path)
    with TestClient(create_app(s)) as c:
        jid = submit(c, "contract A {}", "../../weird name.sol").json()["job_id"]
        wait_done(c, jid)
    assert os.listdir(os.path.join(s.data_dir, "jobs", jid)) == ["contract.sol"]
