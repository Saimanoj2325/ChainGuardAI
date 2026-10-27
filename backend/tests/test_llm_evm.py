import json

import httpx
import pytest
from fastapi.testclient import TestClient

from chainguard_contract.models import Finding, LLMVerdict, VulnClass, Severity, DetectorSource

from app.main import create_app
from app.verifiers import LLMVerifier, build_evidence_prompt, parse_verdict
from tests.conftest import make_settings, submit, wait_done

F = Finding(id="F001", vuln_class=VulnClass.reentrancy, title="t", severity=Severity.high, confidence=0.6,
            detectors=[DetectorSource.heuristic], function_name="withdraw", description="d")


@pytest.mark.parametrize("text,verdict", [
    ('{"verdict":"supported","explanation":"call at L14 before write at L16"}', LLMVerdict.supported),
    ('```json\n{"verdict":"refuted","explanation":"guarded"}\n```', LLMVerdict.refuted),
    ('{"verdict":"uncertain","explanation":"insufficient"}', LLMVerdict.uncertain),
])
def test_parse_ok(text, verdict):
    assert parse_verdict(text)[0] == verdict


@pytest.mark.parametrize("text", ["Sure! It is vulnerable.", '{"verdict":"yes","explanation":"x"}',
                                  '{"verdict":"supported"}', 'prefix {"verdict":"supported","explanation":"x"}', "[]"])
def test_parse_strict_rejects(text):
    with pytest.raises(ValueError):
        parse_verdict(text)


def _transport(content=None, status=200, captured=None):
    def handler(req: httpx.Request):
        if captured is not None:
            captured.append(json.loads(req.content))
        if status != 200:
            return httpx.Response(status, text="upstream down")
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})
    return httpx.MockTransport(handler)


def test_no_key_not_run(tmp_path):
    v = LLMVerifier(make_settings(tmp_path))
    assert v.verify(F, "src")[0] == LLMVerdict.not_run


def test_verifier_ok_and_prompt_is_evidence_only(tmp_path):
    cap = []
    s = make_settings(tmp_path, llm_api_key="k", llm_model="test/model")
    v = LLMVerifier(s, transport=_transport('{"verdict":"supported","explanation":"L14"}', captured=cap))
    assert v.verify(F, "  14: msg.sender.call") == (LLMVerdict.supported, "L14")
    body = cap[0]
    assert body["model"] == "test/model" and body["temperature"] == 0.0
    assert "msg.sender.call" in body["messages"][1]["content"]


def test_verifier_errors_never_fabricate(tmp_path):
    s = make_settings(tmp_path, llm_api_key="k")
    assert LLMVerifier(s, transport=_transport("I think it's vulnerable")).verify(F, "x")[0] == LLMVerdict.error
    assert LLMVerifier(s, transport=_transport(status=500)).verify(F, "x")[0] == LLMVerdict.error


def test_pipeline_uses_llm(tmp_path):
    s = make_settings(tmp_path, llm_api_key="k")
    llm = LLMVerifier(s, transport=_transport('{"verdict":"supported","explanation":"evidence lines 14,16"}'))
    with TestClient(create_app(s, llm=llm)) as c:
        jid = submit(c).json()["job_id"]
        job = wait_done(c, jid)
        assert any(e["stage"] == "llm_verification" and e["status"] == "completed" for e in job["events"])
        fs = c.get(f"/api/v1/analyses/{jid}/findings").json()["findings"]
        assert fs and all(f["verification"]["llm_status"] == "supported" for f in fs)
        assert c.get(f"/api/v1/analyses/{jid}/report").json()["findings"][0]["verification"]["llm_status"] == "supported"


def test_pipeline_llm_all_errors_stage_failed(tmp_path):
    s = make_settings(tmp_path, llm_api_key="k")
    llm = LLMVerifier(s, transport=_transport(status=503))
    with TestClient(create_app(s, llm=llm)) as c:
        jid = submit(c).json()["job_id"]
        job = wait_done(c, jid)
        assert job["status"] == "completed"
        assert any(e["stage"] == "llm_verification" and e["status"] == "failed" for e in job["events"])
        fs = c.get(f"/api/v1/analyses/{jid}/findings").json()["findings"]
        assert all(f["verification"]["llm_status"] == "error" for f in fs)


def test_build_prompt_contains_only_evidence():
    p = build_evidence_prompt(F, "  12: function withdraw() {")
    assert "withdraw" in p and "Function source" in p
