import copy

from chainguard_contract.models import AuditReport, FindingsResponse, Health, Job, SubmitResponse, VerifyResponse

from tests.conftest import REENTRANCY_SOL, SAFE_SOL, submit, wait_done


def test_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    h = Health.model_validate(r.json())
    assert h.analyzers["heuristic"] is True and h.analyzers["slither"] is False
    assert h.analyzers["llm"] is False and h.status == "degraded"


def test_full_flow_reentrancy(client):
    r = submit(client)
    assert r.status_code == 202
    sub = SubmitResponse.model_validate(r.json())
    assert sub.status.value == "queued" and sub.contract.filename == "EtherStore.sol"
    job = Job.model_validate(wait_done(client, sub.job_id))
    assert job.status.value == "completed" and job.stage.value == "done" and job.progress == 100
    stages = {(e.stage.value, e.status) for e in job.events}
    for st in ("parsing", "ml_inference", "llm_verification", "evm_validation"):
        assert (st, "skipped") in stages, st
    for st in ("static_analysis", "evidence", "reporting"):
        assert (st, "completed") in stages, st
    assert job.contract.contracts == ["EtherStore"] and "heuristic@0.1.0" in job.analyzers

    fr = FindingsResponse.model_validate(client.get(f"/api/v1/analyses/{sub.job_id}/findings").json())
    re_ = [f for f in fr.findings if f.vuln_class.value == "reentrancy"]
    assert len(re_) == 1
    f = re_[0]
    assert f.function_name == "withdraw" and f.contract_name == "EtherStore"
    assert {(l.start, l.end) for l in f.evidence.lines} == {(14, 14), (16, 16)}
    assert "msg.sender.call" in f.evidence.snippet and f.detectors[0].value == "heuristic"
    assert f.verification.llm_status.value == "not_run" and f.verification.evm_status.value == "not_run"
    assert not f.is_mock and job.finding_count == len(fr.findings)

    only_low = client.get(f"/api/v1/analyses/{sub.job_id}/findings", params={"severity": "low"}).json()
    assert all(x["severity"] == "low" for x in only_low["findings"])

    rr = client.get(f"/api/v1/analyses/{sub.job_id}/report")
    assert rr.status_code == 200
    rep_json = rr.json()
    rep = AuditReport.model_validate(rep_json)
    assert rep.summary.high >= 1 and rep.registry is not None and rep.registry.report_hash == rep.report_hash
    assert rep.contains_mock_data is False

    v = VerifyResponse.model_validate(client.post("/api/v1/reports/verify", json={"report": rep_json}).json())
    assert v.valid and v.registered and v.chain_intact and v.recomputed_hash == rep.report_hash

    vh = client.post("/api/v1/reports/verify", json={"report_hash": rep.report_hash}).json()
    assert vh["valid"] is True

    tampered = copy.deepcopy(rep_json)
    tampered["findings"][0]["severity"] = "info"
    vt = VerifyResponse.model_validate(client.post("/api/v1/reports/verify", json={"report": tampered}).json())
    assert not vt.valid and not vt.registered and "modified" in vt.reason

    forged = copy.deepcopy(tampered)
    from chainguard_contract.hashing import report_hash
    forged["report_hash"] = report_hash(forged)  # self-consistent but never registered
    vf = client.post("/api/v1/reports/verify", json={"report": forged}).json()
    assert vf["valid"] is False and "not in the registry" in vf["reason"]

    md = client.get(f"/api/v1/analyses/{sub.job_id}/report", params={"format": "markdown"})
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert rep.report_hash in md.text and "not a public blockchain" in md.text and "reentrancy" in md.text


def test_registry_chains_across_jobs(client):
    hashes = []
    for src in (REENTRANCY_SOL, SAFE_SOL):
        jid = submit(client, src).json()["job_id"]
        assert wait_done(client, jid)["status"] == "completed"
        hashes.append(client.get(f"/api/v1/analyses/{jid}/report").json()["registry"])
    assert hashes[1]["index"] == hashes[0]["index"] + 1
    assert hashes[1]["prev_entry_hash"] == hashes[0]["entry_hash"]


def test_safe_contract_no_reentrancy(client):
    jid = submit(client, SAFE_SOL, "Safe.sol").json()["job_id"]
    wait_done(client, jid)
    fs = client.get(f"/api/v1/analyses/{jid}/findings").json()["findings"]
    assert not [f for f in fs if f["vuln_class"] == "reentrancy"]


def test_report_not_ready_and_bad_format(client):
    jid = submit(client).json()["job_id"]
    r = client.get(f"/api/v1/analyses/{jid}/report", params={"format": "pdf"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_format"
    wait_done(client, jid)
    assert client.get(f"/api/v1/analyses/{jid}/report").status_code == 200


def test_cors_preflight(client):
    r = client.options("/api/v1/analyses", headers={"Origin": "http://localhost:5173",
                                                    "Access-Control-Request-Method": "POST"})
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] == "http://localhost:5173"
