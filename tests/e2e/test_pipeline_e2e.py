"""End-to-End Integration Tests for ChainGuard AI.
Tests real contract submissions across vulnerable, patched, and benign categories,
verifying parsing, static analysis, ML inference, report generation, and cryptographic hash verification.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
for p in ("backend", "shared", "sandbox", "ml"):
    sp = str(ROOT / p)
    if sp not in sys.path:
        sys.path.insert(0, sp)

from app.config import Settings
from app.main import create_app


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("cg_e2e_data")
    settings = Settings(data_dir=str(data_dir), disable_sandbox=False, disable_ml=False)
    app = create_app(settings=settings, start_workers=True)
    with TestClient(app) as test_client:
        yield test_client


def _poll_job(client: TestClient, job_id: str, timeout_s: float = 20.0) -> dict:
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout_s:
        resp = client.get(f"/api/v1/analyses/{job_id}")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        if data["status"] in ("completed", "failed"):
            return data
        time.sleep(0.1)
    raise TimeoutError(f"Job {job_id} did not complete within {timeout_s}s")


def test_health_reports_analyzers(client: TestClient):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "analyzers" in data
    assert data["analyzers"].get("heuristic") is True
    assert data["analyzers"].get("gnn") is True


def test_reentrancy_classic_full_pipeline(client: TestClient):
    sol_path = ROOT / "fixtures" / "contracts" / "vulnerable" / "reentrancy_classic.sol"
    assert sol_path.exists(), f"Fixture missing: {sol_path}"
    
    with open(sol_path, "rb") as fh:
        resp = client.post("/api/v1/analyses", files={"file": ("EtherBank.sol", fh, "text/plain")})
    assert resp.status_code == 202, resp.text
    sub = resp.json()
    job_id = sub["job_id"]

    # Poll until done
    job = _poll_job(client, job_id)
    assert job["status"] == "completed"
    assert job["progress"] == 100

    # Verify stage progression
    stages_completed = {e["stage"] for e in job["events"] if e["status"] == "completed"}
    assert "received" in stages_completed
    assert "parsing" in stages_completed
    assert "ml_inference" in stages_completed
    assert "reporting" in stages_completed

    # Check findings
    findings_resp = client.get(f"/api/v1/analyses/{job_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()["findings"]
    assert len(findings) >= 1
    
    reentrancy_finding = next((f for f in findings if f["vuln_class"] == "reentrancy"), None)
    assert reentrancy_finding is not None
    assert reentrancy_finding["severity"] == "critical"
    assert "gnn" in reentrancy_finding["detectors"] or "heuristic" in reentrancy_finding["detectors"]

    # Check Audit Report & Cryptographic Verification
    rep_resp = client.get(f"/api/v1/analyses/{job_id}/report")
    assert rep_resp.status_code == 200
    rep = rep_resp.json()
    assert "report_hash" in rep
    assert "registry" in rep
    assert rep["registry"]["index"] >= 0

    # Verify report hash via verify endpoint
    verify_resp = client.post("/api/v1/reports/verify", json={"report": rep})
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["valid"] is True
    assert v_data["registered"] is True
    assert v_data["chain_intact"] is True


def test_benign_token_no_critical_findings(client: TestClient):
    sol_path = ROOT / "fixtures" / "contracts" / "benign" / "erc20.sol"
    if not sol_path.exists():
        pytest.skip("erc20.sol fixture not present")

    with open(sol_path, "rb") as fh:
        resp = client.post("/api/v1/analyses", files={"file": ("ERC20.sol", fh, "text/plain")})
    assert resp.status_code == 202
    job_id = resp.json()["job_id"]

    job = _poll_job(client, job_id)
    assert job["status"] == "completed"

    findings_resp = client.get(f"/api/v1/analyses/{job_id}/findings")
    findings = findings_resp.json()["findings"]
    critical_findings = [f for f in findings if f["severity"] == "critical"]
    assert len(critical_findings) == 0, f"False positive critical on benign contract: {critical_findings}"


def test_tampered_report_verification_fails(client: TestClient):
    # Create report
    sol_path = ROOT / "fixtures" / "contracts" / "vulnerable" / "tx_origin.sol"
    with open(sol_path, "rb") as fh:
        resp = client.post("/api/v1/analyses", files={"file": ("TxOrigin.sol", fh, "text/plain")})
    job_id = resp.json()["job_id"]
    _poll_job(client, job_id)

    rep = client.get(f"/api/v1/analyses/{job_id}/report").json()
    
    # Tamper with the report (modify contract name or findings)
    tampered = dict(rep)
    tampered["findings"] = []

    verify_resp = client.post("/api/v1/reports/verify", json={"report": tampered})
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["valid"] is False
    assert "does not match" in v_data["reason"].lower()
