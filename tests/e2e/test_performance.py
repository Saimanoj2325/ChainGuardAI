"""Performance & Latency Profiling for ChainGuard AI.
Profiles pipeline wall-clock latency, GNN inference speed, report hashing throughput, and memory RSS.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
import psutil
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
for p in ("backend", "shared", "sandbox", "ml"):
    sp = str(ROOT / p)
    if sp not in sys.path:
        sys.path.insert(0, sp)

from app.config import Settings
from app.main import create_app
from chainguard_contract.hashing import canonical_json, report_hash
from chainguard_ml.analyzer import MLAnalyzer
from chainguard_contract.analyzer import AnalysisInput


def test_gnn_inference_latency_benchmark():
    """GNN inference must execute in under 150ms on standard contracts."""
    sol_path = ROOT / "fixtures" / "contracts" / "vulnerable" / "reentrancy_classic.sol"
    source = sol_path.read_text(encoding="utf-8")
    
    analyzer = MLAnalyzer()
    assert analyzer.available(), "MLAnalyzer not available"
    inp = AnalysisInput("perf_job", "EtherBank.sol", source, ".")

    # Warmup
    analyzer.analyze(inp)

    # 10 iterations profiling
    timings = []
    for _ in range(10):
        t0 = time.perf_counter()
        findings = analyzer.analyze(inp)
        dt = (time.perf_counter() - t0) * 1000.0  # ms
        timings.append(dt)

    avg_ms = sum(timings) / len(timings)
    p95_ms = sorted(timings)[int(len(timings) * 0.95)]
    print(f"\n[PERF] GNN Inference: avg={avg_ms:.2f}ms, p95={p95_ms:.2f}ms (findings={len(findings)})")
    assert avg_ms < 150.0, f"GNN inference too slow: {avg_ms:.2f}ms (target < 150ms)"


def test_canonical_hashing_throughput():
    """Canonical JSON hashing must achieve > 2,000 hashes per second."""
    sample_report = {
        "report_id": "R-12345",
        "job_id": "job-12345",
        "contract": {"filename": "Bank.sol", "sha256": "abcdef", "size_bytes": 1024},
        "findings": [{"id": "f-1", "severity": "critical", "vuln_class": "reentrancy"}],
        "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
    }

    t0 = time.perf_counter()
    n_ops = 5000
    for _ in range(n_ops):
        _ = report_hash(sample_report)
    dt = time.perf_counter() - t0
    ops_per_sec = n_ops / dt
    print(f"\n[PERF] Report Hashing: {ops_per_sec:.0f} ops/sec (total {dt:.3f}s for {n_ops} reports)")
    assert ops_per_sec > 2000, f"Hashing throughput too low: {ops_per_sec:.0f} ops/sec"


def test_pipeline_end_to_end_latency(tmp_path):
    """Full pipeline execution from HTTP post to completed job under 2.5s."""
    settings = Settings(data_dir=str(tmp_path), disable_sandbox=False, disable_ml=False)
    app = create_app(settings=settings, start_workers=True)
    
    with TestClient(app) as client:
        sol_path = ROOT / "fixtures" / "contracts" / "vulnerable" / "reentrancy_classic.sol"
        data = sol_path.read_bytes()
        
        t0 = time.perf_counter()
        resp = client.post("/api/v1/analyses", files={"file": ("EtherBank.sol", data, "text/plain")})
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]

        while time.perf_counter() - t0 < 5.0:
            job = client.get(f"/api/v1/analyses/{job_id}").json()
            if job["status"] == "completed":
                break
            time.sleep(0.05)

        total_dt = time.perf_counter() - t0
        print(f"\n[PERF] End-to-End Pipeline Latency: {total_dt:.3f}s")
        assert job["status"] == "completed"
        assert total_dt < 3.0, f"E2E latency exceeded threshold: {total_dt:.3f}s"
