from fastapi.testclient import TestClient

from chainguard_contract.analyzer import AnalysisInput, AnalyzerError
from chainguard_contract.models import VulnClass

from app.analyzers.sandbox import SandboxAnalyzer, SandboxClient, map_slither_detector
from app.main import create_app
from app.solsrc import SourceIndex
from tests.conftest import REENTRANCY_SOL, make_settings, submit, wait_done

import pytest

SLITHER_REENT = {"check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
                 "description": "Reentrancy in EtherStore.withdraw() ...",
                 "elements": [{"name": "withdraw", "type": "function", "function": "withdraw", "contract": "EtherStore",
                               "lines": [11, 12, 13, 14, 15, 16, 17]},
                              {"name": "balances", "type": "variable", "contract": "EtherStore", "lines": [16]}]}
SLITHER_INFO = {"check": "solc-version", "impact": "Informational", "confidence": "High", "description": "x", "elements": []}


class FakeSandbox(SandboxClient):
    def __init__(self, result=None, raise_exc=None, validate_result=None):
        super().__init__()
        self.result, self.raise_exc, self.validate_result = result, raise_exc, validate_result
        self._loaded = True

    def has_analyze(self): return True
    def has_validate(self): return self.validate_result is not None

    def analyze(self, source, filename):
        if self.raise_exc:
            raise self.raise_exc
        return self.result

    def validate(self, source, filename, finding):
        return self.validate_result


def _result(ok=True, detectors=(SLITHER_REENT, SLITHER_INFO), slither_ok=True):
    return {"ok": ok, "error": None if ok else "solc: ParserError", "solc_version": "0.8.20", "contracts": ["EtherStore"],
            "compile": {"ok": ok, "stderr": ""}, "ast": None,
            "slither": {"ok": slither_ok, "detectors": list(detectors), "error": None if slither_ok else "slither crashed"},
            "graphs": None, "resource": {"wall_s": 0.1, "max_rss_mb": 10}}


def test_map_detector():
    f = map_slither_detector(SLITHER_REENT, SourceIndex(REENTRANCY_SOL))
    assert f.vuln_class == VulnClass.reentrancy and f.severity.value == "high" and f.confidence == 0.7
    assert f.function_name == "withdraw" and f.contract_name == "EtherStore"
    assert [(r.start, r.end) for r in f.evidence.lines] == [(11, 17)] and "withdraw" in f.evidence.snippet
    assert map_slither_detector(SLITHER_INFO, SourceIndex(REENTRANCY_SOL)) is None
    unk = map_slither_detector({"check": "weird", "impact": "Low", "confidence": "Low", "elements": []}, SourceIndex("x"))
    assert unk.vuln_class == VulnClass.other


def test_analyzer_errors_honestly():
    a = SandboxAnalyzer(FakeSandbox())
    with pytest.raises(AnalyzerError):
        a.analyze(AnalysisInput("j", "a.sol", "x", "/tmp", {}))
    with pytest.raises(AnalyzerError):
        a.analyze(AnalysisInput("j", "a.sol", "x", "/tmp", {"sandbox": _result(slither_ok=False)}))


def test_unimportable_sandbox_unavailable():
    c = SandboxClient(disabled=True)
    assert not c.has_analyze() and not c.has_validate() and "disabled" in c.unavailable_reason


def test_pipeline_merges_slither_and_heuristic(tmp_path):
    sb = FakeSandbox(_result(), validate_result={"status": "confirmed", "details": "drained 10 ether in anvil"})
    s = make_settings(tmp_path)
    with TestClient(create_app(s, sandbox=sb)) as c:
        h = c.get("/api/v1/health").json()
        assert h["analyzers"]["slither"] is True and h["analyzers"]["evm_validation"] is True
        jid = submit(c).json()["job_id"]
        job = wait_done(c, jid)
        assert job["contract"]["solc_version"] == "0.8.20"
        assert any(e["stage"] == "parsing" and e["status"] == "completed" for e in job["events"])
        fs = c.get(f"/api/v1/analyses/{jid}/findings").json()["findings"]
        re_ = [f for f in fs if f["vuln_class"] == "reentrancy"]
        assert len(re_) == 1
        assert set(re_[0]["detectors"]) == {"slither", "heuristic"}
        assert abs(re_[0]["confidence"] - round(1 - 0.3 * 0.4, 4)) < 1e-9
        assert re_[0]["verification"]["evm_status"] == "confirmed"
        assert "slither@sandbox-1" in job["analyzers"] and "evm-sandbox" in job["analyzers"]


def test_pipeline_compile_failure_degrades(tmp_path):
    sb = FakeSandbox(_result(ok=False, detectors=(), slither_ok=False))
    with TestClient(create_app(make_settings(tmp_path), sandbox=sb)) as c:
        jid = submit(c).json()["job_id"]
        job = wait_done(c, jid)
        assert job["status"] == "completed" and "compilation failed" in job["error"]
        ev = job["events"]
        assert any(e["stage"] == "parsing" and e["status"] == "failed" for e in ev)
        assert any(e["stage"] == "static_analysis" and e["status"] == "failed" and (e["message"] or "").startswith("slither:") for e in ev)


def test_pipeline_sandbox_raises(tmp_path):
    sb = FakeSandbox(raise_exc=TimeoutError("child timed out"))
    with TestClient(create_app(make_settings(tmp_path), sandbox=sb)) as c:
        jid = submit(c).json()["job_id"]
        job = wait_done(c, jid)
        assert job["status"] == "completed"
        assert any("TimeoutError" in (e["message"] or "") for e in job["events"] if e["stage"] == "parsing")
