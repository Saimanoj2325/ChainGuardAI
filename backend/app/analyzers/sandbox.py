"""Adapters for Agent 4's sandbox package (`sandbox/chainguard_sandbox/api.py`, see docs/INTEGRATION.md).

* SandboxClient: lazily imports chainguard_sandbox.api; available() is False if the import fails.
* SandboxAnalyzer: maps the sandbox's Slither detector output (already computed in the parsing stage and
  passed via AnalysisInput.artifacts["sandbox"]) to contract Findings with detectors=[slither].
"""
from __future__ import annotations

import importlib
import logging

from chainguard_contract.analyzer import AnalysisInput, AnalyzerError
from chainguard_contract.models import DetectorSource, Evidence, Finding, LineRange, Severity, VulnClass

from ..solsrc import SourceIndex

log = logging.getLogger("chainguard.sandbox")

SLITHER_CLASS: dict[str, VulnClass] = {
    "reentrancy-eth": VulnClass.reentrancy, "reentrancy-no-eth": VulnClass.reentrancy,
    "reentrancy-benign": VulnClass.reentrancy, "reentrancy-events": VulnClass.reentrancy,
    "reentrancy-unlimited-gas": VulnClass.reentrancy,
    "unchecked-lowlevel": VulnClass.unchecked_call, "unchecked-send": VulnClass.unchecked_call,
    "unchecked-transfer": VulnClass.unchecked_call, "unused-return": VulnClass.unchecked_call,
    "tx-origin": VulnClass.tx_origin,
    "timestamp": VulnClass.timestamp_dependence,
    "weak-prng": VulnClass.bad_randomness,
    "controlled-delegatecall": VulnClass.delegatecall, "delegatecall-loop": VulnClass.delegatecall,
    "suicidal": VulnClass.unprotected_selfdestruct,
    "arbitrary-send-eth": VulnClass.access_control, "arbitrary-send-erc20": VulnClass.access_control,
    "arbitrary-send-erc20-permit": VulnClass.access_control, "unprotected-upgrade": VulnClass.access_control,
    "protected-vars": VulnClass.access_control,
    "calls-loop": VulnClass.denial_of_service, "msg-value-loop": VulnClass.denial_of_service,
    "costly-loop": VulnClass.denial_of_service, "locked-ether": VulnClass.denial_of_service,
}
IMPACT_SEVERITY = {"high": Severity.high, "medium": Severity.medium, "low": Severity.low,
                   "informational": Severity.info, "optimization": Severity.info}
CONFIDENCE = {"high": 0.9, "medium": 0.7, "low": 0.5}
# Slither impact levels reported as findings (informational/optimization are style noise for an audit report)
REPORTED_IMPACTS = {"high", "medium", "low"}
SEVERITY_OVERRIDE = {VulnClass.unprotected_selfdestruct: Severity.critical}


class SandboxClient:
    def __init__(self, disabled: bool = False, timeout_s: int = 60):
        self.disabled, self.timeout_s = disabled, timeout_s
        self._api = None
        self._err: str | None = None
        self._loaded = False

    def _load(self):
        if self._loaded:
            return self._api
        self._loaded = True
        if self.disabled:
            self._err = "sandbox disabled by CG_DISABLE_SANDBOX"
            return None
        try:
            self._api = importlib.import_module("chainguard_sandbox.api")
        except Exception as e:  # noqa: BLE001 - any import problem means unavailable
            self._err = f"chainguard_sandbox not importable: {type(e).__name__}: {e}"
            log.info(self._err)
            self._api = None
        return self._api

    @property
    def unavailable_reason(self) -> str:
        self._load()
        return self._err or ""

    def has_analyze(self) -> bool:
        api = self._load()
        return api is not None and callable(getattr(api, "analyze", None))

    def has_validate(self) -> bool:
        api = self._load()
        return api is not None and callable(getattr(api, "validate", None))

    def analyze(self, source: str, filename: str) -> dict:
        return self._load().analyze(source, filename, timeout_s=self.timeout_s)

    def validate(self, source: str, filename: str, finding: dict) -> dict:
        return self._load().validate(source, filename, finding, timeout_s=self.timeout_s)


def _lines_of(elements: list[dict]) -> list[int]:
    out: list[int] = []
    for el in elements or []:
        for ln in el.get("lines") or []:
            if isinstance(ln, int) and ln >= 1:
                out.append(ln)
    return sorted(set(out))


def _ranges(lines: list[int]) -> list[tuple[int, int]]:
    rs: list[list[int]] = []
    for ln in lines:
        if rs and ln <= rs[-1][1] + 1:
            rs[-1][1] = ln
        else:
            rs.append([ln, ln])
    return [(a, b) for a, b in rs]


def map_slither_detector(det: dict, idx: SourceIndex) -> Finding | None:
    check = str(det.get("check", "")).strip()
    impact = str(det.get("impact", "")).strip().lower()
    if impact not in REPORTED_IMPACTS:
        return None
    vc = SLITHER_CLASS.get(check, VulnClass.other)
    sev = SEVERITY_OVERRIDE.get(vc, IMPACT_SEVERITY.get(impact, Severity.low))
    conf = CONFIDENCE.get(str(det.get("confidence", "")).strip().lower(), 0.5)
    elements = det.get("elements") or []
    fn_el = next((e for e in elements if e.get("type") == "function"), None)
    function = (fn_el or {}).get("name") or next((e.get("function") for e in elements if e.get("function")), None)
    contract = next((e.get("contract") for e in elements if e.get("contract")), None)
    lines = _lines_of(elements)
    ranges = _ranges(lines)[:20]
    snippet = idx.snippet(ranges[0][0], ranges[-1][1]) if ranges else ""
    desc = str(det.get("description") or check).strip()
    return Finding(
        id="", vuln_class=vc, title=f"Slither {check}" + (f" in {function}()" if function else ""), severity=sev,
        confidence=conf, detectors=[DetectorSource.slither], contract_name=contract, function_name=function,
        description=desc[:2000], recommendation=None,
        evidence=Evidence(lines=[LineRange(start=a, end=b) for a, b in ranges], snippet=snippet,
                          dependency_path=[f"{e.get('type', '?')}:{e.get('name', '?')}" for e in elements][:20],
                          tool_output=f"slither {check} (impact={impact}, confidence={det.get('confidence')}): {desc}"[:1500]))


class SandboxAnalyzer:
    name = "slither"
    version = "sandbox-1"
    stage = "static_analysis"

    def __init__(self, client: SandboxClient):
        self.client = client

    def available(self) -> bool:
        return self.client.has_analyze()

    def analyze(self, inp: AnalysisInput) -> list[Finding]:
        res = inp.artifacts.get("sandbox")
        if res is None:
            raise AnalyzerError("sandbox parse result missing (parsing stage did not run)")
        sl = res.get("slither") or {}
        if not sl.get("ok"):
            raise AnalyzerError(f"slither failed: {sl.get('error') or res.get('error') or 'unknown error'}")
        idx = SourceIndex(inp.source)
        out = []
        for det in sl.get("detectors") or []:
            try:
                f = map_slither_detector(det, idx)
            except Exception as e:  # malformed detector entry; skip but don't invent
                log.warning("skipping malformed slither detector %r: %s", det.get("check"), e)
                continue
            if f:
                out.append(f)
        return out
