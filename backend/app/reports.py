"""Report building, Markdown rendering and verification."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from chainguard_contract.hashing import report_hash as compute_report_hash
from chainguard_contract.models import (AuditReport, ContractInfo, Finding, RegistryEntry, SeverityCounts,
                                        VerifyRequest, VerifyResponse)

from .errors import APIError
from .registry import Registry, compute_entry_hash, timestamp_iso

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def build_report(job_id: str, contract: ContractInfo, analyzers: list[str], findings: list[Finding],
                 registry: Registry) -> dict:
    counts = SeverityCounts()
    for f in findings:
        setattr(counts, f.severity.value, getattr(counts, f.severity.value) + 1)
    rep = AuditReport(report_id=f"R-{job_id}", job_id=job_id, generated_at=datetime.now(timezone.utc).replace(microsecond=0),
                      contract=contract, analyzers=analyzers, summary=counts, findings=findings,
                      contains_mock_data=any(f.is_mock for f in findings), report_hash="0" * 64, registry=None)
    d = rep.model_dump(mode="json")
    h = compute_report_hash(d)
    d["report_hash"] = h
    entry = registry.append(h)
    d["registry"] = entry.model_dump(mode="json")
    AuditReport.model_validate(d)  # sanity: stored report conforms to the contract
    return d


def verify(req: VerifyRequest, registry: Registry) -> VerifyResponse:
    if req.report is None and not req.report_hash:
        raise APIError(400, "missing_input", "Provide either `report` (full report JSON) or `report_hash`.")
    chain = registry.verify_chain()
    if req.report is not None:
        rep = req.report
        claimed = rep.get("report_hash")
        recomputed = compute_report_hash(rep)
        if req.report_hash and claimed and req.report_hash.lower() != str(claimed).lower():
            claimed_note = " (note: supplied report_hash differs from the report's own report_hash)"
        else:
            claimed_note = ""
        claimed = str(claimed).lower() if isinstance(claimed, str) else (req.report_hash.lower() if req.report_hash else None)
        entry = registry.find_by_report_hash(recomputed)
        registered = entry is not None
        reasons = []
        if claimed is None:
            reasons.append("report has no report_hash to check against")
        elif claimed != recomputed:
            reasons.append("report content does not match its report_hash (report was modified after hashing)")
        if not registered:
            reasons.append("recomputed hash is not in the registry")
        if registered and isinstance(rep.get("registry"), dict):
            try:
                supplied = RegistryEntry.model_validate(rep["registry"])
                if supplied.model_dump(mode="json") != entry.model_dump(mode="json"):
                    reasons.append("report's embedded registry entry does not match the ledger")
            except Exception:  # noqa: BLE001
                reasons.append("report's embedded registry entry is malformed")
        if not chain.intact:
            reasons.append(f"registry chain broken: {chain.reason}")
        valid = not reasons
        reason = ("report hash matches content, is registered at index "
                  f"{entry.index}, and the registry chain is intact") if valid else "; ".join(reasons)
        return VerifyResponse(valid=valid, recomputed_hash=recomputed, claimed_hash=claimed, registered=registered,
                              registry=entry, chain_intact=chain.intact, reason=reason + claimed_note)
    h = req.report_hash.strip().lower()
    if not HEX64.match(h):
        raise APIError(400, "invalid_hash", "report_hash must be 64 lowercase hex characters (sha256).")
    entry = registry.find_by_report_hash(h)
    reasons = []
    if entry is None:
        reasons.append("hash is not in the registry")
    if not chain.intact:
        reasons.append(f"registry chain broken: {chain.reason}")
    valid = not reasons
    reason = (f"hash is registered at index {entry.index} and the registry chain is intact (content not re-checked: "
              "no report supplied)") if valid else "; ".join(reasons)
    return VerifyResponse(valid=valid, recomputed_hash=None, claimed_hash=h, registered=entry is not None,
                          registry=entry, chain_intact=chain.intact, reason=reason)


def _md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def render_markdown(rep: dict) -> str:
    r = AuditReport.model_validate(rep)
    c = r.contract
    out = [f"# ChainGuard AI Audit Report — {c.filename}", ""]
    if r.contains_mock_data:
        out += ["> **MOCK DATA** — this report contains synthetic findings and is not a real audit.", ""]
    out += [
        f"- **Report ID:** `{r.report_id}`  ", f"- **Job ID:** `{r.job_id}`  ",
        f"- **Generated:** {timestamp_iso(r.generated_at)}  ", f"- **Schema version:** {r.schema_version}  ",
        f"- **File SHA-256:** `{c.sha256}` ({c.size_bytes} bytes)  ",
        f"- **Solidity:** {c.solc_version or 'unknown'}; contracts: {', '.join(c.contracts) or 'n/a'}  ",
        f"- **Analyzers:** {', '.join(r.analyzers) or 'none'}", "",
        "## Summary", "", "| Critical | High | Medium | Low | Info |", "|---|---|---|---|---|",
        f"| {r.summary.critical} | {r.summary.high} | {r.summary.medium} | {r.summary.low} | {r.summary.info} |", "",
        "## Findings", "",
    ]
    if not r.findings:
        out += ["No findings were reported by the analyzers that ran. This is not a guarantee of security.", ""]
    for f in r.findings:
        lines = ", ".join(f"L{x.start}" if x.start == x.end else f"L{x.start}–{x.end}" for x in f.evidence.lines) or "n/a"
        v = f.verification
        out += [
            f"### {f.id} · {f.severity.value.upper()} · {f.title}", "",
            f"- **Class:** {f.vuln_class.value} · **Confidence:** {f.confidence:.2f} · **Detectors:** {', '.join(d.value for d in f.detectors)}",
            f"- **Location:** {f.contract_name or '?'}.{f.function_name or '?'} ({lines})",
            f"- **LLM verification:** {v.llm_status.value}" + (f" — {_md_escape(v.llm_explanation)}" if v.llm_explanation else ""),
            f"- **EVM validation:** {v.evm_status.value}" + (f" — {_md_escape(v.evm_details)}" if v.evm_details else ""),
        ]
        if f.is_mock:
            out.append("- **MOCK finding**")
        out += ["", f.description, ""]
        if f.recommendation:
            out += [f"**Recommendation:** {f.recommendation}", ""]
        if f.evidence.dependency_path:
            out += ["**Evidence path:**", ""] + [f"1. {s}" for s in f.evidence.dependency_path] + [""]
        if f.evidence.snippet:
            out += ["```solidity", f.evidence.snippet, "```", ""]
    out += ["## Integrity", "", f"- **report_hash (sha256):** `{r.report_hash}`"]
    if r.registry:
        e = r.registry
        out += [f"- **Registry index:** {e.index}", f"- **entry_hash:** `{e.entry_hash}`",
                f"- **prev_entry_hash:** `{e.prev_entry_hash}`", f"- **timestamp:** {timestamp_iso(e.timestamp)}"]
    out += ["", "_Registry: local append-only hash chain kept by this ChainGuard instance — not a public blockchain. "
            "Verify via `POST /api/v1/reports/verify`._", ""]
    return "\n".join(out)


__all__ = ["build_report", "verify", "render_markdown", "compute_entry_hash"]
