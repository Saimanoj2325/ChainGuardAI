"""Finding merge/dedup across analyzers.

Two findings are the same issue when they have the same vuln_class AND either
  (a) any of their evidence line ranges overlap, or
  (b) neither has line evidence and they name the same (contract, function).
Merged finding: detectors = ordered union; severity = max; title/description/recommendation from the
highest-confidence member (others' tool output appended to evidence.tool_output); evidence lines = union
(merged ranges); dependency_path = ordered union; contract/function = first non-null.
Confidence = noisy-OR of members: 1 - Π(1 - c_i), capped at 0.99 — independent detectors agreeing raises
confidence, but never to certainty. Findings from the SAME detector are not double-counted: for each detector
only its max confidence enters the product.
"""
from __future__ import annotations

from chainguard_contract.models import Evidence, Finding, LineRange, Severity

SEV_RANK = {Severity.info: 0, Severity.low: 1, Severity.medium: 2, Severity.high: 3, Severity.critical: 4}


def _overlap(a: list[LineRange], b: list[LineRange]) -> bool:
    return any(x.start <= y.end and y.start <= x.end for x in a for y in b)


def same_issue(a: Finding, b: Finding) -> bool:
    if a.vuln_class != b.vuln_class:
        return False
    if a.evidence.lines and b.evidence.lines:
        return _overlap(a.evidence.lines, b.evidence.lines)
    if not a.evidence.lines and not b.evidence.lines:
        return bool(a.function_name) and a.function_name == b.function_name and a.contract_name == b.contract_name
    return False


def merge_ranges(rs: list[LineRange]) -> list[LineRange]:
    out: list[list[int]] = []
    for r in sorted(rs, key=lambda r: (r.start, r.end)):
        if out and r.start <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], r.end)
        else:
            out.append([r.start, r.end])
    return [LineRange(start=a, end=b) for a, b in out]


def combine_confidence(members: list[Finding]) -> float:
    best: dict[str, float] = {}
    for m in members:
        key = "+".join(sorted(d.value for d in m.detectors))
        best[key] = max(best.get(key, 0.0), m.confidence)
    p = 1.0
    for c in best.values():
        p *= (1.0 - c)
    return round(min(0.99, 1.0 - p), 4) if len(members) > 1 else members[0].confidence


def _combine(group: list[Finding]) -> Finding:
    if len(group) == 1:
        return group[0].model_copy(deep=True)
    lead = max(group, key=lambda f: (f.confidence, SEV_RANK[f.severity]))
    detectors, dep, tools = [], [], []
    for f in group:
        for d in f.detectors:
            if d not in detectors:
                detectors.append(d)
        for s in f.evidence.dependency_path:
            if s not in dep:
                dep.append(s)
        if f.evidence.tool_output and f.evidence.tool_output not in tools:
            tools.append(f.evidence.tool_output)
    lines = merge_ranges([r for f in group for r in f.evidence.lines])
    ev = Evidence(lines=lines, snippet=lead.evidence.snippet,
                  graph_nodes=list(dict.fromkeys(n for f in group for n in f.evidence.graph_nodes)),
                  dependency_path=dep, tool_output=(" | ".join(tools))[:3000] or None)
    return lead.model_copy(update={
        "detectors": detectors,
        "severity": max((f.severity for f in group), key=lambda s: SEV_RANK[s]),
        "confidence": combine_confidence(group),
        "contract_name": next((f.contract_name for f in group if f.contract_name), None),
        "function_name": next((f.function_name for f in group if f.function_name), None),
        "evidence": ev,
        "is_mock": any(f.is_mock for f in group),
    }, deep=True)


def merge_findings(findings: list[Finding]) -> list[Finding]:
    groups: list[list[Finding]] = []
    for f in findings:
        hit = [g for g in groups if any(same_issue(f, m) for m in g)]
        if not hit:
            groups.append([f])
        else:  # f may bridge several groups → fuse them
            base = hit[0]
            base.append(f)
            for g in hit[1:]:
                base.extend(g)
                groups.remove(g)
    merged = [_combine(g) for g in groups]
    merged.sort(key=lambda f: (-SEV_RANK[f.severity], -f.confidence,
                               f.evidence.lines[0].start if f.evidence.lines else 10**9, f.vuln_class.value))
    return [m.model_copy(update={"id": f"F{i + 1:03d}"}) for i, m in enumerate(merged)]
