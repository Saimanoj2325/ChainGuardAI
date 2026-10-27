from chainguard_contract.models import DetectorSource, Evidence, Finding, LineRange, Severity, VulnClass

from app.merge import combine_confidence, merge_findings, merge_ranges


def F(vc=VulnClass.reentrancy, lines=((10, 12),), det=DetectorSource.heuristic, conf=0.6, sev=Severity.high, fn="withdraw"):
    return Finding(id="", vuln_class=vc, title=f"{vc.value} {det.value}", severity=sev, confidence=conf, detectors=[det],
                   function_name=fn, description="d",
                   evidence=Evidence(lines=[LineRange(start=a, end=b) for a, b in lines], dependency_path=[det.value],
                                     tool_output=det.value))


def test_overlap_merges_and_unions_detectors():
    out = merge_findings([F(), F(lines=((12, 14),), det=DetectorSource.slither, conf=0.9, sev=Severity.critical)])
    assert len(out) == 1
    m = out[0]
    assert set(m.detectors) == {DetectorSource.heuristic, DetectorSource.slither}
    assert m.severity == Severity.critical
    assert abs(m.confidence - (1 - 0.4 * 0.1)) < 1e-9
    assert [(r.start, r.end) for r in m.evidence.lines] == [(10, 14)]
    assert m.id == "F001" and m.title.endswith("slither")


def test_different_class_or_lines_kept_apart():
    out = merge_findings([F(), F(vc=VulnClass.unchecked_call), F(lines=((30, 31),))])
    assert len(out) == 3
    assert [f.id for f in out] == ["F001", "F002", "F003"]


def test_same_detector_not_double_counted():
    assert combine_confidence([F(conf=0.6), F(conf=0.5)]) == 0.6


def test_confidence_capped():
    assert combine_confidence([F(conf=1.0), F(det=DetectorSource.slither, conf=1.0)]) == 0.99


def test_no_lines_same_function_merges():
    out = merge_findings([F(lines=()), F(lines=(), det=DetectorSource.gnn)])
    assert len(out) == 1 and len(out[0].detectors) == 2


def test_bridging_fuses_groups():
    out = merge_findings([F(lines=((1, 2),)), F(lines=((5, 6),)), F(lines=((2, 5),), det=DetectorSource.slither)])
    assert len(out) == 1


def test_merge_ranges():
    rs = merge_ranges([LineRange(start=5, end=6), LineRange(start=1, end=2), LineRange(start=3, end=3)])
    assert [(r.start, r.end) for r in rs] == [(1, 3), (5, 6)]
