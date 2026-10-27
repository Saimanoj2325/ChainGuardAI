"""Job pipeline: received → parsing → static_analysis → ml_inference → evidence → llm_verification
→ evm_validation → reporting → done. Every stage records StageEvents; nothing is faked."""
from __future__ import annotations

import json
import logging
import os
import re
import traceback

from chainguard_contract.analyzer import AnalysisInput, AnalyzerError
from chainguard_contract.models import ContractInfo, EVMVerdict, Finding, JobStage, LLMVerdict

from .analyzers import AnalyzerRegistry
from .analyzers.sandbox import SandboxClient
from .db import Database
from .merge import merge_findings
from .registry import Registry
from .reports import build_report
from .solsrc import SourceIndex
from .verifiers import EVMValidator, LLMVerifier

log = logging.getLogger("chainguard.pipeline")

PROGRESS = {JobStage.received: 5, JobStage.parsing: 15, JobStage.static_analysis: 35, JobStage.ml_inference: 50,
            JobStage.evidence: 60, JobStage.llm_verification: 75, JobStage.evm_validation: 88,
            JobStage.reporting: 95, JobStage.done: 100}


class Pipeline:
    def __init__(self, db: Database, registry: Registry, analyzers: AnalyzerRegistry, sandbox: SandboxClient,
                 llm: LLMVerifier, evm: EVMValidator, settings):
        self.db, self.registry, self.analyzers = db, registry, analyzers
        self.sandbox, self.llm, self.evm, self.s = sandbox, llm, evm, settings

    # ---- helpers
    def _stage(self, job_id: str, stage: JobStage, status: str = "started", msg: str | None = None):
        self.db.add_event(job_id, stage.value, status, msg)
        if status == "started":
            self.db.update_job(job_id, stage=stage.value, progress=max(0, PROGRESS[stage] - 5))
        else:
            self.db.update_job(job_id, progress=PROGRESS[stage])

    def _run_analyzers(self, job_id: str, stage: JobStage, inp: AnalysisInput, used: list[str]) -> tuple[list[Finding], int, int]:
        """Returns (findings, n_ok, n_attempted). Emits per-analyzer skipped/failed events."""
        found: list[Finding] = []
        ok = attempted = 0
        for a in self.analyzers.for_stage(stage.value):
            try:
                avail = a.available()
            except Exception as e:  # noqa: BLE001
                avail = False
                self.db.add_event(job_id, stage.value, "skipped", f"{a.name}: available() raised {type(e).__name__}: {e}")
                continue
            if not avail:
                note = self.analyzers.notes.get(a.name) or getattr(getattr(a, "client", None), "unavailable_reason", "") or "not available"
                self.db.add_event(job_id, stage.value, "skipped", f"{a.name}: unavailable ({note})")
                continue
            attempted += 1
            try:
                res = a.analyze(inp)
                if not isinstance(res, list) or not all(isinstance(f, Finding) for f in res):
                    raise AnalyzerError(f"{a.name} returned a non-Finding result")
                found.extend(res)
                ok += 1
                used.append(f"{a.name}@{a.version}")
            except AnalyzerError as e:
                self.db.add_event(job_id, stage.value, "failed", f"{a.name}: {e}"[:1000])
            except Exception as e:  # noqa: BLE001 - analyzer bug; record, don't crash the job
                log.exception("analyzer %s crashed", a.name)
                self.db.add_event(job_id, stage.value, "failed", f"{a.name}: unexpected {type(e).__name__}: {e}"[:1000])
        return found, ok, attempted

    # ---- main
    def run(self, job_id: str) -> None:
        row = self.db.get_job_row(job_id)
        if row is None:
            return
        current = JobStage.received
        try:
            with open(row["source_path"], encoding="utf-8") as fh:
                source = fh.read()
            contract = ContractInfo.model_validate(json.loads(row["contract_json"]))
            workdir = os.path.dirname(row["source_path"])
            self.db.update_job(job_id, status="running")
            artifacts: dict = {}
            used: list[str] = []
            notes: list[str] = []
            idx = SourceIndex(source)

            # parsing (sandbox: solc + AST + slither)
            current = JobStage.parsing
            self._stage(job_id, current)
            if self.sandbox.has_analyze():
                try:
                    res = self.sandbox.analyze(source, contract.filename)
                    artifacts["sandbox"] = res
                    if res.get("solc_version"):
                        contract.solc_version = res["solc_version"]
                    if res.get("contracts"):
                        contract.contracts = list(res["contracts"])
                    if res.get("ok") and (res.get("compile") or {}).get("ok", True):
                        self._stage(job_id, current, "completed", f"compiled with solc {res.get('solc_version') or '?'}")
                    else:
                        err = res.get("error") or (res.get("compile") or {}).get("stderr") or "compile failed"
                        notes.append("compilation failed")
                        self._stage(job_id, current, "failed", f"sandbox: {str(err)[:800]}")
                except Exception as e:  # noqa: BLE001
                    notes.append("sandbox error")
                    self._stage(job_id, current, "failed", f"sandbox analyze() raised {type(e).__name__}: {e}"[:1000])
            else:
                self._stage(job_id, current, "skipped", f"sandbox unavailable: {self.sandbox.unavailable_reason}")
            if not contract.contracts:
                contract.contracts = idx.contract_names()
            if not contract.solc_version:
                m = re.search(r"pragma\s+solidity\s+([^;]+);", idx.masked)
                contract.solc_version = f"pragma {source[m.start(1):m.end(1)].strip()}" if m else None
            self.db.update_job(job_id, contract=contract.model_dump(mode="json"))
            inp = AnalysisInput(job_id=job_id, filename=contract.filename, source=source, workdir=workdir, artifacts=artifacts)

            # static analysis (slither adapter + heuristic)
            current = JobStage.static_analysis
            self._stage(job_id, current)
            static, ok, attempted = self._run_analyzers(job_id, current, inp, used)
            if attempted and ok == 0:
                self._stage(job_id, current, "failed", "all static analyzers failed")
                notes.append("static analysis failed")
            elif not attempted:
                self._stage(job_id, current, "skipped", "no static analyzer available")
            else:
                self._stage(job_id, current, "completed", f"{len(static)} raw findings from {ok}/{attempted} analyzers")
            artifacts["static_findings"] = [f.model_dump(mode="json") for f in static]

            # ML inference
            current = JobStage.ml_inference
            self._stage(job_id, current)
            ml, ok, attempted = self._run_analyzers(job_id, current, inp, used)
            if not attempted:
                why = self.analyzers.notes.get("ml") or "no ML analyzer registered"
                self._stage(job_id, current, "skipped", f"no ML analyzer available ({why})")
            elif ok == 0:
                self._stage(job_id, current, "failed", "ML analyzer failed")
                notes.append("ML inference failed")
            else:
                self._stage(job_id, current, "completed", f"{len(ml)} ML candidates")

            # evidence: merge/dedup + enrich
            current = JobStage.evidence
            self._stage(job_id, current)
            findings = merge_findings(static + ml)
            for f in findings:
                if not f.evidence.snippet and f.evidence.lines:
                    f.evidence.snippet = idx.snippet(f.evidence.lines[0].start, f.evidence.lines[-1].end)
                if not f.function_name and f.evidence.lines:
                    fs = idx.function_at_line(f.evidence.lines[0].start)
                    if fs:
                        f.function_name, f.contract_name = fs.name, f.contract_name or fs.contract
            self.db.replace_findings(job_id, [f.model_dump(mode="json") for f in findings])
            self.db.update_job(job_id, finding_count=len(findings))
            self._stage(job_id, current, "completed", f"{len(static) + len(ml)} raw → {len(findings)} merged findings")

            # LLM verification
            current = JobStage.llm_verification
            self._stage(job_id, current)
            if not self.llm.available():
                self._stage(job_id, current, "skipped", "no LLM API key configured (NIM_API_KEY / CG_LLM_API_KEY)")
            elif not findings:
                self._stage(job_id, current, "skipped", "no findings to verify")
            else:
                counts: dict[str, int] = {}
                for f in findings[: self.s.llm_max_findings]:
                    fs = idx.function_by_name(f.function_name, f.contract_name) or (
                        idx.function_at_line(f.evidence.lines[0].start) if f.evidence.lines else None)
                    v, exp = self.llm.verify(f, idx.function_source(fs) if fs else "")
                    f.verification.llm_status, f.verification.llm_explanation = v, exp
                    counts[v.value] = counts.get(v.value, 0) + 1
                skipped = max(0, len(findings) - self.s.llm_max_findings)
                msg = ", ".join(f"{k}={n}" for k, n in sorted(counts.items())) + (f"; {skipped} not run (cap)" if skipped else "")
                used.append(f"llm@{self.llm.version}")
                if counts.get("error") == sum(counts.values()):
                    self._stage(job_id, current, "failed", f"all LLM calls errored: {msg}")
                else:
                    self._stage(job_id, current, "completed", msg)
                self.db.replace_findings(job_id, [f.model_dump(mode="json") for f in findings])

            # EVM validation
            current = JobStage.evm_validation
            self._stage(job_id, current)
            if not self.evm.available():
                self._stage(job_id, current, "skipped", "EVM validation unavailable (sandbox validate() not installed)")
            elif not findings:
                self._stage(job_id, current, "skipped", "no findings to validate")
            else:
                counts = {}
                for f in findings[: self.s.evm_max_findings]:
                    v, det = self.evm.validate(source, contract.filename, f)
                    f.verification.evm_status, f.verification.evm_details = v, det
                    counts[v.value] = counts.get(v.value, 0) + 1
                used.append("evm-sandbox")
                self._stage(job_id, current, "completed", ", ".join(f"{k}={n}" for k, n in sorted(counts.items())))
                self.db.replace_findings(job_id, [f.model_dump(mode="json") for f in findings])

            # reporting
            current = JobStage.reporting
            self._stage(job_id, current)
            self.db.update_job(job_id, analyzers=used)
            rep = build_report(job_id, contract, used, findings, self.registry)
            self.db.save_report(job_id, rep["report_id"], rep["report_hash"], rep)
            self._stage(job_id, current, "completed",
                        f"report_hash {rep['report_hash'][:16]}… registered at index {rep['registry']['index']}")

            self.db.add_event(job_id, JobStage.done.value, "completed", ("degraded: " + "; ".join(notes)) if notes else None)
            self.db.update_job(job_id, status="completed", stage=JobStage.done.value, progress=100,
                               error=("degraded: " + "; ".join(notes)) if notes else None)
        except Exception as e:  # noqa: BLE001
            log.error("job %s failed in %s: %s\n%s", job_id, current.value, e, traceback.format_exc())
            self.db.add_event(job_id, current.value, "failed", f"{type(e).__name__}: {e}"[:1000])
            self.db.update_job(job_id, status="failed", error=f"stage {current.value} failed: {type(e).__name__}: {e}"[:1000])
