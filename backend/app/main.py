"""FastAPI app factory. Run: uvicorn app.main:app --app-dir backend"""
from __future__ import annotations

import hmac
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from chainguard_contract.models import (CONTRACT_VERSION, AuditReport, ContractInfo, ErrorResponse, Finding,
                                        FindingsResponse, Health, Job, JobStatus, Severity, StageEvent,
                                        SubmitResponse, VerifyRequest, VerifyResponse)

from .analyzers import AnalyzerRegistry
from .analyzers.heuristic import HeuristicAnalyzer
from .analyzers.ml import load_ml_analyzer
from .analyzers.sandbox import SandboxAnalyzer, SandboxClient
from .config import Settings
from .db import Database
from .errors import APIError, error_json, install as install_errors
from .pipeline import Pipeline
from .registry import Registry
from .reports import render_markdown, verify as verify_report
from .validation import validate_upload
from .verifiers import EVMValidator, LLMVerifier
from .worker import JobWorker, QueueFull

log = logging.getLogger("chainguard")
E = {400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 413: {"model": ErrorResponse},
     422: {"model": ErrorResponse}}
API = "/api/v1"
PUBLIC_PATHS = {f"{API}/health"}
MULTIPART_OVERHEAD = 16 * 1024


def default_registry(settings: Settings, sandbox: SandboxClient) -> AnalyzerRegistry:
    reg = AnalyzerRegistry()
    reg.register(SandboxAnalyzer(sandbox))
    reg.register(HeuristicAnalyzer())
    ml, why = load_ml_analyzer(settings.disable_ml)
    if ml is not None:
        try:
            reg.register(ml)
        except TypeError as e:
            reg.notes["ml"] = str(e)
    else:
        reg.notes["ml"] = why
    return reg


def _job_model(db: Database, row) -> Job:
    return Job(job_id=row["job_id"], status=row["status"], stage=row["stage"], progress=row["progress"],
               created_at=row["created_at"], updated_at=row["updated_at"],
               contract=ContractInfo.model_validate(json.loads(row["contract_json"])),
               analyzers=json.loads(row["analyzers_json"] or "[]"),
               events=[StageEvent(stage=e["stage"], status=e["status"], at=e["at"], message=e["message"]) for e in db.events(row["job_id"])],
               error=row["error"], finding_count=row["finding_count"])


def recover_jobs(db: Database, worker: JobWorker) -> None:
    for r in db.jobs_with_status("running"):
        db.add_event(r["job_id"], r["stage"], "failed", "interrupted by server restart")
        db.update_job(r["job_id"], status="failed", error="interrupted by server restart; resubmit the file")
    for r in db.jobs_with_status("queued"):
        try:
            worker.submit(r["job_id"])
        except QueueFull:
            db.update_job(r["job_id"], status="failed", error="queue full after restart; resubmit the file")


def create_app(settings: Settings | None = None, analyzers: AnalyzerRegistry | None = None,
               sandbox: SandboxClient | None = None, llm: LLMVerifier | None = None,
               evm: EVMValidator | None = None, start_workers: bool = True) -> FastAPI:
    s = settings or Settings()
    os.makedirs(os.path.join(s.data_dir, "jobs"), exist_ok=True)
    db = Database(os.path.join(s.data_dir, "chainguard.sqlite3"))
    registry = Registry(db)
    sandbox = sandbox or SandboxClient(disabled=s.disable_sandbox, timeout_s=s.sandbox_timeout_s)
    analyzers = analyzers or default_registry(s, sandbox)
    llm = llm or LLMVerifier(s)
    evm = evm or EVMValidator(sandbox)
    pipeline = Pipeline(db, registry, analyzers, sandbox, llm, evm, s)
    worker = JobWorker(pipeline.run, s.workers, s.queue_max)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if start_workers:
            worker.start()
            recover_jobs(db, worker)
        yield
        worker.stop()

    app = FastAPI(title="ChainGuard AI API", version=CONTRACT_VERSION, lifespan=lifespan)
    app.state.settings, app.state.db, app.state.registry = s, db, registry
    app.state.analyzers, app.state.pipeline, app.state.worker = analyzers, pipeline, worker
    install_errors(app)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if s.api_key and request.method != "OPTIONS" and path not in PUBLIC_PATHS:
            supplied = request.headers.get("x-api-key", "")
            if not hmac.compare_digest(supplied.encode(), s.api_key.encode()):
                return error_json(401, "unauthorized", "Missing or invalid X-API-Key header.")
        if request.method == "POST" and path == f"{API}/analyses":
            cl = request.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > s.max_upload_bytes + MULTIPART_OVERHEAD:
                return error_json(413, "payload_too_large", f"Request exceeds the {s.max_upload_bytes}-byte file limit.")
        return await call_next(request)

    # added after `guard` so CORS is the outermost layer (401/413 responses still carry CORS headers)
    app.add_middleware(CORSMiddleware, allow_origins=s.cors_origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"])

    @app.get(f"{API}/health", response_model=Health)
    def health():
        av = analyzers.availability()
        av["llm"] = llm.available()
        av["evm_validation"] = evm.available()
        core_ok = av.get("heuristic", False) or av.get("slither", False)
        return Health(status="ok" if core_ok and all(av.values()) else "degraded", analyzers=av)

    @app.post(f"{API}/analyses", response_model=SubmitResponse, status_code=202, responses=E,
              summary="Submit a Solidity file (multipart field 'file', .sol, <=512KiB)")
    async def submit(file: UploadFile = File(...)):
        raw = await file.read(s.max_upload_bytes + 1)
        up = validate_upload(file.filename, raw, s.max_upload_bytes)
        job_id = uuid.uuid4().hex
        jdir = os.path.join(s.data_dir, "jobs", job_id)
        os.makedirs(jdir, mode=0o700)
        path = os.path.join(jdir, "contract.sol")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(up.source)
        contract = ContractInfo(filename=up.filename, sha256=up.sha256, size_bytes=up.size_bytes)
        db.create_job(job_id, contract.model_dump(mode="json"), path)
        db.add_event(job_id, "received", "completed", f"{up.size_bytes} bytes, sha256 {up.sha256[:16]}…")
        db.update_job(job_id, progress=5)
        try:
            worker.submit(job_id)
        except QueueFull:
            db.update_job(job_id, status="failed", error="job queue full")
            raise APIError(503, "queue_full", "The analysis queue is full; retry later.")
        return SubmitResponse(job_id=job_id, status=JobStatus.queued, contract=contract)

    def _row(job_id: str):
        row = db.get_job_row(job_id) if len(job_id) <= 64 else None
        if row is None:
            raise APIError(404, "job_not_found", f"No analysis job with id {job_id!r}.")
        return row

    @app.get(f"{API}/analyses/{{job_id}}", response_model=Job, responses=E)
    def get_job(job_id: str):
        return _job_model(db, _row(job_id))

    @app.get(f"{API}/analyses/{{job_id}}/findings", response_model=FindingsResponse, responses=E)
    def findings(job_id: str, severity: list[Severity] | None = Query(None)):
        _row(job_id)
        fs = [Finding.model_validate(f) for f in db.findings(job_id)]
        if severity:
            wanted = set(severity)
            fs = [f for f in fs if f.severity in wanted]
        return FindingsResponse(job_id=job_id, findings=fs)

    @app.get(f"{API}/analyses/{{job_id}}/report", response_model=AuditReport, responses=E,
             summary="JSON report; ?format=markdown returns text/markdown")
    def report(job_id: str, format: str = "json"):
        if format not in ("json", "markdown", "md"):
            raise APIError(400, "invalid_format", "format must be 'json' or 'markdown'.")
        row = _row(job_id)
        rep = db.get_report(job_id)
        if rep is None:
            raise APIError(404, "report_not_ready", f"Job is {row['status']} (stage {row['stage']}); the report is "
                           "available once the job completes." if row["status"] != "failed" else
                           f"Job failed before a report was produced: {row['error']}")
        if format in ("markdown", "md"):
            return Response(render_markdown(rep), media_type="text/markdown; charset=utf-8",
                            headers={"Content-Disposition": f'inline; filename="{rep["report_id"]}.md"'})
        # return the stored JSON verbatim so the bytes hashed are exactly the bytes served
        return JSONResponse(rep)

    @app.post(f"{API}/reports/verify", response_model=VerifyResponse, responses=E)
    def verify(req: VerifyRequest):
        return verify_report(req, registry)

    return app


app = create_app()
