"""Exports the contract models as an OpenAPI 3.1 document at contracts/openapi.json (paths are spec'd here)."""
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from fastapi import FastAPI, UploadFile, File, Query
from chainguard_contract.models import *  # noqa

app = FastAPI(title="ChainGuard AI API", version=CONTRACT_VERSION)
E = {400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 413: {"model": ErrorResponse}, 422: {"model": ErrorResponse}}

@app.get("/api/v1/health", response_model=Health)
def health(): ...
@app.post("/api/v1/analyses", response_model=SubmitResponse, status_code=202, responses=E,
          summary="Submit a Solidity file (multipart field 'file', .sol, <=512KiB)")
def submit(file: UploadFile = File(...)): ...
@app.get("/api/v1/analyses/{job_id}", response_model=Job, responses=E)
def get_job(job_id: str): ...
@app.get("/api/v1/analyses/{job_id}/findings", response_model=FindingsResponse, responses=E)
def findings(job_id: str, severity: list[Severity] | None = Query(None)): ...
@app.get("/api/v1/analyses/{job_id}/report", response_model=AuditReport, responses=E,
         summary="JSON report; ?format=markdown returns text/markdown")
def report(job_id: str, format: str = "json"): ...
@app.post("/api/v1/reports/verify", response_model=VerifyResponse, responses=E)
def verify(req: VerifyRequest): ...

if __name__ == "__main__":
    out = pathlib.Path(__file__).parent.parent / "contracts" / "openapi.json"
    out.write_text(json.dumps(app.openapi(), indent=2))
    print("wrote", out)
