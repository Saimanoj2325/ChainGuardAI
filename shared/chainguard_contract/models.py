from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Literal, Optional
from pydantic import BaseModel, Field

CONTRACT_VERSION = "1.0.0"
MAX_UPLOAD_BYTES = 512 * 1024  # 512 KiB per .sol file


class JobStatus(str, Enum):
    queued = "queued"; running = "running"; completed = "completed"; failed = "failed"


class JobStage(str, Enum):
    received = "received"; parsing = "parsing"; static_analysis = "static_analysis"
    ml_inference = "ml_inference"; evidence = "evidence"; llm_verification = "llm_verification"
    evm_validation = "evm_validation"; reporting = "reporting"; done = "done"


class Severity(str, Enum):
    critical = "critical"; high = "high"; medium = "medium"; low = "low"; info = "info"


class VulnClass(str, Enum):
    reentrancy = "reentrancy"; unchecked_call = "unchecked_call"; tx_origin = "tx_origin"
    timestamp_dependence = "timestamp_dependence"; integer_overflow = "integer_overflow"
    access_control = "access_control"; delegatecall = "delegatecall"
    unprotected_selfdestruct = "unprotected_selfdestruct"; denial_of_service = "denial_of_service"
    bad_randomness = "bad_randomness"; other = "other"


class DetectorSource(str, Enum):
    slither = "slither"; heuristic = "heuristic"; gnn = "gnn"; baseline_ml = "baseline_ml"
    llm = "llm"; mock = "mock"


class LineRange(BaseModel):
    start: int = Field(ge=1); end: int = Field(ge=1)


class Evidence(BaseModel):
    lines: list[LineRange] = []
    snippet: str = ""
    graph_nodes: list[str] = []          # e.g. "CFG:withdraw#3", "DFG:balances"
    dependency_path: list[str] = []      # ordered human-readable steps
    tool_output: Optional[str] = None    # raw detector message, truncated


class LLMVerdict(str, Enum):
    not_run = "not_run"; supported = "supported"; refuted = "refuted"; uncertain = "uncertain"; error = "error"


class EVMVerdict(str, Enum):
    not_run = "not_run"; confirmed = "confirmed"; not_reproduced = "not_reproduced"
    not_applicable = "not_applicable"; error = "error"


class Verification(BaseModel):
    llm_status: LLMVerdict = LLMVerdict.not_run
    llm_explanation: Optional[str] = None
    evm_status: EVMVerdict = EVMVerdict.not_run
    evm_details: Optional[str] = None


class Finding(BaseModel):
    id: str
    vuln_class: VulnClass
    title: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    detectors: list[DetectorSource]
    contract_name: Optional[str] = None
    function_name: Optional[str] = None
    description: str
    recommendation: Optional[str] = None
    evidence: Evidence = Evidence()
    verification: Verification = Verification()
    is_mock: bool = False  # MUST be true for any synthetic/mock finding


class ContractInfo(BaseModel):
    filename: str
    sha256: str
    size_bytes: int
    solc_version: Optional[str] = None
    contracts: list[str] = []


class SubmitResponse(BaseModel):
    job_id: str
    status: JobStatus
    contract: ContractInfo


class StageEvent(BaseModel):
    stage: JobStage
    status: Literal["started", "completed", "skipped", "failed"]
    at: datetime
    message: Optional[str] = None


class Job(BaseModel):
    job_id: str
    status: JobStatus
    stage: JobStage
    progress: int = Field(ge=0, le=100)
    created_at: datetime
    updated_at: datetime
    contract: ContractInfo
    analyzers: list[str] = []            # analyzer plugin names+versions used
    events: list[StageEvent] = []
    error: Optional[str] = None
    finding_count: Optional[int] = None


class FindingsResponse(BaseModel):
    job_id: str
    findings: list[Finding]


class SeverityCounts(BaseModel):
    critical: int = 0; high: int = 0; medium: int = 0; low: int = 0; info: int = 0


class RegistryEntry(BaseModel):
    """Entry in the append-only hash-chained audit registry (local ledger; not a public blockchain)."""
    index: int
    report_hash: str
    prev_entry_hash: str
    entry_hash: str
    timestamp: datetime


class AuditReport(BaseModel):
    report_id: str
    job_id: str
    schema_version: str = CONTRACT_VERSION
    generated_at: datetime
    contract: ContractInfo
    analyzers: list[str]
    summary: SeverityCounts
    findings: list[Finding]
    contains_mock_data: bool = False
    report_hash: str  # sha256 hex over canonical JSON of report EXCLUDING report_hash and registry
    registry: Optional[RegistryEntry] = None


class VerifyRequest(BaseModel):
    report: Optional[dict] = None      # full report JSON as downloaded
    report_hash: Optional[str] = None  # or just the hash


class VerifyResponse(BaseModel):
    valid: bool
    recomputed_hash: Optional[str] = None
    claimed_hash: Optional[str] = None
    registered: bool
    registry: Optional[RegistryEntry] = None
    chain_intact: bool
    reason: str


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None


class Health(BaseModel):
    status: Literal["ok", "degraded"]
    contract_version: str = CONTRACT_VERSION
    analyzers: dict[str, bool]  # analyzer name -> available
