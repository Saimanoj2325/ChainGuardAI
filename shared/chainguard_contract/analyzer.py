"""Pluggable analyzer interface. Backend runs every registered Analyzer; each returns findings.
Analyzers MUST NOT fabricate output: on failure raise AnalyzerError (job records it) rather than return fake findings."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from .models import Finding


class AnalyzerError(RuntimeError):
    pass


@dataclass
class AnalysisInput:
    job_id: str
    filename: str
    source: str
    workdir: str                 # job-private directory (already contains the .sol file)
    artifacts: dict = field(default_factory=dict)  # outputs of earlier stages (e.g. sandbox parse result, graphs)


@runtime_checkable
class Analyzer(Protocol):
    name: str
    version: str
    stage: str  # one of JobStage values it belongs to

    def available(self) -> bool: ...
    def analyze(self, inp: AnalysisInput) -> list[Finding]: ...
