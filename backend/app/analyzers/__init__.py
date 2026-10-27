"""Pluggable analyzer registry (implements shared/chainguard_contract/analyzer.py's Analyzer protocol)."""
from __future__ import annotations

from dataclasses import dataclass, field

from chainguard_contract.analyzer import Analyzer


@dataclass
class AnalyzerRegistry:
    analyzers: list = field(default_factory=list)
    notes: dict[str, str] = field(default_factory=dict)   # name -> why it's missing/unavailable

    def register(self, a: Analyzer) -> None:
        if not isinstance(a, Analyzer):
            raise TypeError(f"{a!r} does not implement the Analyzer protocol")
        self.analyzers = [x for x in self.analyzers if x.name != a.name] + [a]

    def for_stage(self, stage: str) -> list:
        return [a for a in self.analyzers if a.stage == stage]

    def availability(self) -> dict[str, bool]:
        out = {}
        for a in self.analyzers:
            try:
                out[a.name] = bool(a.available())
            except Exception:  # noqa: BLE001
                out[a.name] = False
        return out
