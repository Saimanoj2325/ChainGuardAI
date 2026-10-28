"""Runtime ML Analyzer implementing chainguard_contract.analyzer.Analyzer protocol.
Loads trained GNN weights and performs inference to generate evidence-grounded Finding candidates.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional
import numpy as np
import torch

from chainguard_contract.analyzer import AnalysisInput, Analyzer, AnalyzerError
from chainguard_contract.models import DetectorSource, Evidence, Finding, LineRange, Severity, VulnClass

from .features import graph_to_tensors
from .graph import build_program_graph
from .models.gnn import ContractGNN, VULN_CLASSES

log = logging.getLogger("chainguard.ml.analyzer")

WEIGHTS_PATH = Path(__file__).resolve().parent.parent / "models" / "best_model.pt"

SEVERITY_MAP = {
    VulnClass.reentrancy: Severity.critical,
    VulnClass.unchecked_call: Severity.medium,
    VulnClass.tx_origin: Severity.medium,
    VulnClass.timestamp_dependence: Severity.low,
    VulnClass.integer_overflow: Severity.high,
    VulnClass.access_control: Severity.high,
    VulnClass.delegatecall: Severity.critical,
    VulnClass.unprotected_selfdestruct: Severity.critical,
    VulnClass.denial_of_service: Severity.medium,
    VulnClass.bad_randomness: Severity.low,
    VulnClass.other: Severity.info,
}

TITLE_MAP = {
    VulnClass.reentrancy: "Potential reentrancy vulnerability detected by GNN",
    VulnClass.unchecked_call: "Unchecked external call return value detected by GNN",
    VulnClass.tx_origin: "Insecure tx.origin authentication detected by GNN",
    VulnClass.timestamp_dependence: "Timestamp dependence in contract logic detected by GNN",
    VulnClass.integer_overflow: "Potential arithmetic overflow/underflow detected by GNN",
    VulnClass.access_control: "Missing access control restriction detected by GNN",
    VulnClass.delegatecall: "Unsafe delegatecall to untrusted target detected by GNN",
    VulnClass.unprotected_selfdestruct: "Unprotected selfdestruct call detected by GNN",
    VulnClass.denial_of_service: "Denial of service vector detected by GNN",
    VulnClass.bad_randomness: "Predictable randomness source detected by GNN",
    VulnClass.other: "Security anomaly detected by GNN",
}

DESC_MAP = {
    VulnClass.reentrancy: "Graph neural network identified graph flow containing state modification after an external call.",
    VulnClass.unchecked_call: "GNN detected external low-level call execution where return status is not verified.",
    VulnClass.tx_origin: "GNN detected authorization logic relying on tx.origin instead of msg.sender.",
    VulnClass.timestamp_dependence: "GNN detected critical state transitions conditioned on block.timestamp.",
    VulnClass.integer_overflow: "GNN detected unchecked arithmetic operations in pre-0.8.0 Solidity source.",
    VulnClass.access_control: "GNN detected state-modifying functions lacking authorization modifier guards.",
    VulnClass.delegatecall: "GNN detected delegatecall invocation where target address or parameters may be manipulated.",
    VulnClass.unprotected_selfdestruct: "GNN detected selfdestruct instruction callable without access control restriction.",
    VulnClass.denial_of_service: "GNN detected unbounded loop or push-payment pattern susceptible to DoS.",
    VulnClass.bad_randomness: "GNN detected randomness derived from predictable block environment variables.",
    VulnClass.other: "GNN identified structural anomaly matching vulnerability patterns.",
}


class MLAnalyzer(Analyzer):
    """GNN-based Vulnerability Analyzer implementing the Analyzer protocol."""

    name: str = "gnn"
    version: str = "1.0.0"
    stage: str = "ml_inference"

    def __init__(self, weights_path: Optional[Path] = None):
        self.weights_path = weights_path or WEIGHTS_PATH
        self._model: Optional[ContractGNN] = None

    def _load_model(self) -> Optional[ContractGNN]:
        if self._model is not None:
            return self._model
        if not self.weights_path.exists():
            return None
        try:
            model = ContractGNN(in_dim=64, hidden_dim=128, global_dim=32, num_classes=len(VULN_CLASSES))
            state_dict = torch.load(self.weights_path, map_location="cpu")
            model.load_state_dict(state_dict)
            model.eval()
            self._model = model
            return model
        except Exception as e:
            log.warning("Failed to load GNN weights from %s: %s", self.weights_path, e)
            return None

    def available(self) -> bool:
        """Available if model weights file exists and can be loaded."""
        return self._load_model() is not None

    def analyze(self, inp: AnalysisInput) -> List[Finding]:
        """Runs graph extraction and GNN inference to output candidate findings."""
        model = self._load_model()
        if model is None:
            raise AnalyzerError("GNN model weights not available or failed to load")

        source = inp.source
        sandbox_ast = inp.artifacts.get("sandbox", {}).get("ast")
        graph = build_program_graph(source, ast=sandbox_ast)
        node_features, edge_index, global_features = graph_to_tensors(graph, source)

        x = torch.from_numpy(node_features)
        edges = torch.from_numpy(edge_index)
        g_feat = torch.from_numpy(global_features)

        pred = model.predict(x, edges, g_feat, threshold=0.5)
        findings: List[Finding] = []

        lines = source.splitlines()
        node_importance = pred.get("node_importance", [])

        for cls_name, prob in pred.get("probabilities", {}).items():
            if prob < 0.5:
                continue

            try:
                v_class = VulnClass(cls_name)
            except ValueError:
                v_class = VulnClass.other

            # Find the most relevant node in the graph for this finding
            best_node = None
            max_score = -1.0
            for i, n in enumerate(graph.nodes):
                score = node_importance[i] if i < len(node_importance) else 0.0
                # Boost nodes relevant to this vulnerability class
                if v_class == VulnClass.reentrancy and n.node_type in ("call", "write"):
                    score += 1.0
                elif v_class == VulnClass.unchecked_call and n.node_type == "call":
                    score += 1.0
                elif v_class == VulnClass.tx_origin and "tx.origin" in n.label:
                    score += 2.0
                elif v_class == VulnClass.unprotected_selfdestruct and "selfdestruct" in n.label:
                    score += 2.0
                elif v_class == VulnClass.delegatecall and "delegatecall" in n.label:
                    score += 2.0
                if score > max_score and n.line_start > 0:
                    max_score = score
                    best_node = n

            # Compute line evidence
            evidence_lines: List[LineRange] = []
            snippet = ""
            graph_nodes: List[str] = []
            dep_path: List[str] = []

            if best_node:
                s_line = best_node.line_start
                e_line = max(s_line, best_node.line_end)
                evidence_lines.append(LineRange(start=s_line, end=e_line))
                if 1 <= s_line <= len(lines):
                    snippet = "\n".join(lines[s_line - 1 : min(len(lines), e_line)])
                graph_nodes.append(f"GNN:{best_node.id}")
                dep_path.append(f"Graph traversal identified anomaly at {best_node.id}")

            finding = Finding(
                id=f"gnn-{v_class.value}-{len(findings)+1}",
                vuln_class=v_class,
                title=TITLE_MAP.get(v_class, f"{v_class.value} detected"),
                severity=SEVERITY_MAP.get(v_class, Severity.medium),
                confidence=round(float(prob), 4),
                detectors=[DetectorSource.gnn],
                contract_name=graph.contract_name,
                function_name=graph.functions[0] if graph.functions else None,
                description=DESC_MAP.get(v_class, "Detected by Graph Neural Network."),
                recommendation="Review the highlighted graph node and apply appropriate security patterns.",
                evidence=Evidence(
                    lines=evidence_lines,
                    snippet=snippet,
                    graph_nodes=graph_nodes,
                    dependency_path=dep_path,
                    tool_output=f"GNN confidence: {prob:.2%}",
                ),
                is_mock=False,
            )
            findings.append(finding)

        return findings


def get_analyzer() -> MLAnalyzer:
    return MLAnalyzer()
