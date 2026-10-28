"""Feature extraction and graph embedding encoder for smart contract graphs."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple
import numpy as np

from .graph import ProgramGraph, GraphNode

NODE_TYPES = ["contract", "function", "state_var", "statement", "call", "require", "write"]
CALL_TYPES = ["call", "send", "transfer", "delegatecall", "selfdestruct", "none"]

FEATURE_DIM = 64
GRAPH_FEATURE_DIM = 32

_VULN_KEYWORDS = [
    ("tx_origin", re.compile(r"\btx\.origin\b")),
    ("timestamp", re.compile(r"\b(block\.timestamp|now)\b")),
    ("delegatecall", re.compile(r"\bdelegatecall\b")),
    ("selfdestruct", re.compile(r"\b(selfdestruct|suicide)\b")),
    ("blockhash", re.compile(r"\b(blockhash|block\.difficulty|block\.prevrandao)\b")),
    ("call_value", re.compile(r"\.call\s*\{[^}]*value\s*:")),
    ("reentrancy_pattern", re.compile(r"\.call[^{]*\{[^}]*\}[^;]*;[^}]*=\s*0;")),
    ("assembly", re.compile(r"\bassembly\s*\{")),
]


def encode_node_features(node: GraphNode, source: str) -> np.ndarray:
    """Encodes a single GraphNode into a dense 64-dimensional feature vector."""
    vec = np.zeros(FEATURE_DIM, dtype=np.float32)

    # 1. One-hot node type (0..6)
    t_idx = NODE_TYPES.index(node.node_type) if node.node_type in NODE_TYPES else len(NODE_TYPES)
    if t_idx < len(NODE_TYPES):
        vec[t_idx] = 1.0

    # 2. Call types (7..12)
    c_type = node.attributes.get("call_type", "none")
    c_idx = CALL_TYPES.index(c_type) if c_type in CALL_TYPES else len(CALL_TYPES) - 1
    vec[7 + c_idx] = 1.0

    # 3. Check status & flags (13..19)
    if node.attributes.get("is_checked", False):
        vec[13] = 1.0
    if "payable" in node.attributes.get("modifiers", ""):
        vec[14] = 1.0
    if "onlyOwner" in node.attributes.get("modifiers", ""):
        vec[15] = 1.0
    if "public" in node.attributes.get("modifiers", "") or "external" in node.attributes.get("modifiers", ""):
        vec[16] = 1.0
    if "internal" in node.attributes.get("modifiers", "") or "private" in node.attributes.get("modifiers", ""):
        vec[17] = 1.0

    # 4. Keyword presence in node label (20..27)
    for i, (_, pattern) in enumerate(_VULN_KEYWORDS):
        if pattern.search(node.label):
            vec[20 + i] = 1.0

    # 5. Position in file (28)
    total_lines = max(1, source.count("\n") + 1)
    vec[28] = float(node.line_start) / total_lines

    return vec


def graph_to_tensors(graph: ProgramGraph, source: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Converts a ProgramGraph into:
      - node_features: (N, 64) float32 matrix
      - edge_index: (2, E) int64 matrix of [source_idx, target_idx]
      - global_features: (32,) float32 vector for graph-level baseline models
    """
    num_nodes = len(graph.nodes)
    if num_nodes == 0:
        return np.zeros((1, FEATURE_DIM), dtype=np.float32), np.zeros((2, 0), dtype=np.int64), np.zeros(GRAPH_FEATURE_DIM, dtype=np.float32)

    id_to_idx = {n.id: i for i, n in enumerate(graph.nodes)}
    node_features = np.zeros((num_nodes, FEATURE_DIM), dtype=np.float32)

    for i, n in enumerate(graph.nodes):
        node_features[i] = encode_node_features(n, source)

    edges_src: List[int] = []
    edges_dst: List[int] = []

    for e in graph.edges:
        if e.source in id_to_idx and e.target in id_to_idx:
            edges_src.append(id_to_idx[e.source])
            edges_dst.append(id_to_idx[e.target])

    edge_index = np.array([edges_src, edges_dst], dtype=np.int64) if edges_src else np.zeros((2, 0), dtype=np.int64)

    # Global graph features
    global_features = extract_graph_global_features(graph, source)

    return node_features, edge_index, global_features


def extract_graph_global_features(graph: ProgramGraph, source: str) -> np.ndarray:
    """Computes a 32-dimensional summary vector over graph structure and syntactic patterns."""
    feat = np.zeros(GRAPH_FEATURE_DIM, dtype=np.float32)

    num_nodes = max(1, len(graph.nodes))
    calls = [n for n in graph.nodes if n.node_type == "call"]
    writes = [n for n in graph.nodes if n.node_type == "write"]
    requires = [n for n in graph.nodes if n.node_type == "require"]
    
    # 0..4 Structural metrics
    feat[0] = min(1.0, len(graph.nodes) / 100.0)
    feat[1] = min(1.0, len(graph.edges) / 150.0)
    feat[2] = min(1.0, len(graph.functions) / 20.0)
    feat[3] = min(1.0, len(calls) / max(1, len(graph.functions)))
    feat[4] = min(1.0, len(requires) / max(1, len(graph.functions)))

    # 5..9 Call patterns
    num_calls = max(1, len(calls))
    feat[5] = sum(1 for c in calls if c.attributes.get("call_type") == "delegatecall") / num_calls
    feat[6] = sum(1 for c in calls if c.attributes.get("call_type") == "selfdestruct") / num_calls
    feat[7] = sum(1 for c in calls if c.attributes.get("call_type") == "call") / num_calls
    feat[8] = sum(1 for c in calls if not c.attributes.get("is_checked", True)) / num_calls

    # 10..15 Semantic keywords in contract
    for i, (_, pattern) in enumerate(_VULN_KEYWORDS):
        if pattern.search(source):
            feat[10 + i] = 1.0

    # 18: Reentrancy heuristic (state write positioned after call in same function)
    for c in calls:
        if c.attributes.get("call_type") in ("call", "send"):
            for w in writes:
                if w.line_start > c.line_start and (w.line_start - c.line_start) < 15:
                    feat[18] = 1.0
                    break

    # 19: Unchecked low-level call presence
    for c in calls:
        if c.attributes.get("call_type") == "call" and not c.attributes.get("is_checked", True):
            feat[19] = 1.0
            break

    # 20: Pre-0.8.0 unchecked math indicator
    if "pragma solidity" in source:
        m = re.search(r"pragma\s+solidity\s+[\^~>=<]*\s*0\.([4567])", source)
        if m:
            feat[20] = 1.0

    return feat
