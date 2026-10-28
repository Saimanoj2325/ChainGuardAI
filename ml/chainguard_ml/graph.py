"""Program Graph Construction: AST, CFG, and DFG representation for smart contracts."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class GraphNode:
    id: str
    node_type: str  # "contract" | "function" | "state_var" | "statement" | "call" | "require" | "write"
    label: str
    line_start: int
    line_end: int
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    edge_type: str  # "ast_child" | "cfg_next" | "cfg_branch" | "dfg_def_use" | "dfg_state_write"


@dataclass
class ProgramGraph:
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    contract_name: Optional[str] = None
    functions: List[str] = field(default_factory=list)

    def node_by_id(self, nid: str) -> Optional[GraphNode]:
        for n in self.nodes:
            if n.id == nid:
                return n
        return None

    def outgoing_edges(self, nid: str) -> List[GraphEdge]:
        return [e for e in self.edges if e.source == nid]

    def incoming_edges(self, nid: str) -> List[GraphEdge]:
        return [e for e in self.edges if e.target == nid]

    def summary(self) -> Dict[str, Any]:
        return {
            "num_nodes": len(self.nodes),
            "num_edges": len(self.edges),
            "functions": self.functions,
            "node_types": {t: sum(1 for n in self.nodes if n.node_type == t) for t in set(n.node_type for n in self.nodes)},
            "edge_types": {t: sum(1 for e in self.edges if e.edge_type == t) for t in set(e.edge_type for e in self.edges)},
        }


# Regex patterns for lexical graph construction when full solc AST is omitted or compiling is degraded
_CONTRACT_RE = re.compile(r"\b(contract|library|interface)\s+([A-Za-z0-9_]+)", re.MULTILINE)
_FUNCTION_RE = re.compile(
    r"\bfunction\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)\s*([^{;]*)(?:\{|;)", re.MULTILINE
)
_STATE_VAR_RE = re.compile(
    r"^\s*(mapping\s*\([^;]+\)|address\s*(?:payable)?|uint\d*|int\d*|bool|bytes\d*|string)\s+(?:public|private|internal)?\s*([A-Za-z0-9_]+)\s*;",
    re.MULTILINE,
)
_REQUIRE_RE = re.compile(r"\b(require|assert)\s*\(([^;]+)\);", re.MULTILINE)
_CALL_RE = re.compile(r"([A-Za-z0-9_.]+)\.(call|send|transfer|delegatecall)\s*\{?([^};]*)\}?\s*\(([^;]*)\)", re.MULTILINE)
_WRITE_RE = re.compile(r"([A-Za-z0-9_]+(?:\s*\[[^\]]+\])?)\s*(=|\+=|-=|\*=|/=|%=)\s*([^;]+);", re.MULTILINE)
_SELFDESTRUCT_RE = re.compile(r"\b(selfdestruct|suicide)\s*\(([^)]*)\);", re.MULTILINE)


def build_program_graph(source: str, ast: Optional[Dict[str, Any]] = None) -> ProgramGraph:
    """Constructs a ProgramGraph with AST, CFG, and DFG nodes and relations from source and optional AST."""
    graph = ProgramGraph()
    lines = source.splitlines()

    def line_num_at(idx: int) -> int:
        return source[:idx].count("\n") + 1

    # 1. Contract Nodes
    contract_match = _CONTRACT_RE.search(source)
    c_name = contract_match.group(2) if contract_match else "Contract"
    c_line = line_num_at(contract_match.start()) if contract_match else 1
    graph.contract_name = c_name
    c_node_id = f"Contract:{c_name}"
    graph.nodes.append(GraphNode(
        id=c_node_id,
        node_type="contract",
        label=c_name,
        line_start=c_line,
        line_end=len(lines),
        attributes={"kind": contract_match.group(1) if contract_match else "contract"}
    ))

    # 2. State Variables
    state_vars: Set[str] = set()
    for m in _STATE_VAR_RE.finditer(source):
        var_type, var_name = m.group(1).strip(), m.group(2).strip()
        v_line = line_num_at(m.start())
        state_vars.add(var_name)
        v_node_id = f"StateVar:{var_name}"
        graph.nodes.append(GraphNode(
            id=v_node_id,
            node_type="state_var",
            label=f"{var_type} {var_name}",
            line_start=v_line,
            line_end=v_line,
            attributes={"type": var_type, "name": var_name}
        ))
        graph.edges.append(GraphEdge(source=c_node_id, target=v_node_id, edge_type="ast_child"))

    # 3. Functions & Statements
    for fm in _FUNCTION_RE.finditer(source):
        fn_name = fm.group(1)
        graph.functions.append(fn_name)
        fn_start = line_num_at(fm.start())
        
        # approximate function boundary
        brace_start = source.find("{", fm.end() - 2)
        if brace_start == -1:
            fn_end = fn_start
            body = ""
        else:
            # find matching closing brace
            depth = 1
            cur = brace_start + 1
            while cur < len(source) and depth > 0:
                if source[cur] == "{":
                    depth += 1
                elif source[cur] == "}":
                    depth -= 1
                cur += 1
            fn_end = line_num_at(cur)
            body = source[brace_start:cur]

        fn_node_id = f"Function:{fn_name}"
        graph.nodes.append(GraphNode(
            id=fn_node_id,
            node_type="function",
            label=f"{fn_name}()",
            line_start=fn_start,
            line_end=fn_end,
            attributes={"modifiers": fm.group(3).strip(), "signature": f"{fn_name}({fm.group(2)})"}
        ))
        graph.edges.append(GraphEdge(source=c_node_id, target=fn_node_id, edge_type="ast_child"))

        # Inside function body: parse statements
        prev_stmt_id = fn_node_id
        
        # Match checks / requires
        for rm in _REQUIRE_RE.finditer(body):
            rel_start = brace_start + rm.start()
            s_line = line_num_at(rel_start)
            req_id = f"Stmt:req@{fn_name}:{s_line}"
            graph.nodes.append(GraphNode(
                id=req_id,
                node_type="require",
                label=rm.group(0).strip(),
                line_start=s_line,
                line_end=s_line,
                attributes={"condition": rm.group(2).strip()}
            ))
            graph.edges.append(GraphEdge(source=fn_node_id, target=req_id, edge_type="ast_child"))
            graph.edges.append(GraphEdge(source=prev_stmt_id, target=req_id, edge_type="cfg_next"))
            prev_stmt_id = req_id

        # Match calls (call, send, transfer, delegatecall)
        for cm in _CALL_RE.finditer(body):
            rel_start = brace_start + cm.start()
            s_line = line_num_at(rel_start)
            call_type = cm.group(2)
            call_id = f"Call:{call_type}@{fn_name}:{s_line}"
            target_expr = cm.group(1).strip()
            args = cm.group(4).strip()
            graph.nodes.append(GraphNode(
                id=call_id,
                node_type="call",
                label=cm.group(0).strip(),
                line_start=s_line,
                line_end=s_line,
                attributes={"call_type": call_type, "target": target_expr, "args": args}
            ))
            graph.edges.append(GraphEdge(source=fn_node_id, target=call_id, edge_type="ast_child"))
            graph.edges.append(GraphEdge(source=prev_stmt_id, target=call_id, edge_type="cfg_next"))
            
            # Check if call is unchecked (standalone statement without require/bool check)
            pre_context = body[max(0, cm.start() - 40):cm.start()]
            is_checked = "bool " in pre_context or "require(" in pre_context or "if (" in pre_context
            graph.nodes[-1].attributes["is_checked"] = is_checked

            prev_stmt_id = call_id

        # Match state writes
        for wm in _WRITE_RE.finditer(body):
            rel_start = brace_start + wm.start()
            s_line = line_num_at(rel_start)
            dest = wm.group(1).strip()
            write_id = f"Write:{dest}@{fn_name}:{s_line}"
            graph.nodes.append(GraphNode(
                id=write_id,
                node_type="write",
                label=wm.group(0).strip(),
                line_start=s_line,
                line_end=s_line,
                attributes={"target_var": dest, "op": wm.group(2)}
            ))
            graph.edges.append(GraphEdge(source=fn_node_id, target=write_id, edge_type="ast_child"))
            graph.edges.append(GraphEdge(source=prev_stmt_id, target=write_id, edge_type="cfg_next"))
            
            # DFG: connect to state variable if matching
            for sv in state_vars:
                if sv in dest:
                    graph.edges.append(GraphEdge(
                        source=write_id,
                        target=f"StateVar:{sv}",
                        edge_type="dfg_state_write"
                    ))
            prev_stmt_id = write_id

        # Match selfdestruct
        for sm in _SELFDESTRUCT_RE.finditer(body):
            rel_start = brace_start + sm.start()
            s_line = line_num_at(rel_start)
            sd_id = f"Stmt:selfdestruct@{fn_name}:{s_line}"
            graph.nodes.append(GraphNode(
                id=sd_id,
                node_type="call",
                label=sm.group(0).strip(),
                line_start=s_line,
                line_end=s_line,
                attributes={"call_type": "selfdestruct"}
            ))
            graph.edges.append(GraphEdge(source=fn_node_id, target=sd_id, edge_type="ast_child"))
            graph.edges.append(GraphEdge(source=prev_stmt_id, target=sd_id, edge_type="cfg_next"))
            prev_stmt_id = sd_id

    return graph
