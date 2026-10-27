"""Lightweight Solidity source utilities (no compiler): comment/string masking, contract & function spans.
Good enough for heuristics and evidence extraction; not a parser."""
from __future__ import annotations

import re
from dataclasses import dataclass, field


def mask_comments_and_strings(src: str) -> str:
    """Replace comments and string-literal contents with spaces, preserving offsets and newlines."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def line_of(src: str, offset: int) -> int:
    return src.count("\n", 0, offset) + 1


def match_brace(masked: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(masked)):
        ch = masked[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(masked) - 1


@dataclass
class FunctionSpan:
    name: str
    contract: str | None
    header: str            # masked text between 'function' and '{'
    params: list[str]
    start: int             # char offset of 'function'
    body_start: int        # offset of '{'
    end: int               # offset of matching '}'
    start_line: int = 0
    end_line: int = 0


@dataclass
class ContractSpan:
    name: str
    kind: str
    start: int
    end: int
    state_vars: set[str] = field(default_factory=set)


_CONTRACT_RE = re.compile(r"\b(contract|library|interface)\s+([A-Za-z_]\w*)[^{;]*\{")
_FUNC_RE = re.compile(r"\b(function\s+([A-Za-z_]\w*)|constructor|receive|fallback|modifier\s+([A-Za-z_]\w*))\s*\(")
_STATE_DECL_RE = re.compile(
    r"^\s*(?:mapping\s*\(.*\)|[A-Za-z_][\w.]*(?:\s*\[[^\]]*\])*)\s+(?:(?:public|private|internal|constant|immutable|override|payable)\s+)*([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
    re.M)
_NOT_STATE = {"return", "emit", "using", "event", "error", "struct", "enum", "import", "pragma", "delete"}


def _param_names(params_text: str) -> list[str]:
    names = []
    for part in params_text.split(","):
        toks = part.strip().split()
        if len(toks) >= 2:
            names.append(toks[-1])
    return names


class SourceIndex:
    def __init__(self, src: str):
        self.src = src
        self.masked = mask_comments_and_strings(src)
        self.lines = src.splitlines()
        self.contracts: list[ContractSpan] = []
        self.functions: list[FunctionSpan] = []
        self._index()

    def _index(self) -> None:
        m = self.masked
        for cm in _CONTRACT_RE.finditer(m):
            ob = cm.end() - 1
            self.contracts.append(ContractSpan(cm.group(2), cm.group(1), cm.start(), match_brace(m, ob)))
        for fm in _FUNC_RE.finditer(m):
            kw = fm.group(1)
            name = fm.group(2) or fm.group(3) or kw.split()[0]
            is_modifier = kw.startswith("modifier")
            # find end of params
            p_open = fm.end() - 1
            depth, j = 0, p_open
            while j < len(m):
                if m[j] == "(":
                    depth += 1
                elif m[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            params = _param_names(m[p_open + 1:j])
            k = j + 1
            while k < len(m) and m[k] not in "{;":
                k += 1
            if k >= len(m) or m[k] == ";":
                continue  # declaration without body
            end = match_brace(m, k)
            contract = next((c.name for c in self.contracts if c.start <= fm.start() <= c.end), None)
            fs = FunctionSpan(("modifier:" if is_modifier else "") + name, contract, m[fm.start():k], params,
                              fm.start(), k, end, line_of(m, fm.start()), line_of(m, end))
            self.functions.append(fs)
        # state variables: contract-level statements outside any function body
        for c in self.contracts:
            body = list(m[c.start:c.end + 1])
            for f in self.functions:
                if c.start <= f.start <= c.end:
                    for i in range(f.start - c.start, min(f.end - c.start + 1, len(body))):
                        if body[i] != "\n":
                            body[i] = " "
            text = "".join(body)
            first = text.find("{")
            text = text[first + 1:] if first != -1 else text
            for sm in _STATE_DECL_RE.finditer(text):
                stmt = sm.group(0).strip()
                if stmt.split()[0] in _NOT_STATE:
                    continue
                c.state_vars.add(sm.group(1))

    # ---- queries
    def real_functions(self) -> list[FunctionSpan]:
        return [f for f in self.functions if not f.name.startswith("modifier:")]

    def state_vars(self, contract: str | None) -> set[str]:
        out: set[str] = set()
        for c in self.contracts:
            if contract is None or c.name == contract:
                out |= c.state_vars
        return out

    def function_at_line(self, line: int) -> FunctionSpan | None:
        cands = [f for f in self.functions if f.start_line <= line <= f.end_line]
        return min(cands, key=lambda f: f.end_line - f.start_line) if cands else None

    def function_by_name(self, name: str | None, contract: str | None = None) -> FunctionSpan | None:
        if not name:
            return None
        for f in self.functions:
            if f.name == name and (contract is None or f.contract == contract):
                return f
        return None

    def contract_names(self) -> list[str]:
        return [c.name for c in self.contracts]

    def snippet(self, start: int, end: int, context: int = 1, max_lines: int = 40) -> str:
        a = max(1, start - context)
        b = min(len(self.lines), end + context, a + max_lines - 1)
        return "\n".join(f"{i:>4}: {self.lines[i - 1]}" for i in range(a, b + 1))

    def function_source(self, f: FunctionSpan, max_lines: int = 120) -> str:
        return self.snippet(f.start_line, f.end_line, context=0, max_lines=max_lines)

    def pragma_versions(self) -> list[tuple[int, int, int]]:
        out = []
        for pm in re.finditer(r"pragma\s+solidity\s+([^;]+);", self.masked):
            for v in re.finditer(r"(\d+)\.(\d+)(?:\.(\d+))?", pm.group(1)):
                out.append((int(v.group(1)), int(v.group(2)), int(v.group(3) or 0)))
                break  # lowest bound = first version mentioned
        return out
