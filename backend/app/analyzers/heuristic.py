"""HeuristicAnalyzer: pattern checks over masked Solidity source (no compiler needed).

These are heuristics with deliberately moderate confidence values; they are labelled detectors=[heuristic]
and are meant to be corroborated by Slither/ML/LLM/EVM stages, never presented as proof."""
from __future__ import annotations

import re

from chainguard_contract.analyzer import AnalysisInput
from chainguard_contract.models import DetectorSource, Evidence, Finding, LineRange, Severity, VulnClass

from ..solsrc import FunctionSpan, SourceIndex, line_of

EXT_CALL_RE = re.compile(r"\.\s*call\s*(\{[^}]*\})?\s*(\.value\s*\([^)]*\)\s*)?\(")
LOWLEVEL_RE = re.compile(r"\.\s*(call|send|delegatecall|staticcall)\s*(\{[^}]*\})?\s*(\.value\s*\([^)]*\)\s*)?\(")
ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\[[^;\]]*\]\s*)*(\+=|-=|\*=|/=|%=|=(?!=)|\+\+|--)")
OWNER_CHECK_RE = re.compile(r"(msg\.sender\s*[!=]=|[!=]=\s*msg\.sender|_checkOwner\s*\(|onlyOwner|only[A-Z]\w*|\bauth\b|hasRole\s*\()")
ARITH_RE = re.compile(r"(\+=|-=|\*=|[^+]\+[^+=]|[^-]-[^-=>]|\*(?!=))")


def _mk(vc, title, sev, conf, f: FunctionSpan | None, desc, rec, lines, idx: SourceIndex, path, tool) -> Finding:
    lr = [LineRange(start=a, end=b) for a, b in lines]
    lo = min(a for a, _ in lines) if lines else 1
    hi = max(b for _, b in lines) if lines else 1
    return Finding(id="", vuln_class=vc, title=title, severity=sev, confidence=conf,
                   detectors=[DetectorSource.heuristic], contract_name=f.contract if f else None,
                   function_name=f.name if f else None, description=desc, recommendation=rec,
                   evidence=Evidence(lines=lr, snippet=idx.snippet(lo, hi), dependency_path=path, tool_output=tool))


class HeuristicAnalyzer:
    name = "heuristic"
    version = "0.1.0"
    stage = "static_analysis"

    def available(self) -> bool:
        return True

    def analyze(self, inp: AnalysisInput) -> list[Finding]:
        idx = SourceIndex(inp.source)
        out: list[Finding] = []
        m = idx.masked
        for f in idx.real_functions():
            body = m[f.body_start:f.end + 1]
            base = f.body_start
            out += self._reentrancy(idx, f, body, base)
            out += self._unchecked(idx, f, body, base)
            out += self._tx_origin(idx, f, body, base)
            out += self._timestamp(idx, f, body, base)
            out += self._delegatecall(idx, f, body, base)
            out += self._selfdestruct(idx, f, body, base)
        out += self._arith(idx)
        return out

    # external call followed by a state write in the same function
    def _reentrancy(self, idx, f, body, base):
        if re.search(r"\bnonReentrant\b", f.header):
            return []
        svars = idx.state_vars(f.contract)
        res = []
        for cm in EXT_CALL_RE.finditer(body):
            call_line = line_of(idx.masked, base + cm.start())
            after = body[cm.end():]
            for am in ASSIGN_RE.finditer(after):
                var = am.group(1)
                if var in svars:
                    wl = line_of(idx.masked, base + cm.end() + am.start())
                    if wl == call_line:
                        continue
                    res.append(_mk(VulnClass.reentrancy, f"Possible reentrancy in {f.name}()", Severity.high, 0.6, f,
                                   f"`{f.name}` performs an external call (line {call_line}) before updating state variable "
                                   f"`{var}` (line {wl}). A malicious callee can re-enter before the state is updated.",
                                   "Apply checks-effects-interactions (update state before the call) or use a reentrancy guard.",
                                   [(call_line, call_line), (wl, wl)], idx,
                                   [f"{f.name}(): external call at L{call_line}", f"state write `{var}` at L{wl} after the call"],
                                   "heuristic: external-call-before-state-write"))
                    return res
        return res

    def _unchecked(self, idx, f, body, base):
        res = []
        for lm in LOWLEVEL_RE.finditer(body):
            if lm.group(1) == "staticcall":
                continue
            # statement start: last ';', '{' or '}' before the call
            s = max(body.rfind(";", 0, lm.start()), body.rfind("{", 0, lm.start()), body.rfind("}", 0, lm.start())) + 1
            stmt = body[s:lm.start()].strip()
            if re.search(r"(=|\brequire\s*\(|\bassert\s*\(|\bif\s*\(|\breturn\b|\(\s*bool)", stmt):
                continue
            ln = line_of(idx.masked, base + lm.start())
            res.append(_mk(VulnClass.unchecked_call, f"Unchecked low-level {lm.group(1)} in {f.name}()", Severity.medium, 0.6, f,
                           f"The return value of the low-level `{lm.group(1)}` on line {ln} is not checked; failures are silently ignored.",
                           "Check the returned success flag (e.g. `(bool ok, ) = ...; require(ok);`).",
                           [(ln, ln)], idx, [f"{f.name}(): `{lm.group(1)}` result discarded at L{ln}"],
                           "heuristic: unchecked-low-level-call"))
        return res

    def _tx_origin(self, idx, f, body, base):
        res = []
        for tm in re.finditer(r"tx\.origin\s*[!=]=|[!=]=\s*tx\.origin", body):
            ln = line_of(idx.masked, base + tm.start())
            res.append(_mk(VulnClass.tx_origin, f"tx.origin used for authorization in {f.name}()", Severity.high, 0.7, f,
                           f"Line {ln} compares `tx.origin`; a contract the owner interacts with can act on their behalf (phishing).",
                           "Use `msg.sender` for authorization.", [(ln, ln)], idx,
                           [f"{f.name}(): authorization via tx.origin at L{ln}"], "heuristic: tx-origin-auth"))
            break
        return res

    def _timestamp(self, idx, f, body, base):
        res = []
        for tm in re.finditer(r"\bblock\.timestamp\b|\bnow\b", body):
            ln = line_of(idx.masked, base + tm.start())
            line = idx.masked.splitlines()[ln - 1]
            if re.search(r"(require\s*\(|if\s*\(|[<>]=?|==|%)", line):
                rnd = "%" in line
                res.append(_mk(VulnClass.bad_randomness if rnd else VulnClass.timestamp_dependence,
                               ("Block timestamp used as randomness" if rnd else "Timestamp-dependent logic") + f" in {f.name}()",
                               Severity.medium if rnd else Severity.low, 0.4, f,
                               f"Line {ln} uses `block.timestamp` in a condition{' / modulo' if rnd else ''}; miners/validators can skew it.",
                               "Avoid timestamp for randomness or tight timing; tolerate ~15s drift.",
                               [(ln, ln)], idx, [f"{f.name}(): block.timestamp in condition at L{ln}"], "heuristic: timestamp-in-condition"))
                break
        return res

    def _delegatecall(self, idx, f, body, base):
        res = []
        for dm in re.finditer(r"([A-Za-z_]\w*)\s*\.\s*delegatecall\s*\(", body):
            target = dm.group(1)
            if target in f.params:
                ln = line_of(idx.masked, base + dm.start())
                res.append(_mk(VulnClass.delegatecall, f"delegatecall to caller-supplied address in {f.name}()", Severity.high, 0.6, f,
                               f"`{target}` is a function parameter used as a delegatecall target (line {ln}); the caller can run arbitrary code in this contract's storage context.",
                               "Never delegatecall to user-supplied addresses; whitelist trusted implementations.",
                               [(ln, ln)], idx, [f"{f.name}(): parameter `{target}`", f"delegatecall target at L{ln}"],
                               "heuristic: controlled-delegatecall"))
        return res

    def _selfdestruct(self, idx, f, body, base):
        sm = re.search(r"\b(selfdestruct|suicide)\s*\(", body)
        if not sm:
            return []
        if OWNER_CHECK_RE.search(f.header) or OWNER_CHECK_RE.search(body[:sm.start()]):
            return []
        ln = line_of(idx.masked, base + sm.start())
        return [_mk(VulnClass.unprotected_selfdestruct, f"Unprotected selfdestruct in {f.name}()", Severity.high, 0.6, f,
                    f"`{f.name}` calls `{sm.group(1)}` (line {ln}) with no visible msg.sender/owner check.",
                    "Restrict with an owner/role check, or remove selfdestruct.",
                    [(ln, ln)], idx, [f"{f.name}(): no access control", f"{sm.group(1)} at L{ln}"], "heuristic: unprotected-selfdestruct")]

    def _arith(self, idx: SourceIndex):
        vers = idx.pragma_versions()
        if not vers or not any(v < (0, 8, 0) for v in vers):
            return []
        if re.search(r"\busing\s+SafeMath\b", idx.masked):
            return []
        res = []
        for f in idx.real_functions():
            svars = idx.state_vars(f.contract)
            body = idx.masked[f.body_start:f.end + 1]
            hits = []
            for am in ASSIGN_RE.finditer(body):
                if am.group(1) in svars and am.group(2) in ("+=", "-=", "*=", "++", "--"):
                    hits.append(line_of(idx.masked, f.body_start + am.start()))
                elif am.group(1) in svars and am.group(2) == "=":
                    rhs_end = body.find(";", am.end())
                    rhs = body[am.end():rhs_end if rhs_end != -1 else None]
                    if re.search(r"[A-Za-z_\])]\s*[+\-*]\s*[A-Za-z_0-9(]", rhs):
                        hits.append(line_of(idx.masked, f.body_start + am.start()))
            if hits:
                hits = sorted(set(hits))
                res.append(_mk(VulnClass.integer_overflow, f"Unchecked arithmetic (Solidity <0.8) in {f.name}()", Severity.medium, 0.4, f,
                               f"Pragma allows Solidity <0.8 (no built-in overflow checks) and `{f.name}` does arithmetic on state at lines {', '.join(map(str, hits))} without SafeMath.",
                               "Upgrade to Solidity >=0.8 or use SafeMath.", [(h, h) for h in hits], idx,
                               ["pragma solidity <0.8 (no checked arithmetic)"] + [f"{f.name}(): arithmetic on state at L{h}" for h in hits],
                               "heuristic: pre-0.8-arithmetic"))
        return res
