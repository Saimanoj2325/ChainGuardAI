#!/usr/bin/env python3
"""Build fixtures/manifest.json (ground truth for SYNTHETIC fixtures) from anchors.

Line numbers are never typed by hand: each expected finding names code anchors (exact substrings),
the script locates them inside the named function and records 1-based line ranges.
`--check` fails if the committed manifest differs from what the files currently produce.
"""
from __future__ import annotations
import hashlib, json, pathlib, re, sys

FIX = pathlib.Path(__file__).resolve().parents[1]
C = FIX / "contracts"
MAX_UPLOAD_BYTES = 512 * 1024

# Observed-outcome vocabulary used by tests/e2e (see tests/e2e/README.md):
#   job_completed       completed, analysis ran
#   completed_degraded  completed but with a failed stage event / error note and zero findings
#   job_failed          job status=failed with a non-empty error
#   rejected_413        submit returned 413
#   rejected_4xx        submit returned another 4xx (400/415/422)
# Never acceptable: server_error (5xx), timeout (job never finished), transport errors.
GRACEFUL_REJECT = ["rejected_4xx", "job_failed", "completed_degraded"]
ANALYZE_OR_LIMIT = ["job_completed", "completed_degraded", "job_failed", "rejected_4xx"]

V = {  # vulnerable ground truth
    "reentrancy_classic.sol": [dict(cls="reentrancy", fn="withdraw", anchors=["msg.sender.call{value: amount}", "balances[msg.sender] = 0;"],
                                    note="external call before balance reset (0.8.x; checked arithmetic does not help)")],
    "reentrancy_cross_function.sol": [dict(cls="reentrancy", fn="withdrawBalance", anchors=["msg.sender.call{value: amountToWithdraw}", "userBalances[msg.sender] = 0;"],
                                           related_functions=["transfer"], note="re-enter transfer() during the call while balance is still set")],
    "unchecked_call.sol": [dict(cls="unchecked_call", fn="payOut", anchors=["msg.sender.send(amount);"]),
                           dict(cls="unchecked_call", fn="forward", anchors=["target.call.value(amount)();"])],
    "tx_origin.sol": [dict(cls="tx_origin", fn="transferTo", anchors=["tx.origin == owner"])],
    "timestamp_dependence.sol": [dict(cls="timestamp_dependence", fn="play", anchors=["require(now != pastBlockTime", "if (now % 15 == 0)"])],
    "integer_overflow.sol": [dict(cls="integer_overflow", fn="transfer", anchors=["balances[msg.sender] - value >= 0", "balances[msg.sender] -= value;"]),
                             dict(cls="integer_overflow", fn="batchTransfer", anchors=["receivers.length * value"])],
    "integer_overflow_timelock.sol": [dict(cls="integer_overflow", fn="increaseLockTime", anchors=["lockTime[msg.sender] += secondsToIncrease;"])],
    "access_control_owner.sol": [dict(cls="access_control", fn="setOwner", anchors=["function setOwner", "owner = newOwner;"])],
    "access_control_initializer.sol": [dict(cls="access_control", fn="initialize", anchors=["function initialize", "withdrawLimit = _limit;"])],
    "delegatecall.sol": [dict(cls="delegatecall", fn="execute", anchors=["target.delegatecall(data)"])],
    "unprotected_selfdestruct.sol": [dict(cls="unprotected_selfdestruct", fn="close", anchors=["selfdestruct(msg.sender);"])],
    "dos_unbounded_loop.sol": [dict(cls="denial_of_service", fn="distribute", anchors=["for (uint256 i = 0; i < shareholders.length; i++)", "shareholders[i].transfer(share);"])],
    "dos_push_payment.sol": [dict(cls="denial_of_service", fn="claimThrone", anchors=["require(king.send(highestBid)"])],
    "bad_randomness.sol": [dict(cls="bad_randomness", fn="flip", anchors=["blockhash(block.number - 1)", "bool side = entropy % 2 == 1;"])],
}
# Classes that are defensible secondary reports on a file: not counted as FP in the "lenient" FP figure.
ACCEPTABLE_EXTRA = {
    "vulnerable/timestamp_dependence.sol": ["bad_randomness"],
    "vulnerable/bad_randomness.sol": ["timestamp_dependence"],
    "vulnerable/integer_overflow_timelock.sol": ["timestamp_dependence"],
    "vulnerable/delegatecall.sol": ["access_control"],
    "vulnerable/unprotected_selfdestruct.sol": ["access_control"],
    "vulnerable/unchecked_call.sol": ["other"],
    "vulnerable/dos_unbounded_loop.sol": ["other"],
    "patched/reentrancy_classic.sol": ["reentrancy"],
    "patched/reentrancy_cross_function.sol": ["reentrancy"],
    "patched/integer_overflow_timelock.sol": ["timestamp_dependence"],
    "patched/delegatecall.sol": ["delegatecall"],
    "patched/dos_unbounded_loop.sol": ["denial_of_service", "reentrancy"],
    "patched/dos_push_payment.sol": ["reentrancy"],
    "patched/bad_randomness.sol": ["bad_randomness", "timestamp_dependence"],
    "patched/timestamp_dependence.sol": ["bad_randomness"],
    "patched/unchecked_call.sol": ["other"],
    "benign/multisig_lite.sol": ["reentrancy", "unchecked_call", "other"],
    "benign/coarse_timelock.sol": ["timestamp_dependence"],
    "benign/pull_payment_escrow.sol": ["reentrancy"],
}
PATCH_NOTES = {
    "reentrancy_classic.sol": "checks-effects-interactions + nonReentrant modifier",
    "reentrancy_cross_function.sol": "state reset before call; nonReentrant on both withdrawBalance and transfer",
    "unchecked_call.sol": "require() on send/call return values",
    "tx_origin.sol": "msg.sender instead of tx.origin",
    "timestamp_dependence.sol": "payout decided by owner commit-reveal, not block.timestamp",
    "integer_overflow.sol": "SafeMath library (0.4.26)",
    "integer_overflow_timelock.sol": "upgraded to solc 0.8.24 checked arithmetic",
    "access_control_owner.sol": "onlyOwner on setOwner + zero-address check",
    "access_control_initializer.sol": "initializer restricted to deployer and one-shot flag",
    "delegatecall.sol": "owner-only and allow-listed delegatecall targets",
    "unprotected_selfdestruct.sol": "owner check; funds go to owner",
    "dos_unbounded_loop.sol": "paginated allocation + pull-payment claim",
    "dos_push_payment.sol": "pull-payment refunds",
    "bad_randomness.sol": "house commit-reveal secret instead of block values",
}
BENIGN = {
    "simple_token.sol": "ERC20-like token with 0.8 checked arithmetic",
    "simple_storage.sol": "owner-gated storage",
    "multisig_lite.sol": "2-of-3 multisig; executed flag set before low-level call with checked result (possible reentrancy/low-level-call FP)",
    "coarse_timelock.sol": "block.timestamp only for a day-granularity release window (possible timestamp_dependence FP)",
    "pull_payment_escrow.sol": "pull-payment escrow following CEI (possible reentrancy FP)",
}
MALFORMED = {
    "syntax_error.sol": ("compile_error", GRACEFUL_REJECT, "missing ';' and unbalanced parens"),
    "unsupported_pragma.sol": ("compile_error", GRACEFUL_REJECT, "pragma ^0.3.0 predates all supported solc releases"),
    "empty.sol": ("reject_400", GRACEFUL_REJECT, "zero bytes"),
    "binary_garbage.sol": ("reject_400", GRACEFUL_REJECT, "ELF magic + 4 KiB deterministic random bytes (seed 1337)"),
    "non_utf8.sol": ("reject_400", GRACEFUL_REJECT, "latin-1 bytes (invalid UTF-8) in comment and string literal"),
    "long_line.sol": ("analyze_or_limit", ANALYZE_OR_LIMIT, "~80 KB single line (40000-term constant sum); valid Solidity, compiles with solc 0.8.24"),
}
RESOURCE = {
    "deep_nesting.sol": (False, "timeout_or_limit", ANALYZE_OR_LIMIT, "250-level nested parentheses; solc 0.8.24 reports 'Maximum recursion depth reached during parsing'"),
    "many_functions.sol": (False, "analyze_or_limit", ANALYZE_OR_LIMIT, "2000 trivial external functions (~167 KB)"),
    "generated/huge_contract.sol": (True, "timeout_or_limit", ANALYZE_OR_LIMIT, "~460 KB generated contract just under the 512 KiB upload limit"),
    "generated/oversize.sol": (True, "reject_413", ["rejected_413"], "> 512 KiB generated file; must be rejected before analysis"),
}


def pragma(src: str):
    m = re.search(r"pragma\s+solidity\s+([^;]+);", src)
    return m.group(1).strip() if m else None


def function_span(lines: list[str], fn: str) -> tuple[int, int]:
    pat = re.compile(rf"\bfunction\s+{re.escape(fn)}\s*\(")
    hits = [i for i, l in enumerate(lines) if pat.search(l)]
    if len(hits) != 1:
        raise SystemExit(f"function {fn}: expected exactly 1 definition, found {len(hits)}")
    start, depth, seen = hits[0], 0, False
    for j in range(start, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        seen = seen or "{" in lines[j]
        if seen and depth == 0:
            return start + 1, j + 1
    raise SystemExit(f"unterminated function {fn}")


def anchor_range(lines, fs, fe, anchors, label):
    nums = []
    for a in anchors:
        found = [i + 1 for i in range(fs - 1, fe) if a in lines[i]]
        if len(found) != 1:
            raise SystemExit(f"{label}: anchor {a!r} found {len(found)} times inside function lines {fs}-{fe}")
        nums.append(found[0])
    return min(nums), max(nums)


def contract_names(src):
    return re.findall(r"^\s*(?:abstract\s+)?(?:contract|library)\s+(\w+)", src, re.M)


def entry(cat, name, path: pathlib.Path, **extra):
    raw = path.read_bytes() if path.exists() else None
    e = {"path": f"fixtures/contracts/{cat}/{name}", "category": cat, "synthetic": True}
    if raw is not None:
        e["sha256"] = hashlib.sha256(raw).hexdigest(); e["size_bytes"] = len(raw)
        try:
            src = raw.decode("utf-8"); e["pragma"] = pragma(src); e["contracts"] = contract_names(src)
        except UnicodeDecodeError:
            e["pragma"] = None; e["contracts"] = []
    e.update(extra)
    return e


def build():
    out = []
    for name, exp in V.items():
        p = C / "vulnerable" / name; lines = p.read_text().splitlines()
        findings = []
        for x in exp:
            fs, fe = function_span(lines, x["fn"])
            s, t = anchor_range(lines, fs, fe, x["anchors"], f"vulnerable/{name}")
            f = {"vuln_class": x["cls"], "function": x["fn"], "lines": [{"start": s, "end": t}],
                 "function_lines": {"start": fs, "end": fe}, "anchors": x["anchors"]}
            if "related_functions" in x: f["related_functions"] = x["related_functions"]
            if "note" in x: f["note"] = x["note"]
            findings.append(f)
        out.append(entry("vulnerable", name, p, expected_outcome="analyze", accept=["job_completed"],
                         expected_findings=findings, acceptable_extra_classes=ACCEPTABLE_EXTRA.get(f"vulnerable/{name}", []),
                         counterpart=f"fixtures/contracts/patched/{name}"))
    for name in V:
        p = C / "patched" / name
        assert p.exists(), f"missing patched counterpart {name}"
        out.append(entry("patched", name, p, expected_outcome="analyze", accept=["job_completed"], expected_findings=[],
                         acceptable_extra_classes=ACCEPTABLE_EXTRA.get(f"patched/{name}", []), fix=PATCH_NOTES[name],
                         counterpart=f"fixtures/contracts/vulnerable/{name}"))
    for name, note in BENIGN.items():
        out.append(entry("benign", name, C / "benign" / name, expected_outcome="analyze", accept=["job_completed"], expected_findings=[],
                         acceptable_extra_classes=ACCEPTABLE_EXTRA.get(f"benign/{name}", []), note=note))
    for name, (eo, acc, note) in MALFORMED.items():
        out.append(entry("malformed", name, C / "malformed" / name, expected_outcome=eo, accept=acc, expected_findings=[], note=note))
    for name, (gen, eo, acc, note) in RESOURCE.items():
        p = C / "resource" / name
        e = entry("resource", name, p, expected_outcome=eo, accept=acc, expected_findings=[], note=note, generated=gen)
        if gen:
            for k in ("sha256", "size_bytes", "pragma", "contracts"): e.pop(k, None)
            e["generator"] = "python fixtures/scripts/gen_resource.py --generated"
        out.append(e)
    names = {e["path"] for e in out}
    for cat in ("vulnerable", "patched", "benign", "malformed", "resource"):
        for p in (C / cat).glob("*.sol"):
            assert f"fixtures/contracts/{cat}/{p.name}" in names, f"fixture not in manifest: {cat}/{p.name}"
    return {"schema": "chainguard-fixture-manifest/1", "synthetic": True,
            "notice": "SYNTHETIC hand-written fixtures for integration testing. Never report results on these as benchmark metrics.",
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "outcome_vocabulary": ["job_completed", "completed_degraded", "job_failed", "rejected_413", "rejected_4xx",
                                   "server_error", "timeout", "transport_error"],
            "line_numbering": "1-based, inclusive; computed from anchors by fixtures/scripts/build_manifest.py",
            "fixtures": out}


if __name__ == "__main__":
    m = json.dumps(build(), indent=2) + "\n"
    target = FIX / "manifest.json"
    if "--check" in sys.argv:
        ok = target.exists() and target.read_text() == m
        print("manifest up to date" if ok else "manifest.json is stale; run python fixtures/scripts/build_manifest.py")
        sys.exit(0 if ok else 1)
    target.write_text(m); print("wrote", target)
