#!/usr/bin/env python3
"""Deterministic generator for SYNTHETIC resource-stress fixtures (ChainGuard AI).

Committed (small, regenerated identically):
  fixtures/contracts/resource/deep_nesting.sol
  fixtures/contracts/resource/many_functions.sol
Generated at test time (large; git-ignored under resource/generated/):
  fixtures/contracts/resource/generated/huge_contract.sol   (~460 KB, just under the 512 KiB limit)
  fixtures/contracts/resource/generated/oversize.sol        (> 512 KiB, must be rejected with 413)

Usage: python fixtures/scripts/gen_resource.py [--committed] [--generated] [--check]
"""
from __future__ import annotations
import argparse, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1] / "contracts" / "resource"
GEN = ROOT / "generated"
HEADER = "// SPDX-License-Identifier: MIT\n// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.\n"
MAX_UPLOAD_BYTES = 512 * 1024


def deep_nesting(depth: int = 250) -> str:
    expr = "x"
    for i in range(depth):
        expr = f"(({expr}) + {i % 7 + 1})"
    return (HEADER + "pragma solidity 0.8.24;\n\ncontract DeepNesting {\n"
            "    function compute(uint256 x) external pure returns (uint256) {\n"
            f"        unchecked {{ return {expr}; }}\n    }}\n}}\n")


def many_functions(n: int = 2000) -> str:
    fns = "".join(f"    function f{i:05d}(uint256 a) external pure returns (uint256) {{ return a + {i}; }}\n" for i in range(n))
    return HEADER + "pragma solidity 0.8.24;\n\ncontract ManyFunctions {\n" + fns + "}\n"


def _filler_contract(target_bytes: int, name: str) -> str:
    out = [HEADER, "pragma solidity 0.8.24;\n\n", f"contract {name} {{\n", "    mapping(uint256 => uint256) internal store;\n"]
    size = sum(len(s) for s in out)
    i = 0
    while size < target_bytes:
        s = (f"    function g{i:06d}(uint256 a, uint256 b) external {{\n"
             f"        uint256 c = a * {i % 97 + 1} + b;\n"
             f"        if (c > {i}) {{ store[{i}] = c; }} else {{ store[{i}] = b; }}\n"
             f"    }}\n")
        out.append(s); size += len(s); i += 1
    out.append("}\n")
    return "".join(out)


def huge_contract() -> str:
    return _filler_contract(460 * 1024, "HugeContract")


def oversize() -> str:
    return _filler_contract(MAX_UPLOAD_BYTES + 64 * 1024, "Oversize")


COMMITTED = {"deep_nesting.sol": deep_nesting, "many_functions.sol": many_functions}
GENERATED = {"huge_contract.sol": huge_contract, "oversize.sol": oversize}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--committed", action="store_true")
    ap.add_argument("--generated", action="store_true")
    ap.add_argument("--check", action="store_true", help="verify committed files match the generator")
    a = ap.parse_args()
    if a.check:
        bad = [n for n, f in COMMITTED.items() if (ROOT / n).read_text() != f()]
        print("mismatch:" if bad else "committed resource fixtures match generator", *bad)
        return 1 if bad else 0
    if not (a.committed or a.generated):
        a.generated = True
    if a.committed:
        for n, f in COMMITTED.items():
            (ROOT / n).write_text(f()); print("wrote", ROOT / n)
    if a.generated:
        GEN.mkdir(parents=True, exist_ok=True)
        for n, f in GENERATED.items():
            p = GEN / n; p.write_text(f()); print("wrote", p, p.stat().st_size, "bytes")
        assert (GEN / "huge_contract.sol").stat().st_size < MAX_UPLOAD_BYTES
        assert (GEN / "oversize.sol").stat().st_size > MAX_UPLOAD_BYTES
    return 0


if __name__ == "__main__":
    sys.exit(main())
