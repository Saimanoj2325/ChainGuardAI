"""Locate the offline toolchain installed by sandbox/setup.sh and pick a solc
version for a source file from its pragma.

Pure functions, no I/O beyond listing the toolchain directory, so they are safe
to use both on the host (api.py) and inside the sandbox (worker.py).
"""
from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PKG_DIR = Path(__file__).resolve().parent
SANDBOX_DIR = PKG_DIR.parent
TOOLCHAIN_DIR = Path(os.environ.get("CHAINGUARD_TOOLCHAIN", SANDBOX_DIR / ".toolchain")).resolve()
NATIVE_DIR = TOOLCHAIN_DIR / "solc" / "native"
WASM_DIR = TOOLCHAIN_DIR / "solc" / "wasm"
NODE_MODULES = TOOLCHAIN_DIR / "node" / "node_modules"
FOUNDRY_BIN = TOOLCHAIN_DIR / "bin"
FORGE_STD = TOOLCHAIN_DIR / "forge-std"
SOLC_WASM_JS = PKG_DIR / "solc_wasm.js"

Version = tuple[int, int, int]


def parse_version(s: str) -> Version:
    a, b, c = (int(x) for x in s.strip().split("+")[0].split("."))
    return (a, b, c)


def fmt(v: Version) -> str:
    return "%d.%d.%d" % v


@dataclass(frozen=True)
class Solc:
    version: str
    kind: str  # "native" | "wasm"
    path: str  # native binary or soljson.js

    def argv(self) -> list[str]:
        """Command prefix that behaves like `solc` for --version / --standard-json."""
        if self.kind == "native":
            return [self.path]
        node = shutil.which("node") or "/usr/bin/node"
        # V8 reserves a huge virtual range for wasm memory, incompatible with
        # RLIMIT_AS; lift the *soft* AS limit for this process only (memory is
        # still bounded by the host-side RSS watchdog / container cgroup).
        prl = shutil.which("prlimit")
        pre = [prl, "--as=unlimited"] if prl else []
        return pre + [node, str(SOLC_WASM_JS), self.path, str(NODE_MODULES)]


def installed() -> dict[Version, Solc]:
    out: dict[Version, Solc] = {}
    if WASM_DIR.is_dir():
        for p in WASM_DIR.glob("soljson-*.js"):
            try:
                v = parse_version(p.name[len("soljson-"):-3])
            except ValueError:
                continue
            out[v] = Solc(fmt(v), "wasm", str(p))
    if NATIVE_DIR.is_dir():  # native wins over wasm for the same version
        for p in NATIVE_DIR.glob("solc-*"):
            if p.suffix == ".tmp" or not os.access(p, os.X_OK):
                continue
            try:
                v = parse_version(p.name[len("solc-"):])
            except ValueError:
                continue
            out[v] = Solc(fmt(v), "native", str(p))
    return out


_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_TERM_RE = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?")


def _term_ok(op: str, want: tuple, v: Version) -> bool:
    major, minor, patch = want
    # wildcard handling
    if op in ("", "=") and (minor is None or patch is None):
        if minor is None:
            return v[0] == major
        return v[0] == major and v[1] == minor
    w = (major, minor or 0, patch or 0)
    if op == "^":
        if w[0] > 0:
            return v >= w and v[0] == w[0]
        if w[1] > 0:
            return v >= w and v[0] == 0 and v[1] == w[1]
        return v == w
    if op == "~":
        if minor is None:
            return v[0] == w[0]
        return v >= w and v[:2] == w[:2]
    return {"": v == w, "=": v == w, ">=": v >= w, "<=": v <= w, ">": v > w, "<": v < w}[op]


def satisfies(spec: str, v: Version) -> bool:
    """npm-style semver subset used by Solidity pragmas (supports ||, ranges, ^, ~)."""
    for alt in spec.split("||"):
        alt = alt.strip()
        if not alt:
            continue
        # hyphen range "a - b"
        m = re.fullmatch(r"(\S+)\s+-\s+(\S+)", alt)
        if m:
            if parse_version(_pad(m.group(1))) <= v <= parse_version(_pad(m.group(2))):
                return True
            continue
        ok = True
        terms = list(_TERM_RE.finditer(alt))
        if not terms:
            continue
        for t in terms:
            op = t.group(1) or ""
            def num(x):
                return None if x in (None, "x", "*") else int(x)
            want = (int(t.group(2)), num(t.group(3)), num(t.group(4)))
            if not _term_ok(op, want, v):
                ok = False
                break
        if ok:
            return True
    return False


def _pad(s: str) -> str:
    parts = s.lstrip("v").split(".")
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts[:3])


def pragmas(source: str) -> list[str]:
    return [m.group(1).strip() for m in _PRAGMA_RE.finditer(_COMMENT_RE.sub("", source))]


def select_solc(source: str) -> tuple[Optional[Solc], str]:
    """Return (solc, reason). Picks the newest installed version satisfying every
    `pragma solidity` in the file; with no pragma, the newest installed."""
    avail = installed()
    if not avail:
        return None, "no solc installed; run sandbox/setup.sh"
    specs = pragmas(source)
    cands = sorted(avail, reverse=True)
    for v in cands:
        try:
            if all(satisfies(s, v) for s in specs):
                return avail[v], ("pragma " + " & ".join(specs)) if specs else "no pragma: newest installed"
        except (ValueError, KeyError):
            return None, f"unparseable pragma: {specs!r}"
    return None, (f"no installed solc satisfies pragma {specs!r}; installed: "
                  + ", ".join(fmt(v) for v in sorted(avail)))
