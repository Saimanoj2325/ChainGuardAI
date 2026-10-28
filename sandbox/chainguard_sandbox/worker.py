"""Sandbox worker: runs INSIDE the isolated child (local namespaces or the
InstaBox Docker container).  Reads <jobdir>/in/request.json + the source file,
writes <jobdir>/out/result.json.  Never touches the network.

Modes
  analyze   solc compile check + compact AST, Slither detectors, function graph summary
  validate  behavioural validation of one finding with `forge test` (offline)

Usage: python -I worker.py <jobdir>
"""
from __future__ import annotations

import json
import os
try:
    import resource
except ImportError:
    resource = None
import subprocess
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # package import under -I
from chainguard_sandbox import toolchain  # noqa: E402

MAX_AST_BYTES = 8 * 1024 * 1024
MAX_STDERR = 16 * 1024


def _w(jobdir: Path, obj: dict) -> None:
    out = jobdir / "out" / "result.json"
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj))
    tmp.replace(out)


def _solc_wrapper(jobdir: Path, solc: toolchain.Solc) -> str:
    """An executable `solc` path for crytic-compile / forge (wasm needs a shim)."""
    if solc.kind == "native":
        return solc.path
    bindir = jobdir / "work" / "bin"
    bindir.mkdir(exist_ok=True)
    w = bindir / "solc"
    argv = " ".join("'%s'" % a.replace("'", "'\\''") for a in solc.argv())
    w.write_text("#!/bin/sh\nexec %s \"$@\"\n" % argv)
    w.chmod(0o700)
    return str(w)


def compile_standard_json(solc: toolchain.Solc, filename: str, source: str, timeout: float,
                          bytecode: bool = True) -> tuple[bool, dict | None, str]:
    sel = ["abi"] + (["evm.bytecode.object"] if bytecode else [])
    inp = {"language": "Solidity", "sources": {filename: {"content": source}},
           "settings": {"outputSelection": {"*": {"": ["ast"], "*": sel}}}}
    try:
        p = subprocess.run(solc.argv() + ["--standard-json"], input=json.dumps(inp).encode(),
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, None, f"solc timed out after {timeout:.0f}s"
    try:
        out = json.loads(p.stdout.decode(errors="replace") or "{}")
    except ValueError:
        return False, None, ("solc produced no JSON (exit %s): " % p.returncode
                             + p.stderr.decode(errors="replace")[:MAX_STDERR])
    errs = out.get("errors", [])
    msgs = "\n".join(e.get("formattedMessage", e.get("message", "")) for e in errs)
    ok = not any(e.get("severity") == "error" for e in errs) and p.returncode == 0 and "sources" in out
    if not ok and not msgs:
        msgs = "solc exit %s: %s" % (p.returncode, p.stderr.decode(errors="replace")[:MAX_STDERR])
    return ok, out, msgs[:MAX_STDERR]


def contracts_from_ast(ast: dict | None) -> list[str]:
    if not ast:
        return []
    return [n.get("name") for n in ast.get("nodes", []) if n.get("nodeType") == "ContractDefinition"]


# ---------------------------------------------------------------- slither
def run_slither(src_path: Path, solc_exe: str) -> tuple[dict, dict | None]:
    try:
        from crytic_compile import CryticCompile
        from crytic_compile.platform.solc_standard_json import SolcStandardJson
        from slither import Slither
        from slither.detectors import all_detectors
        from slither.detectors.abstract_detector import AbstractDetector
    except Exception as e:  # pragma: no cover
        return {"ok": False, "detectors": [], "error": f"slither import failed: {e}"}, None
    try:
        sj = SolcStandardJson()
        sj.add_source_file(str(src_path))
        cc = CryticCompile(sj, solc=solc_exe, solc_working_dir=str(src_path.parent))
        sl = Slither(cc)
        for name in dir(all_detectors):
            d = getattr(all_detectors, name)
            if isinstance(d, type) and issubclass(d, AbstractDetector) and d is not AbstractDetector:
                sl.register_detector(d)
        results = [r for batch in sl.run_detectors() for r in batch]
    except Exception as e:
        return {"ok": False, "detectors": [], "error": f"{type(e).__name__}: {str(e)[:2000]}"}, None
    dets = []
    for r in results:
        els = []
        for el in r.get("elements", []):
            sm = el.get("source_mapping") or {}
            tsf = el.get("type_specific_fields") or {}
            parent = tsf.get("parent") or {}
            func = contract = None
            if el.get("type") == "function":
                func = el.get("name")
                contract = parent.get("name") if parent.get("type") == "contract" else None
            elif el.get("type") == "contract":
                contract = el.get("name")
            elif parent.get("type") == "function":
                func = parent.get("name")
                gp = (parent.get("type_specific_fields") or {}).get("parent") or {}
                contract = gp.get("name") if gp.get("type") == "contract" else None
            elif parent.get("type") == "contract":
                contract = parent.get("name")
            els.append({"name": el.get("name"), "type": el.get("type"), "function": func,
                        "contract": contract, "lines": list(sm.get("lines") or [])})
        dets.append({"check": r.get("check"), "impact": r.get("impact"), "confidence": r.get("confidence"),
                     "description": (r.get("description") or "").strip()[:4000], "elements": els})
    return {"ok": True, "detectors": dets, "error": None}, graphs_summary(sl)


def graphs_summary(sl) -> dict:
    fns = []
    try:
        for c in sl.contracts:
            for f in c.functions_and_modifiers_declared:
                nodes = list(f.nodes)
                edges = [[n.node_id, s.node_id] for n in nodes for s in n.sons]
                fns.append({
                    "contract": c.name, "function": f.name, "visibility": f.visibility,
                    "payable": bool(getattr(f, "payable", False)),
                    "modifiers": [m.name for m in f.modifiers],
                    "cfg_nodes": [{"id": n.node_id, "type": str(n.type).split(".")[-1],
                                   "expr": str(n.expression)[:200] if n.expression else None,
                                   "lines": list(n.source_mapping.lines)[:20]} for n in nodes][:400],
                    "cfg_edges": edges[:1000],
                    "state_vars_read": sorted(v.name for v in f.state_variables_read),
                    "state_vars_written": sorted(v.name for v in f.state_variables_written),
                    "external_calls": len(f.external_calls_as_expressions),
                    "low_level_calls": len(f.low_level_calls),
                })
    except Exception as e:
        return {"error": f"graph extraction failed: {e}", "functions": fns}
    return {"kind": "slither-cfg", "functions": fns}


def _rss_mb() -> float:
    if resource is not None:
        try:
            r = max(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
            return round(r / 1024, 1)
        except Exception:
            pass
    try:
        import psutil
        return round(psutil.Process().memory_info().rss / (1024 * 1024), 1)
    except Exception:
        return 0.0


def do_analyze(jobdir: Path, req: dict) -> dict:
    t0 = time.monotonic()
    fname = req["filename"]
    src_path = jobdir / "in" / fname
    source = src_path.read_text(encoding="utf-8")
    res = {"ok": False, "error": None, "solc_version": None, "contracts": [],
           "compile": {"ok": False, "stderr": ""}, "ast": None,
           "slither": {"ok": False, "detectors": [], "error": "not run"}, "graphs": None,
           "resource": {"wall_s": 0.0, "max_rss_mb": 0.0}}
    solc, why = toolchain.select_solc(source)
    if solc is None:
        res["error"] = why
        res["compile"]["stderr"] = why
        res["slither"]["error"] = "not run: no compiler"
        return res
    res["solc_version"] = solc.version
    ok, out, msgs = compile_standard_json(solc, fname, source, timeout=float(req.get("solc_timeout", 45)))
    res["compile"] = {"ok": ok, "stderr": msgs}
    ast = ((out or {}).get("sources", {}).get(fname) or {}).get("ast")
    if ast is not None and len(json.dumps(ast)) <= MAX_AST_BYTES:
        res["ast"] = ast
    elif ast is not None:
        res["compile"]["stderr"] += "\n[sandbox] AST omitted: larger than %d bytes" % MAX_AST_BYTES
    res["contracts"] = contracts_from_ast(ast)
    if not ok:
        res["error"] = "compilation failed" + (": " + msgs.splitlines()[0] if msgs else "")
        res["slither"]["error"] = "not run: compilation failed"
        return res
    if req.get("run_slither", True):
        res["slither"], res["graphs"] = run_slither(src_path, _solc_wrapper(jobdir, solc))
    else:
        res["slither"]["error"] = "not run: disabled"
    res["ok"] = True
    res["error"] = None if res["slither"]["ok"] else "slither failed: " + str(res["slither"]["error"])[:500]
    res["resource"] = {"wall_s": round(time.monotonic() - t0, 3), "max_rss_mb": _rss_mb()}
    return res


def main() -> None:
    jobdir = Path(sys.argv[1])
    t0 = time.monotonic()
    try:
        req = json.loads((jobdir / "in" / "request.json").read_text())
        if req["mode"] == "analyze":
            res = do_analyze(jobdir, req)
        elif req["mode"] == "validate":
            from chainguard_sandbox import validators
            res = validators.validate(jobdir, req)
        elif req["mode"] == "selftest":
            from chainguard_sandbox import selftest
            res = selftest.run(jobdir, req)
        else:
            res = {"ok": False, "error": "unknown mode"}
    except MemoryError:
        res = {"ok": False, "error": "worker ran out of memory (RLIMIT_AS)"}
    except Exception as e:
        res = {"ok": False, "error": f"worker crashed: {type(e).__name__}: {e}",
               "traceback": traceback.format_exc()[-3000:]}
    res.setdefault("resource", {})
    res["resource"].setdefault("wall_s", round(time.monotonic() - t0, 3))
    res["resource"].setdefault("max_rss_mb", _rss_mb())
    _w(jobdir, res)


if __name__ == "__main__":
    main()
