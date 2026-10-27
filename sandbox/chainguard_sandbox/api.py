"""Public sandbox interface used by the backend (see docs/INTEGRATION.md).

    analyze(source, filename, *, timeout_s=60) -> dict
    validate(source, filename, finding, *, timeout_s=60) -> {"status", "details", ...}

Backend selection: env CG_SANDBOX_BACKEND = "local" (default; Linux user/net/pid/
mount namespaces on this host) or "instabox" (Docker container inside an
InstaBox Firecracker microVM).  Both return the same shapes.  Extra keys
(e.g. "backend", "evidence") may be present; callers must ignore unknown keys.

Neither function raises for bad input or tool failure: errors come back as
ok=false / status="error" with a message.  Nothing is ever faked.
"""
from __future__ import annotations

import os
import re
import unicodedata
from typing import Any

MAX_SOURCE_BYTES = 512 * 1024  # mirrors chainguard_contract.models.MAX_UPLOAD_BYTES
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


class InputError(ValueError):
    pass


def sanitize_filename(filename: str) -> str:
    """Reduce an untrusted filename to a safe basename ending in .sol.
    Rejects NUL/control chars and anything that is empty after sanitising.
    Path components are stripped (../../etc/passwd.sol -> passwd.sol)."""
    if not isinstance(filename, str) or not filename:
        raise InputError("filename is required")
    if any(ord(c) < 32 or ord(c) == 127 for c in filename):
        raise InputError("filename contains NUL or control characters")
    if len(filename) > 255:
        raise InputError("filename too long")
    base = unicodedata.normalize("NFKC", filename).replace("\\", "/").split("/")[-1]
    base = _SAFE.sub("_", base).lstrip(".")
    if not base or base in (".", ".."):
        raise InputError("filename is empty after sanitising")
    if not base.endswith(".sol"):
        raise InputError("filename must end with .sol")
    if base in ("request.json",):
        raise InputError("reserved filename")
    return base[:100] if len(base) <= 100 else base[:96] + ".sol"


def _check_source(source: Any) -> bytes:
    if isinstance(source, bytes):
        data = source
    elif isinstance(source, str):
        data = source.encode("utf-8", errors="strict")
    else:
        raise InputError("source must be str or bytes")
    if not data.strip():
        raise InputError("source is empty")
    if len(data) > MAX_SOURCE_BYTES:
        raise InputError(f"source exceeds {MAX_SOURCE_BYTES} bytes")
    if b"\x00" in data:
        raise InputError("source contains NUL bytes (binary file?)")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError("source is not valid UTF-8")
    return data


def backend_name() -> str:
    return (os.environ.get("CG_SANDBOX_BACKEND") or "local").strip().lower()


def _backend():
    name = backend_name()
    if name == "instabox":
        from . import instabox
        return instabox.BACKEND
    if name in ("", "local"):
        from . import runner
        return runner.BACKEND
    raise InputError(f"unknown CG_SANDBOX_BACKEND={name!r} (expected local|instabox)")


def _empty_analysis(error: str, backend: str) -> dict:
    return {"ok": False, "error": error, "solc_version": None, "contracts": [],
            "compile": {"ok": False, "stderr": ""}, "ast": None,
            "slither": {"ok": False, "detectors": [], "error": "not run"},
            "graphs": None, "resource": {"wall_s": 0.0, "max_rss_mb": 0.0}, "backend": backend}


def analyze(source: str, filename: str, *, timeout_s: float = 60) -> dict:
    bname = backend_name()
    try:
        fname = sanitize_filename(filename)
        data = _check_source(source)
        backend = _backend()
    except InputError as e:
        return _empty_analysis(f"invalid input: {e}", bname)
    from .runner import Limits
    lim = Limits(wall_s=float(timeout_s), cpu_s=int(timeout_s) + 5)
    rr = backend.run("analyze", {"filename": fname, "solc_timeout": max(5.0, timeout_s * 0.6)},
                     {fname: data}, lim)
    if not rr.ok or not isinstance(rr.result, dict):
        out = _empty_analysis(rr.error or "sandbox failed", backend.name)
        out["resource"] = {"wall_s": rr.wall_s, "max_rss_mb": rr.max_rss_mb}
        if rr.result and isinstance(rr.result, dict) and rr.result.get("error"):
            out["error"] = rr.result["error"]
        return out
    res = rr.result
    base = _empty_analysis("", backend.name)
    base.update({k: v for k, v in res.items() if k in base or k in ("traceback",)})
    base["backend"] = backend.name
    base["resource"] = {"wall_s": rr.wall_s, "max_rss_mb": max(rr.max_rss_mb,
                        float((res.get("resource") or {}).get("max_rss_mb") or 0))}
    if not base.get("ok") and not base.get("error"):
        base["error"] = "analysis failed"
    return base


def validate(source: str, filename: str, finding: dict, *, timeout_s: float = 60) -> dict:
    bname = backend_name()
    try:
        fname = sanitize_filename(filename)
        data = _check_source(source)
        if not isinstance(finding, dict):
            raise InputError("finding must be a dict")
        backend = _backend()
    except InputError as e:
        return {"status": "error", "details": f"invalid input: {e}", "backend": bname}
    from .runner import Limits
    from .validators import plan_or_reason
    plan, reason = plan_or_reason(finding)
    if plan is None:
        return {"status": "not_applicable", "details": reason, "backend": backend.name}
    lim = Limits(wall_s=float(timeout_s), cpu_s=int(timeout_s) + 5, mem_mb=3072)
    safe_finding = {k: finding.get(k) for k in ("vuln_class", "function_name", "contract_name", "title", "id")}
    rr = backend.run("validate", {"filename": fname, "finding": safe_finding}, {fname: data}, lim)
    if not rr.ok or not isinstance(rr.result, dict):
        return {"status": "error", "details": rr.error or "sandbox failed", "backend": backend.name,
                "resource": {"wall_s": rr.wall_s, "max_rss_mb": rr.max_rss_mb}}
    out = dict(rr.result)
    if out.get("status") not in ("confirmed", "not_reproduced", "not_applicable", "error"):
        out = {"status": "error", "details": "worker returned no valid status: " + str(out.get("error"))[:500]}
    out.setdefault("details", "")
    out["backend"] = backend.name
    out["resource"] = {"wall_s": rr.wall_s, "max_rss_mb": rr.max_rss_mb}
    return out
