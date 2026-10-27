#!/usr/bin/env python3
"""Compile-check SYNTHETIC fixtures and write fixtures/COMPILE_CHECK.md + fixtures/compile_check.json.

Backend order: native solc via py-solc-x (x86_64), else solc-js (node + npm `solc` + soljson builds,
which works on aarch64 where native static binaries do not run).
Env: SOLJSON_DIR (dir with soljson-v<ver>+commit.*.js), SOLCJS_NODE_PATH (dir containing node_modules/solc).
"""
from __future__ import annotations
import json, os, pathlib, platform, re, subprocess, sys, datetime

FIX = pathlib.Path(__file__).resolve().parents[1]
CATS = ["vulnerable", "patched", "benign", "malformed", "resource"]
SOLJSON_DIR = pathlib.Path(os.environ.get("SOLJSON_DIR", pathlib.Path.home() / ".cache/chainguard/soljson"))
NODE_PATH = os.environ.get("SOLCJS_NODE_PATH", "/tmp/solcjs/node_modules")


def pragma_version(src: str) -> str | None:
    m = re.search(r"pragma\s+solidity\s+[\^>=<~ ]*([0-9]+\.[0-9]+\.[0-9]+)", src)
    return m.group(1) if m else None


def native(ver: str, path: pathlib.Path):
    import solcx
    try:
        solcx.install_solc(ver)
    except Exception as e:
        raise RuntimeError(f"native solc {ver} unavailable: {e}")
    try:
        solcx.compile_files([str(path)], output_values=["abi"], solc_version=ver)
        return {"version": ver, "ok": True, "errors": [], "backend": "solcx-native"}
    except solcx.exceptions.SolcError as e:
        return {"version": ver, "ok": False, "errors": [str(e.stderr_data)[:2000]], "backend": "solcx-native"}


def solcjs(ver: str, path: pathlib.Path):
    builds = sorted(SOLJSON_DIR.glob(f"soljson-v{ver}+commit.*.js"))
    if not builds:
        raise RuntimeError(f"no soljson build for {ver} in {SOLJSON_DIR}")
    env = dict(os.environ, NODE_PATH=NODE_PATH)
    p = subprocess.run(["node", "--stack-size=8000", str(FIX / "scripts/solcjs_compile.js"), str(builds[0]), str(path)],
                       capture_output=True, text=True, env=env, timeout=600)
    if p.returncode != 0:
        return {"version": ver, "ok": False, "errors": [("solc-js crashed: " + p.stderr)[-1500:]], "backend": "solcjs"}
    r = json.loads(p.stdout); r["backend"] = "solcjs"
    return r


def check(path: pathlib.Path):
    raw = path.read_bytes()
    try:
        src = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"ok": False, "version": None, "errors": ["not valid UTF-8 (not compiled)"], "backend": "none"}
    ver = pragma_version(src)
    if not ver:
        return {"ok": False, "version": None, "errors": ["no exact pragma version found (not compiled)"], "backend": "none"}
    if ver.startswith("0.3"):
        return {"ok": False, "version": ver, "errors": [f"pragma {ver} predates every available solc build"], "backend": "none"}
    errs = []
    if platform.machine() in ("x86_64", "AMD64"):
        try:
            return native(ver, path)
        except RuntimeError as e:
            errs.append(str(e))
    try:
        return solcjs(ver, path)
    except Exception as e:
        errs.append(str(e))
    return {"ok": None, "version": ver, "errors": errs, "backend": "unavailable"}


def main():
    rows = []
    for cat in CATS:
        for p in sorted((FIX / "contracts" / cat).glob("*.sol")):
            r = check(p); r["file"] = f"{cat}/{p.name}"; r["category"] = cat
            rows.append(r)
            print(f"{r['file']:50s} {r.get('version')!s:8s} {r['backend']:13s} ok={r['ok']}", flush=True)
    (FIX / "compile_check.json").write_text(json.dumps(rows, indent=2))
    lines = ["# Fixture compile check (SYNTHETIC fixtures)", "",
             f"Generated {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')} on {platform.machine()} by `python fixtures/scripts/compile_check.py`.", "",
             "Expectation: vulnerable/patched/benign compile cleanly; malformed should fail; resource files are stress inputs.", "",
             "| file | pragma | backend | compiles | note |", "|---|---|---|---|---|"]
    for r in rows:
        note = (r.get("errors") or [""])[0].replace("\n", " ").replace("|", "\\|")[:160]
        lines.append(f"| {r['file']} | {r.get('version') or '-'} | {r['backend']} | {r['ok']} | {note} |")
    bad = [r["file"] for r in rows if r["category"] in ("vulnerable", "patched", "benign") and r["ok"] is not True]
    lines += ["", f"**Unexpected failures in vulnerable/patched/benign:** {', '.join(bad) if bad else 'none'}"]
    (FIX / "COMPILE_CHECK.md").write_text("\n".join(lines) + "\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
