# ChainGuard AI — Integration Plan & Ownership

## Single sources of truth
| What | Where | Owner |
|---|---|---|
| API schemas | `shared/chainguard_contract/models.py` → `contracts/openapi.json` (regenerate with `python shared/export_openapi.py`) | Lead / Integration |
| Report hashing | `shared/chainguard_contract/hashing.py` (sha256 over canonical JSON, sorted keys, `(",",":")` separators, excluding `report_hash` and `registry`) | Lead |
| Analyzer plugin interface | `shared/chainguard_contract/analyzer.py` | Lead |
| Sandbox interface | `sandbox/README.md` + `sandbox/chainguard_sandbox/api.py` | Sandbox |
| Test fixtures | `fixtures/contracts/{vulnerable,patched,benign,malformed,resource}` + `fixtures/manifest.json` | Integration |

Schema changes: only via edit to `models.py` + regenerate `openapi.json` in the same commit. Never hand-edit openapi.json.

## Directory ownership (avoid conflicting edits)
- `ml/` — Agent 1 (Dataset & ML)
- `frontend/` — Agent 2 (Frontend)
- `backend/` — Agent 3 (Backend/API)
- `sandbox/` — Agent 4 (Sandbox & Security)
- `fixtures/`, `tests/e2e/`, `docs/INTEGRATION.md`, `.github/` — Agent 5 / Lead

## Pipeline (job stages = `JobStage` enum)
received → parsing (sandbox) → static_analysis (Slither in sandbox + heuristic) → ml_inference (GNN or baseline; skipped with an explicit event if no trained model) → evidence → llm_verification (skipped if no LLM key configured; never faked) → evm_validation (sandbox, Foundry/anvil) → reporting (hash + registry append) → done

## Sandbox ⇄ Backend interface
Backend calls `chainguard_sandbox.api.analyze(source: str, filename: str, *, timeout_s=60) -> dict` returning:
```
{ "ok": bool, "error": str|None, "solc_version": str|None, "contracts": [str],
  "compile": {"ok": bool, "stderr": str},
  "ast": dict|None,                 # solc compact AST
  "slither": {"ok": bool, "detectors": [ {check, impact, confidence, description, elements:[{name,type,function,contract,lines:[int]}]} ], "error": str|None},
  "graphs": {...} | None,           # optional: function-level CFG/DFG summary for ML
  "resource": {"wall_s": float, "max_rss_mb": float} }
```
and `chainguard_sandbox.api.validate(source, filename, finding: dict, *, timeout_s=60) -> {"status": "confirmed|not_reproduced|not_applicable|error", "details": str}`.
All execution of untrusted code happens in a child process with no network (user+net namespace), rlimits (CPU, AS, FSIZE, NPROC), a private temp dir, and a scrubbed env.

## Honesty rules
- Mock data: only in `frontend/src/mocks/`, every mock finding has `is_mock: true`, reports with mocks set `contains_mock_data: true`, UI shows a MOCK banner.
- No fake inference. Analyzer failure → `AnalyzerError` → stage event `failed` + job error/degraded note.
- Synthetic fixtures (`fixtures/`) are never reported as benchmark results. Benchmark metrics live in `ml/reports/` with dataset name, split, seed, and command.
- The "registry" is a local append-only hash chain (optionally anchored on a local anvil chain). It is not a public blockchain; say so.
