# ChainGuard AI fixtures — SYNTHETIC

Hand-written, synthetic Solidity contracts for integration and E2E testing. **They are not a benchmark**:
never quote detection numbers on these as model/tool accuracy (benchmark metrics live in `ml/reports/`).

| dir | purpose |
|---|---|
| `contracts/vulnerable/` | one or more seeded bugs per `VulnClass` (mixed solc 0.4.26 / 0.6.12 / 0.8.24) |
| `contracts/patched/` | fixed counterpart with the same filename |
| `contracts/benign/` | realistic safe contracts; documented possible false positives in the manifest |
| `contracts/malformed/` | syntax error, garbage bytes, empty, non-UTF-8, 80 KB line, unsupported pragma |
| `contracts/resource/` | deep nesting, 2000 functions; `generated/` (git-ignored) holds the ~460 KB and >512 KiB files |

* `manifest.json` — ground truth: expected classes, functions, 1-based inclusive line ranges, acceptable outcomes.
  Built from code anchors: `python fixtures/scripts/build_manifest.py` (`--check` to verify it is current).
* `python fixtures/scripts/gen_resource.py --generated` — create the large resource files (the E2E harness does this itself).
* `python fixtures/scripts/compile_check.py` — compile check → `COMPILE_CHECK.md`, `compile_check.json`.
  Uses native solc via py-solc-x on x86_64; on other arches uses solc-js (`SOLJSON_DIR`, `SOLCJS_NODE_PATH`).
