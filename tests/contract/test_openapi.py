"""Contract tests: contracts/openapi.json is valid OpenAPI 3.1 and is exactly what shared/export_openapi.py generates."""
from __future__ import annotations
import difflib, importlib.util, json, pathlib, sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = ROOT / "contracts" / "openapi.json"
EXPORTER = ROOT / "shared" / "export_openapi.py"


@pytest.fixture(scope="module")
def committed() -> dict:
    return json.loads(SPEC.read_text())


@pytest.fixture(scope="module")
def regenerated() -> dict:
    # Import the exporter as a module (its __main__ block, which writes the file, does not run).
    sys.path.insert(0, str(EXPORTER.parent))
    try:
        spec = importlib.util.spec_from_file_location("cg_export_openapi_under_test", EXPORTER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return json.loads(json.dumps(mod.app.openapi()))
    finally:
        sys.path.remove(str(EXPORTER.parent))


def test_is_openapi_31(committed):
    assert committed["openapi"].startswith("3.1"), committed["openapi"]


def test_spec_validates(committed):
    from openapi_spec_validator import validate
    from openapi_spec_validator.validation import OpenAPIV31SpecValidator
    validate(committed, cls=OpenAPIV31SpecValidator)


def test_committed_matches_generator(committed, regenerated, tmp_path):
    want = json.dumps(regenerated, indent=2, sort_keys=True).splitlines()
    have = json.dumps(committed, indent=2, sort_keys=True).splitlines()
    (tmp_path / "regenerated.json").write_text("\n".join(want))
    diff = "\n".join(difflib.unified_diff(have, want, "contracts/openapi.json", "regenerated", lineterm="", n=2))
    assert committed == regenerated, (
        "contracts/openapi.json is out of sync with shared/chainguard_contract/models.py.\n"
        "Run `python shared/export_openapi.py` and commit both together.\n" + diff[:6000])


def test_required_paths_present(committed):
    for p in ["/api/v1/health", "/api/v1/analyses", "/api/v1/analyses/{job_id}",
              "/api/v1/analyses/{job_id}/findings", "/api/v1/analyses/{job_id}/report", "/api/v1/reports/verify"]:
        assert p in committed["paths"], p


def test_vulnclass_enum_matches_fixture_manifest(committed):
    """Every vuln_class used in fixture ground truth must exist in the API enum."""
    enum = set(committed["components"]["schemas"]["VulnClass"]["enum"])
    manifest = json.loads((ROOT / "fixtures" / "manifest.json").read_text())
    used = {f["vuln_class"] for e in manifest["fixtures"] for f in e["expected_findings"]}
    used |= {c for e in manifest["fixtures"] for c in e.get("acceptable_extra_classes", [])}
    assert used <= enum, used - enum


def test_fixture_manifest_is_current():
    import subprocess
    r = subprocess.run([sys.executable, str(ROOT / "fixtures/scripts/build_manifest.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
