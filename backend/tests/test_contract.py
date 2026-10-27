"""The backend's OpenAPI document must match the shared contract (contracts/openapi.json)."""
import json
import pathlib

from app import REPO_ROOT
from app.main import create_app
from tests.conftest import make_settings

CONTRACT = json.loads((REPO_ROOT / "contracts" / "openapi.json").read_text())


def test_component_schemas_match(tmp_path):
    ours = create_app(make_settings(tmp_path), start_workers=False).openapi()
    theirs = CONTRACT["components"]["schemas"]
    for name, schema in theirs.items():
        assert name in ours["components"]["schemas"], f"missing schema {name}"
        assert ours["components"]["schemas"][name] == schema, f"schema drift in {name}"
    extra = set(ours["components"]["schemas"]) - set(theirs)
    assert not extra, f"backend exposes schemas not in contract: {extra}"


def test_paths_and_operations_match(tmp_path):
    ours = create_app(make_settings(tmp_path), start_workers=False).openapi()
    assert set(ours["paths"]) == set(CONTRACT["paths"])
    for p, ops in CONTRACT["paths"].items():
        assert set(ours["paths"][p]) == set(ops), p
        for m, op in ops.items():
            o = ours["paths"][p][m]
            assert o.get("parameters") == op.get("parameters"), (p, m)
            assert o.get("requestBody") == op.get("requestBody"), (p, m)
            assert set(o["responses"]) == set(op["responses"]), (p, m)
            for code, resp in op["responses"].items():
                assert o["responses"][code].get("content") == resp.get("content"), (p, m, code)
