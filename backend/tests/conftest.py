import os
import pathlib
import sys
import tempfile
import time

import pytest

BACKEND = pathlib.Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

# keep the module-level `app` (created on import of app.main) out of the real data dir
os.environ.setdefault("CG_DATA_DIR", tempfile.mkdtemp(prefix="cg-test-"))
os.environ.setdefault("CG_DISABLE_SANDBOX", "1")

import app  # noqa: E402,F401  (adds shared/ to sys.path)
from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402

REENTRANCY_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0);
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");
        balances[msg.sender] = 0;
    }
}
"""

SAFE_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Safe {
    mapping(address => uint256) public balances;
    function withdraw() public {
        uint256 bal = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent);
    }
}
"""


def make_settings(tmp_path, **over) -> Settings:
    s = Settings()
    s.data_dir = str(tmp_path / "data")
    s.disable_sandbox = True
    s.disable_ml = True
    s.llm_api_key = None
    s.api_key = None
    s.workers = 2
    for k, v in over.items():
        setattr(s, k, v)
    return s


@pytest.fixture
def settings(tmp_path):
    return make_settings(tmp_path)


@pytest.fixture
def client(settings):
    app_ = create_app(settings)
    with TestClient(app_) as c:
        yield c


def submit(c, source: str | bytes = REENTRANCY_SOL, filename="EtherStore.sol", headers=None):
    data = source.encode() if isinstance(source, str) else source
    return c.post("/api/v1/analyses", files={"file": (filename, data, "text/plain")}, headers=headers or {})


def wait_done(c, job_id, timeout=15.0, headers=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        j = c.get(f"/api/v1/analyses/{job_id}", headers=headers or {}).json()
        if j["status"] in ("completed", "failed"):
            return j
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish: {j}")
