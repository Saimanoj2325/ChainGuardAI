"""ChainGuard AI backend. Makes the shared contract, sandbox and ml packages importable."""
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
for _sub in ("shared", "sandbox", "ml"):
    _p = str(REPO_ROOT / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)
