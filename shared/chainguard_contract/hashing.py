"""Canonical report hashing. Shared by backend and verifier; frontend may reimplement (documented in docs/API.md)."""
import hashlib, json

EXCLUDED = {"report_hash", "registry"}

def canonical_json(report: dict) -> bytes:
    body = {k: v for k, v in report.items() if k not in EXCLUDED}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()

def report_hash(report: dict) -> str:
    return hashlib.sha256(canonical_json(report)).hexdigest()
