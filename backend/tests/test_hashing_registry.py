import hashlib
from datetime import datetime, timezone

from chainguard_contract.hashing import report_hash
from chainguard_contract.models import VerifyRequest

from app.db import Database
from app.registry import GENESIS_PREV, Registry, compute_entry_hash
from app.reports import verify


def reg(tmp_path):
    return Registry(Database(str(tmp_path / "r.sqlite3")))


def test_report_hash_excludes_hash_and_registry_and_is_order_independent():
    a = {"b": 1, "a": [1, 2], "report_hash": "x", "registry": {"i": 1}}
    b = {"a": [1, 2], "b": 1, "report_hash": "y"}
    assert report_hash(a) == report_hash(b)
    assert report_hash(a) != report_hash({"a": [1, 2], "b": 2})


def test_entry_hash_formula_and_genesis(tmp_path):
    r = reg(tmp_path)
    t = datetime(2026, 10, 27, 8, 0, 0, 123456, tzinfo=timezone.utc)
    e0 = r.append("a" * 64, now=t)
    assert e0.index == 0 and e0.prev_entry_hash == GENESIS_PREV
    expected = hashlib.sha256(f"0|{'a' * 64}|{GENESIS_PREV}|2026-10-27T08:00:00Z".encode()).hexdigest()
    assert e0.entry_hash == expected
    e1 = r.append("b" * 64, now=t)
    assert e1.index == 1 and e1.prev_entry_hash == e0.entry_hash
    assert e1.entry_hash == compute_entry_hash(1, "b" * 64, e0.entry_hash, "2026-10-27T08:00:00Z")
    assert r.verify_chain().intact and r.verify_chain().length == 2


def test_chain_tamper_detected(tmp_path):
    r = reg(tmp_path)
    for c in "abc":
        r.append(c * 64)
    r.db.execute("UPDATE registry SET report_hash=? WHERE idx=1", ("d" * 64,))
    chk = r.verify_chain()
    assert not chk.intact and chk.broken_at == 1 and "entry 1" in chk.reason


def test_chain_relink_detected(tmp_path):
    r = reg(tmp_path)
    for c in "ab":
        r.append(c * 64)
    r.db.execute("UPDATE registry SET prev_entry_hash=? WHERE idx=1", ("0" * 64,))
    assert not r.verify_chain().intact


def test_verify_by_hash(tmp_path):
    r = reg(tmp_path)
    r.append("a" * 64)
    ok = verify(VerifyRequest(report_hash="a" * 64), r)
    assert ok.valid and ok.registered and ok.chain_intact
    bad = verify(VerifyRequest(report_hash="e" * 64), r)
    assert not bad.valid and not bad.registered and "not in the registry" in bad.reason


def test_verify_detects_broken_chain_even_if_registered(tmp_path):
    r = reg(tmp_path)
    r.append("a" * 64)
    r.append("b" * 64)
    r.db.execute("UPDATE registry SET timestamp='2020-01-01T00:00:00Z' WHERE idx=0")
    res = verify(VerifyRequest(report_hash="b" * 64), r)
    assert res.registered and not res.chain_intact and not res.valid
