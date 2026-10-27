"""Append-only, hash-chained audit registry (a local ledger in SQLite — NOT a public blockchain).

entry_hash = sha256(f"{index}|{report_hash}|{prev_entry_hash}|{timestamp_iso}")
* index starts at 0; the genesis entry's prev_entry_hash is 64 zeros.
* timestamp_iso is the entry timestamp exactly as it appears in the JSON RegistryEntry
  (UTC, second precision, pydantic serialization, e.g. "2026-10-27T08:41:05Z"), so anyone holding
  the report's `registry` block can recompute entry_hash.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from pydantic import TypeAdapter

from chainguard_contract.models import RegistryEntry

from .db import Database

GENESIS_PREV = "0" * 64
_DT = TypeAdapter(datetime)


def timestamp_iso(dt: datetime) -> str:
    return _DT.dump_python(dt.astimezone(timezone.utc).replace(microsecond=0), mode="json")


def compute_entry_hash(index: int, report_hash: str, prev_entry_hash: str, ts_iso: str) -> str:
    return hashlib.sha256(f"{index}|{report_hash}|{prev_entry_hash}|{ts_iso}".encode()).hexdigest()


@dataclass
class ChainCheck:
    intact: bool
    length: int
    reason: str
    broken_at: int | None = None


class Registry:
    def __init__(self, db: Database):
        self.db = db

    @staticmethod
    def _row_to_entry(r) -> RegistryEntry:
        return RegistryEntry(index=r["idx"], report_hash=r["report_hash"], prev_entry_hash=r["prev_entry_hash"],
                             entry_hash=r["entry_hash"], timestamp=r["timestamp"])

    def append(self, report_hash: str, now: datetime | None = None) -> RegistryEntry:
        ts = timestamp_iso(now or datetime.now(timezone.utc))
        with self.db.lock:
            conn = self.db.conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                last = conn.execute("SELECT idx, entry_hash FROM registry ORDER BY idx DESC LIMIT 1").fetchone()
                index = 0 if last is None else last["idx"] + 1
                prev = GENESIS_PREV if last is None else last["entry_hash"]
                eh = compute_entry_hash(index, report_hash, prev, ts)
                conn.execute("INSERT INTO registry(idx,report_hash,prev_entry_hash,entry_hash,timestamp) VALUES (?,?,?,?,?)",
                             (index, report_hash, prev, eh, ts))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return RegistryEntry(index=index, report_hash=report_hash, prev_entry_hash=prev, entry_hash=eh, timestamp=ts)

    def find_by_report_hash(self, report_hash: str) -> RegistryEntry | None:
        r = self.db.one("SELECT * FROM registry WHERE report_hash=? ORDER BY idx LIMIT 1", (report_hash,))
        return self._row_to_entry(r) if r else None

    def entries(self) -> list[RegistryEntry]:
        return [self._row_to_entry(r) for r in self.db.all("SELECT * FROM registry ORDER BY idx")]

    def verify_chain(self) -> ChainCheck:
        rows = self.db.all("SELECT * FROM registry ORDER BY idx")
        prev = GENESIS_PREV
        for expected_idx, r in enumerate(rows):
            if r["idx"] != expected_idx:
                return ChainCheck(False, len(rows), f"registry index gap: expected {expected_idx}, found {r['idx']}", expected_idx)
            if r["prev_entry_hash"] != prev:
                return ChainCheck(False, len(rows), f"entry {expected_idx} prev_entry_hash does not link to entry {expected_idx - 1}", expected_idx)
            if compute_entry_hash(r["idx"], r["report_hash"], r["prev_entry_hash"], r["timestamp"]) != r["entry_hash"]:
                return ChainCheck(False, len(rows), f"entry {expected_idx} entry_hash does not match its contents", expected_idx)
            prev = r["entry_hash"]
        return ChainCheck(True, len(rows), f"chain of {len(rows)} entries intact")
