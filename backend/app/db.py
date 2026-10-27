"""SQLite persistence (stdlib sqlite3, one connection guarded by a lock; WAL mode)."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  job_id TEXT PRIMARY KEY, status TEXT NOT NULL, stage TEXT NOT NULL, progress INTEGER NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, contract_json TEXT NOT NULL,
  analyzers_json TEXT NOT NULL DEFAULT '[]', error TEXT, finding_count INTEGER, source_path TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS stage_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, stage TEXT NOT NULL, status TEXT NOT NULL,
  at TEXT NOT NULL, message TEXT);
CREATE INDEX IF NOT EXISTS ix_events_job ON stage_events(job_id, id);
CREATE TABLE IF NOT EXISTS findings (
  job_id TEXT NOT NULL, idx INTEGER NOT NULL, finding_json TEXT NOT NULL, PRIMARY KEY (job_id, idx));
CREATE TABLE IF NOT EXISTS reports (
  job_id TEXT PRIMARY KEY, report_id TEXT NOT NULL UNIQUE, report_hash TEXT NOT NULL, report_json TEXT NOT NULL,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS registry (
  idx INTEGER PRIMARY KEY, report_hash TEXT NOT NULL, prev_entry_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL UNIQUE, timestamp TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_registry_hash ON registry(report_hash);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


class Database:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.executescript(SCHEMA)

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    # ---- generic helpers
    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self.lock:
            return self.conn.execute(sql, params)

    def one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        with self.lock:
            return self.conn.execute(sql, params).fetchone()

    def all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, params).fetchall()

    # ---- jobs
    def create_job(self, job_id: str, contract: dict, source_path: str) -> None:
        now = iso(utcnow())
        self.execute("INSERT INTO jobs(job_id,status,stage,progress,created_at,updated_at,contract_json,source_path) "
                     "VALUES (?,?,?,?,?,?,?,?)", (job_id, "queued", "received", 0, now, now, json.dumps(contract), source_path))

    def update_job(self, job_id: str, **fields) -> None:
        if not fields:
            return
        if "contract" in fields:
            fields["contract_json"] = json.dumps(fields.pop("contract"))
        if "analyzers" in fields:
            fields["analyzers_json"] = json.dumps(fields.pop("analyzers"))
        fields["updated_at"] = iso(utcnow())
        cols = ", ".join(f"{k}=?" for k in fields)
        self.execute(f"UPDATE jobs SET {cols} WHERE job_id=?", (*fields.values(), job_id))

    def get_job_row(self, job_id: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM jobs WHERE job_id=?", (job_id,))

    def jobs_with_status(self, status: str) -> list[sqlite3.Row]:
        return self.all("SELECT * FROM jobs WHERE status=? ORDER BY created_at", (status,))

    def add_event(self, job_id: str, stage: str, status: str, message: str | None = None) -> None:
        self.execute("INSERT INTO stage_events(job_id,stage,status,at,message) VALUES (?,?,?,?,?)",
                     (job_id, stage, status, iso(utcnow()), message))

    def events(self, job_id: str) -> list[sqlite3.Row]:
        return self.all("SELECT * FROM stage_events WHERE job_id=? ORDER BY id", (job_id,))

    # ---- findings
    def replace_findings(self, job_id: str, findings: list[dict]) -> None:
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                self.conn.execute("DELETE FROM findings WHERE job_id=?", (job_id,))
                self.conn.executemany("INSERT INTO findings(job_id,idx,finding_json) VALUES (?,?,?)",
                                      [(job_id, i, json.dumps(f)) for i, f in enumerate(findings)])
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def findings(self, job_id: str) -> list[dict]:
        return [json.loads(r["finding_json"]) for r in self.all(
            "SELECT finding_json FROM findings WHERE job_id=? ORDER BY idx", (job_id,))]

    # ---- reports
    def save_report(self, job_id: str, report_id: str, report_hash: str, report: dict) -> None:
        self.execute("INSERT OR REPLACE INTO reports(job_id,report_id,report_hash,report_json,created_at) VALUES (?,?,?,?,?)",
                     (job_id, report_id, report_hash, json.dumps(report), iso(utcnow())))

    def get_report(self, job_id: str) -> dict | None:
        r = self.one("SELECT report_json FROM reports WHERE job_id=?", (job_id,))
        return json.loads(r["report_json"]) if r else None
