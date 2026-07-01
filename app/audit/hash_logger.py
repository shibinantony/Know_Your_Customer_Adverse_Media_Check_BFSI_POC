from __future__ import annotations

import argparse
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable


GENESIS_HASH = "0" * 64


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, default=str, ensure_ascii=False))


def _canonical_event(
    *,
    timestamp_utc: str,
    correlation_id: str,
    actor: str,
    event_type: str,
    details: dict[str, Any],
    previous_hash: str,
) -> str:
    event = {
        "actor": actor,
        "correlation_id": correlation_id,
        "details": _json_safe(details),
        "event_type": event_type,
        "previous_hash": previous_hash,
        "timestamp_utc": timestamp_utc,
    }
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _event_hash(**kwargs: Any) -> str:
    return sha256(_canonical_event(**kwargs).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    db_event_count: int
    jsonl_event_count: int
    last_event_hash: str
    issues: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "db_event_count": self.db_event_count,
            "jsonl_event_count": self.jsonl_event_count,
            "last_event_hash": self.last_event_hash,
            "issues": self.issues,
        }


class HashChainLogger:
    """Append-only audit logger backed by SQLite and JSONL with SHA-256 hash chaining."""

    def __init__(
        self,
        db_path: str | Path = "logs/audit_chain.sqlite3",
        jsonl_path: str | Path = "logs/audit_chain.jsonl",
    ) -> None:
        self.db_path = Path(db_path)
        self.jsonl_path = Path(jsonl_path)
        self._thread_lock = threading.Lock()

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    created_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_correlation ON audit_events(correlation_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type)"
            )
        self.jsonl_path.touch(exist_ok=True)

    def log_event(
        self,
        *,
        event_type: str,
        actor: str,
        correlation_id: str,
        details: dict[str, Any] | None = None,
        timestamp_utc: str | None = None,
    ) -> dict[str, Any]:
        self.initialize()
        timestamp = timestamp_utc or _utc_now_iso()
        safe_details = _json_safe(details or {})

        with self._thread_lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                previous_hash = self._last_hash(conn)
                event_hash = _event_hash(
                    timestamp_utc=timestamp,
                    correlation_id=correlation_id,
                    actor=actor,
                    event_type=event_type,
                    details=safe_details,
                    previous_hash=previous_hash,
                )
                cur = conn.execute(
                    """
                    INSERT INTO audit_events (
                        timestamp_utc,
                        correlation_id,
                        actor,
                        event_type,
                        event_json,
                        previous_hash,
                        event_hash
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        timestamp,
                        correlation_id,
                        actor,
                        event_type,
                        json.dumps(safe_details, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                        previous_hash,
                        event_hash,
                    ),
                )
                record = {
                    "id": int(cur.lastrowid),
                    "timestamp_utc": timestamp,
                    "correlation_id": correlation_id,
                    "actor": actor,
                    "event_type": event_type,
                    "details": safe_details,
                    "previous_hash": previous_hash,
                    "event_hash": event_hash,
                }
                self._append_jsonl(record)
                conn.commit()
                return record
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def verify(self) -> VerificationResult:
        self.initialize()
        db_records = self._read_db_records()
        jsonl_records = self._read_jsonl_records()
        issues: list[str] = []

        db_last_hash = self._verify_record_chain(db_records, "sqlite", issues)
        jsonl_last_hash = self._verify_record_chain(jsonl_records, "jsonl", issues)

        if len(db_records) != len(jsonl_records):
            issues.append(
                f"record count mismatch: sqlite={len(db_records)} jsonl={len(jsonl_records)}"
            )

        for offset, (db_record, jsonl_record) in enumerate(zip(db_records, jsonl_records), start=1):
            comparable_db = self._record_for_compare(db_record)
            comparable_jsonl = self._record_for_compare(jsonl_record)
            if comparable_db != comparable_jsonl:
                issues.append(f"sqlite/jsonl mismatch at ordinal {offset}")
                break

        if db_records and jsonl_records and db_last_hash != jsonl_last_hash:
            issues.append(f"last hash mismatch: sqlite={db_last_hash} jsonl={jsonl_last_hash}")

        return VerificationResult(
            valid=not issues,
            db_event_count=len(db_records),
            jsonl_event_count=len(jsonl_records),
            last_event_hash=db_last_hash if db_records else GENESIS_HASH,
            issues=issues,
        )

    def tail(self, limit: int = 20) -> list[dict[str, Any]]:
        self.initialize()
        records = self._read_db_records()
        return records[-limit:]

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _last_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return str(row["event_hash"]) if row else GENESIS_HASH

    def _append_jsonl(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self.jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _read_db_records(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    timestamp_utc,
                    correlation_id,
                    actor,
                    event_type,
                    event_json,
                    previous_hash,
                    event_hash
                FROM audit_events
                ORDER BY id ASC
                """
            ).fetchall()

        records: list[dict[str, Any]] = []
        for row in rows:
            records.append(
                {
                    "id": int(row["id"]),
                    "timestamp_utc": str(row["timestamp_utc"]),
                    "correlation_id": str(row["correlation_id"]),
                    "actor": str(row["actor"]),
                    "event_type": str(row["event_type"]),
                    "details": json.loads(str(row["event_json"])),
                    "previous_hash": str(row["previous_hash"]),
                    "event_hash": str(row["event_hash"]),
                }
            )
        return records

    def _read_jsonl_records(self) -> list[dict[str, Any]]:
        if not self.jsonl_path.exists():
            return []
        records: list[dict[str, Any]] = []
        with self.jsonl_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    records.append(json.loads(stripped))
                except json.JSONDecodeError as exc:
                    records.append(
                        {
                            "id": -line_number,
                            "timestamp_utc": "",
                            "correlation_id": "",
                            "actor": "",
                            "event_type": "jsonl_parse_error",
                            "details": {"line_number": line_number, "error": str(exc)},
                            "previous_hash": "",
                            "event_hash": "",
                        }
                    )
        return records

    def _verify_record_chain(
        self, records: Iterable[dict[str, Any]], source: str, issues: list[str]
    ) -> str:
        previous = GENESIS_HASH
        seen_hashes: set[str] = set()
        last_hash = GENESIS_HASH

        for ordinal, record in enumerate(records, start=1):
            event_hash = str(record.get("event_hash", ""))
            previous_hash = str(record.get("previous_hash", ""))

            if previous_hash != previous:
                issues.append(
                    f"{source} chain break at ordinal {ordinal}: expected previous_hash={previous}, found={previous_hash}"
                )

            expected_hash = _event_hash(
                timestamp_utc=str(record.get("timestamp_utc", "")),
                correlation_id=str(record.get("correlation_id", "")),
                actor=str(record.get("actor", "")),
                event_type=str(record.get("event_type", "")),
                details=dict(record.get("details") or {}),
                previous_hash=previous_hash,
            )
            if event_hash != expected_hash:
                issues.append(
                    f"{source} hash mismatch at ordinal {ordinal}: expected={expected_hash}, found={event_hash}"
                )

            if event_hash in seen_hashes:
                issues.append(f"{source} duplicate event_hash at ordinal {ordinal}: {event_hash}")
            seen_hashes.add(event_hash)
            previous = event_hash
            last_hash = event_hash

        return last_hash

    @staticmethod
    def _record_for_compare(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": int(record.get("id", -1)),
            "timestamp_utc": str(record.get("timestamp_utc", "")),
            "correlation_id": str(record.get("correlation_id", "")),
            "actor": str(record.get("actor", "")),
            "event_type": str(record.get("event_type", "")),
            "details": _json_safe(record.get("details") or {}),
            "previous_hash": str(record.get("previous_hash", "")),
            "event_hash": str(record.get("event_hash", "")),
        }


def _parse_details(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"details must be valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("details must be a JSON object")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CITADEL tamper-evident hash-chain audit logger")
    parser.add_argument("command", choices=("init", "verify", "tail", "append"))
    parser.add_argument("--db", default="logs/audit_chain.sqlite3", help="SQLite audit database path")
    parser.add_argument("--jsonl", default="logs/audit_chain.jsonl", help="JSONL audit log path")
    parser.add_argument("--limit", type=int, default=20, help="Number of tail records to print")
    parser.add_argument("--event-type", default="manual.audit_event")
    parser.add_argument("--actor", default="operator")
    parser.add_argument("--correlation-id", default="manual")
    parser.add_argument("--details", default="{}", help="JSON object for append command")
    args = parser.parse_args(argv)

    logger = HashChainLogger(args.db, args.jsonl)

    if args.command == "init":
        logger.initialize()
        print(json.dumps({"initialized": True, "db": args.db, "jsonl": args.jsonl}, indent=2))
        return 0

    if args.command == "verify":
        result = logger.verify()
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
        return 0 if result.valid else 1

    if args.command == "tail":
        print(json.dumps(logger.tail(args.limit), indent=2, sort_keys=True, ensure_ascii=False))
        return 0

    record = logger.log_event(
        event_type=args.event_type,
        actor=args.actor,
        correlation_id=args.correlation_id,
        details=_parse_details(args.details),
    )
    print(json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
