from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol


class MetadataStore(Protocol):
    def record_scan(self, *, source: str, scan_id: str, workspace: str, payload: dict[str, Any]) -> None:
        ...

    def audit(self, *, event_type: str, actor: str, workspace: str, metadata: dict[str, Any] | None = None) -> None:
        ...

    def scan_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        ...

    def audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        ...


class LocalJsonMetadataStore(MetadataStore):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record_scan(self, *, source: str, scan_id: str, workspace: str, payload: dict[str, Any]) -> None:
        self._append(
            {
                "record_type": "scan_run",
                "created_at": _now(),
                "source": source,
                "scan_id": scan_id,
                "workspace": workspace,
                "status": "completed",
                "summary": _scan_summary(payload),
            }
        )

    def audit(self, *, event_type: str, actor: str, workspace: str, metadata: dict[str, Any] | None = None) -> None:
        self._append(
            {
                "record_type": "audit_event",
                "created_at": _now(),
                "event_type": event_type,
                "actor": actor,
                "workspace": workspace,
                "metadata": metadata or {},
            }
        )

    def scan_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._read("scan_run", limit)

    def audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._read("audit_event", limit)

    def _append(self, record: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    def _read(self, record_type: str, limit: int) -> list[dict[str, Any]]:
        if limit <= 0 or not self.path.exists():
            return []
        records = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("record_type") == record_type:
                    records.append(record)
        return list(reversed(records[-limit:]))


class PostgresMetadataStore(MetadataStore):
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    def record_scan(self, *, source: str, scan_id: str, workspace: str, payload: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO scan_runs (id, workspace_id, source, status, started_at, completed_at, summary_json)
            VALUES (%s, %s, %s, 'completed', now(), now(), %s::jsonb)
            ON CONFLICT (id) DO UPDATE SET completed_at = excluded.completed_at, summary_json = excluded.summary_json
            """,
            (scan_id, workspace, source, json.dumps(_scan_summary(payload))),
        )

    def audit(self, *, event_type: str, actor: str, workspace: str, metadata: dict[str, Any] | None = None) -> None:
        self._execute(
            """
            INSERT INTO audit_events (workspace_id, actor_id, event_type, metadata_json)
            VALUES (%s, %s, %s, %s::jsonb)
            """,
            (workspace, actor, event_type, json.dumps(metadata or {})),
        )

    def scan_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._query(
            "SELECT id AS scan_id, workspace_id AS workspace, source, status, completed_at, summary_json FROM scan_runs ORDER BY completed_at DESC LIMIT %s",
            (limit,),
        )

    def audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._query(
            "SELECT created_at, workspace_id AS workspace, actor_id AS actor, event_type, metadata_json AS metadata FROM audit_events ORDER BY created_at DESC LIMIT %s",
            (limit,),
        )

    def _execute(self, query: str, params: tuple[Any, ...]) -> None:
        try:
            import psycopg
        except ModuleNotFoundError as exc:
            raise RuntimeError("Postgres metadata store requires psycopg.") from exc
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
            connection.commit()

    def _query(self, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ModuleNotFoundError as exc:
            raise RuntimeError("Postgres metadata store requires psycopg.") from exc
        with psycopg.connect(self.dsn, row_factory=dict_row) as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]


def get_metadata_store() -> MetadataStore:
    dsn = os.getenv("PHI_GUARD_METADATA_POSTGRES_DSN") or os.getenv("DATABASE_URL")
    if dsn:
        return PostgresMetadataStore(dsn)
    path = Path(os.getenv("PHI_GUARD_METADATA_PATH", ".phi_guard/metadata-store.jsonl"))
    return LocalJsonMetadataStore(path)


def _scan_summary(payload: dict[str, Any]) -> dict[str, Any]:
    findings = payload.get("findings", [])
    assets = payload.get("assets", [])
    return {
        "asset_count": len(assets) if isinstance(assets, list) else 0,
        "finding_count": len(findings) if isinstance(findings, list) else 0,
        "critical_count": sum(1 for finding in findings if isinstance(finding, dict) and finding.get("severity") == "critical"),
        "raw_value_stored": False,
    }


def _now() -> str:
    return datetime.now(UTC).isoformat()
