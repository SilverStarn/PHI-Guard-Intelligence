from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

from phi_guard_scanner.agent.connectors.cloud import unsupported_cloud_connector
from phi_guard_scanner.agent.connectors.files import scan_path
from phi_guard_scanner.agent.connectors.postgres import PostgresScanOptions, scan_postgres
from phi_guard_scanner.agent.connectors.sql_databases import unsupported_database_connector
from phi_guard_scanner.agent.contracts import AgentIdentity, AgentSource, ScanMode, SourceType, build_sanitized_package


def scan_local_path(
    *,
    path: Path,
    mode: ScanMode,
    project_name: str,
    agent_id: str,
    source_type: SourceType = SourceType.FILES,
) -> dict[str, Any]:
    scan_payload, warnings = scan_path(path, project_name=project_name)
    return build_sanitized_package(
        scan_payload=scan_payload,
        source=AgentSource(source_type=source_type, name=project_name, uri=str(path), mode=mode),
        agent=AgentIdentity(agent_id=agent_id),
        warnings=warnings,
    )


def scan_postgres_source(
    *,
    dsn: str,
    mode: ScanMode,
    project_name: str,
    agent_id: str,
    schemas: tuple[str, ...] = ("public",),
) -> dict[str, Any]:
    scan_payload, warnings = scan_postgres(
        PostgresScanOptions(
            dsn=dsn,
            project_name=project_name,
            mode=mode.value,
            schemas=schemas,
        )
    )
    return build_sanitized_package(
        scan_payload=scan_payload,
        source=AgentSource(
            source_type=SourceType.POSTGRES,
            name=project_name,
            uri="postgres://redacted",
            mode=mode,
            options={"schemas": list(schemas)},
        ),
        agent=AgentIdentity(agent_id=agent_id),
        warnings=warnings,
    )


def scan_uri(*, uri: str, source_type: SourceType, mode: ScanMode, project_name: str, agent_id: str) -> dict[str, Any]:
    if source_type in {SourceType.FILES, SourceType.SQLITE, SourceType.FHIR, SourceType.DBT, SourceType.LOGS}:
        return scan_local_path(
            path=_path_from_uri(uri),
            mode=mode,
            project_name=project_name,
            agent_id=agent_id,
            source_type=source_type,
        )
    if source_type == SourceType.POSTGRES:
        return scan_postgres_source(dsn=uri, mode=mode, project_name=project_name, agent_id=agent_id)
    if source_type in {SourceType.MYSQL, SourceType.SQL_SERVER}:
        unsupported_database_connector(source_type.value)
    if source_type in {SourceType.S3, SourceType.AZURE_BLOB, SourceType.GCS}:
        unsupported_cloud_connector(source_type.value)
    raise RuntimeError(f"Unsupported source type: {source_type.value}")


def submit_package(*, package: dict[str, Any], api_url: str, agent_token: str) -> dict[str, Any]:
    body = json.dumps(package).encode("utf-8")
    request = urllib.request.Request(
        url=f"{api_url.rstrip('/')}/api/agent/scans",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {agent_token}",
            "Content-Type": "application/json",
            "User-Agent": "phi-guard-scanner-agent/0.1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - operator-supplied API URL.
        return json.loads(response.read().decode("utf-8"))


def _path_from_uri(uri: str) -> Path:
    if uri.startswith("file://"):
        return Path(uri.removeprefix("file://"))
    return Path(uri)
