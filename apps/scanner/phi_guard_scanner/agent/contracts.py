from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from phi_guard_scanner.classifiers.patterns import masked_shape


class ScanMode(StrEnum):
    METADATA_ONLY = "metadata_only"
    MASKED_SAMPLE = "masked_sample"
    DEEP_LOCAL = "deep_local"


class SourceType(StrEnum):
    POSTGRES = "postgres"
    MYSQL = "mysql"
    SQL_SERVER = "sql_server"
    SQLITE = "sqlite"
    FILES = "files"
    S3 = "s3"
    AZURE_BLOB = "azure_blob"
    GCS = "gcs"
    FHIR = "fhir"
    DBT = "dbt"
    LOGS = "logs"


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    version: str = "0.1.0"
    identity_mode: str = "signed_token"


@dataclass(frozen=True)
class AgentSource:
    source_type: SourceType
    name: str
    uri: str
    mode: ScanMode
    options: dict[str, Any] = field(default_factory=dict)


def build_sanitized_package(
    *,
    scan_payload: dict[str, Any],
    source: AgentSource,
    agent: AgentIdentity,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "package_version": "2026-05-14",
        "generated_at": datetime.now(UTC).isoformat(),
        "agent": {
            "agent_id": agent.agent_id,
            "version": agent.version,
            "identity_mode": agent.identity_mode,
        },
        "source": {
            "source_type": source.source_type.value,
            "name": source.name,
            "uri": _safe_uri(source.uri),
            "mode": source.mode.value,
            "options": _safe_options(source.options),
        },
        "privacy": {
            "raw_value_stored": False,
            "raw_file_uploaded": False,
            "classification_location": "local_agent",
            "llm_receives_raw_phi": False,
        },
        "evidence": _evidence_from_scan(scan_payload),
        "sanitized_intelligence_graph": scan_payload,
        "warnings": warnings or [],
    }


def _evidence_from_scan(scan_payload: dict[str, Any]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for asset in scan_payload.get("assets", []):
        if asset.get("asset_type") != "column":
            continue
        column_name = asset.get("name") or ".".join(
            part for part in [asset.get("table_name"), asset.get("column_name")] if part
        )
        for classification in asset.get("classifications", []):
            evidence.append(
                {
                    "column": column_name,
                    "label": classification.get("label"),
                    "confidence": classification.get("confidence", 0),
                    "sample_shape": _sample_shape(classification),
                    "raw_value_stored": False,
                    "source": classification.get("source"),
                }
            )
    return evidence


def _sample_shape(classification: dict[str, Any]) -> str:
    details = classification.get("details", {})
    patterns = details.get("value_patterns") or []
    preferred = [
        "email",
        "name",
        "ssn",
        "mrn",
        "phone",
        "dob",
        "date",
        "street_address",
        "geography",
        "zip",
        "ip",
        "icd10",
        "notes",
    ]
    for pattern in preferred:
        if pattern in patterns:
            return masked_shape("date" if pattern == "dob" else pattern)
    label = str(classification.get("label") or "")
    if label == "FREE_TEXT_PHI_RISK":
        return masked_shape("notes")
    return "metadata-only signal"


def _safe_uri(uri: str) -> str:
    if "://" not in uri:
        return uri
    scheme, rest = uri.split("://", 1)
    if "@" in rest:
        rest = rest.split("@", 1)[1]
    if "?" in rest:
        rest = rest.split("?", 1)[0]
    return f"{scheme}://{rest}"


def _safe_options(options: dict[str, Any]) -> dict[str, Any]:
    blocked = {"password", "token", "secret", "connection_string", "dsn"}
    return {key: value for key, value in options.items() if key.lower() not in blocked}
