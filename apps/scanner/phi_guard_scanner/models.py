from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class AssetType(StrEnum):
    DATABASE = "database"
    SCHEMA = "schema"
    TABLE = "table"
    COLUMN = "column"
    VIEW = "view"
    EXPORT = "export"
    ROLE = "role"
    CONTROL = "control"
    EXTERNAL_DESTINATION = "external_destination"
    AI_TOOL = "ai_tool"
    FINDING = "finding"


class ClassificationLabel(StrEnum):
    DIRECT_IDENTIFIER = "DIRECT_IDENTIFIER"
    QUASI_IDENTIFIER = "QUASI_IDENTIFIER"
    HEALTH_CONTEXT = "HEALTH_CONTEXT"
    PAYMENT_CONTEXT = "PAYMENT_CONTEXT"
    FREE_TEXT_PHI_RISK = "FREE_TEXT_PHI_RISK"
    LINKABLE_KEY = "LINKABLE_KEY"
    DEIDENTIFICATION_BLOCKER = "DEIDENTIFICATION_BLOCKER"
    ACCESS_CONTROL_GAP = "ACCESS_CONTROL_GAP"
    LINEAGE_PROPAGATED_RISK = "LINEAGE_PROPAGATED_RISK"
    AI_EXPOSURE_RISK = "AI_EXPOSURE_RISK"


class EdgeType(StrEnum):
    CONTAINS = "CONTAINS"
    REFERENCES = "REFERENCES"
    JOINS_TO = "JOINS_TO"
    DERIVES_FROM = "DERIVES_FROM"
    READ_BY = "READ_BY"
    WRITTEN_BY = "WRITTEN_BY"
    EXPORTED_TO = "EXPORTED_TO"
    SENT_TO = "SENT_TO"
    HAS_FINDING = "HAS_FINDING"
    MITIGATED_BY = "MITIGATED_BY"
    MAPS_TO_CONTROL = "MAPS_TO_CONTROL"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


@dataclass(frozen=True)
class Classification:
    label: ClassificationLabel
    confidence: float
    source: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Asset:
    id: str
    name: str
    asset_type: AssetType
    schema_name: str | None = None
    table_name: str | None = None
    column_name: str | None = None
    data_type: str | None = None
    row_count_estimate: int | None = None
    risk_score: int = 0
    description: str = ""
    classifications: list[Classification] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LineageEdge:
    id: str
    source_asset_id: str
    target_asset_id: str
    edge_type: EdgeType
    confidence: float = 1.0
    label: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AccessGrant:
    id: str
    asset_id: str
    principal_type: str
    principal_name: str
    permission: str
    source: str
    last_seen_at: str


@dataclass(frozen=True)
class Evidence:
    evidence_type: str
    safe_snippet: str
    raw_value_stored: bool
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RiskFactors:
    impact: float
    likelihood: float
    exposure: float
    control_gap: float
    confidence: float


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    status: str
    risk_score: int
    confidence: float
    asset_id: str
    description: str
    observation: str
    why_it_matters: str
    control_mapping: list[str]
    remediation_summary: str
    recommended_steps: list[str]
    human_review: str
    blast_radius: dict[str, Any]
    evidence: list[Evidence]
    risk_factors: RiskFactors


@dataclass
class IntelligenceScan:
    workspace_id: str
    data_source_id: str
    scan_id: str
    generated_at: str
    assets: list[Asset]
    edges: list[LineageEdge]
    access_grants: list[AccessGrant]
    findings: list[Finding]


def to_plain(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, list):
        return [to_plain(item) for item in value]
    if isinstance(value, tuple):
        return [to_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: to_plain(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return to_plain(asdict(value))
    return value

