from __future__ import annotations

from datetime import UTC, datetime

from phi_guard_scanner.classifiers.schema_classifier import ColumnProfile, classify_column
from phi_guard_scanner.models import (
    AccessGrant,
    Asset,
    AssetType,
    IntelligenceScan,
    Classification,
    ClassificationLabel,
    EdgeType,
    LineageEdge,
    to_plain,
)
from phi_guard_scanner.rules.risk_rules import generate_findings


WORKSPACE_ID = "workspace:northstar"
DATA_SOURCE_ID = "datasource:northstar-postgres"


TABLES: list[dict[str, object]] = [
    {
        "name": "patients",
        "row_count": 120_000,
        "description": "Patient master table with identifiers and demographics.",
        "columns": [
            ("id", "uuid", []),
            ("first_name", "text", []),
            ("last_name", "text", []),
            ("email", "text", ["alex.rivera@example.test"]),
            ("phone_number", "text", ["555-214-0198"]),
            ("ssn", "text", ["123-45-6789"]),
            ("mrn", "text", ["MRN-44812048"]),
            ("date_of_birth", "date", ["1982-04-16"]),
            ("street_address", "text", []),
            ("city", "text", []),
            ("state", "text", []),
            ("zip", "text", ["02139"]),
            ("gender", "text", []),
            ("created_at", "timestamp", ["2025-10-02"]),
        ],
    },
    {
        "name": "encounters",
        "row_count": 260_000,
        "description": "Clinical encounter facts linked to patients and providers.",
        "columns": [
            ("id", "uuid", []),
            ("patient_id", "uuid", []),
            ("provider_id", "uuid", []),
            ("encounter_date", "date", ["2025-11-03"]),
            ("diagnosis_code", "text", ["E11.9"]),
            ("procedure_code", "text", ["99213"]),
            ("condition", "text", []),
            ("notes_summary", "text", []),
        ],
    },
    {
        "name": "appointment_notes",
        "row_count": 84_221,
        "description": "Operational notes captured by schedulers and support staff.",
        "columns": [
            ("id", "uuid", []),
            ("appointment_id", "uuid", []),
            ("patient_id", "uuid", []),
            ("notes", "text", ["contains phone-like/date-like/address-like tokens"]),
            ("created_by", "text", []),
            ("created_at", "timestamp", ["2026-01-04"]),
        ],
    },
    {
        "name": "claims",
        "row_count": 210_000,
        "description": "Insurance claims with diagnosis and payer context.",
        "columns": [
            ("id", "uuid", []),
            ("patient_id", "uuid", []),
            ("claim_id", "text", []),
            ("payer", "text", []),
            ("diagnosis_code", "text", ["I10"]),
            ("claim_amount", "numeric", []),
            ("service_date", "date", ["2025-12-15"]),
            ("account_number", "text", ["acct_84729120"]),
        ],
    },
    {
        "name": "payments",
        "row_count": 180_000,
        "description": "Payment and billing table.",
        "columns": [
            ("id", "uuid", []),
            ("patient_id", "uuid", []),
            ("claim_id", "uuid", []),
            ("payment_amount", "numeric", []),
            ("account_balance", "numeric", []),
            ("payment_date", "date", ["2025-12-29"]),
        ],
    },
    {
        "name": "medications",
        "row_count": 95_000,
        "description": "Medication orders linked to patients.",
        "columns": [
            ("id", "uuid", []),
            ("patient_id", "uuid", []),
            ("medication_name", "text", []),
            ("start_date", "date", ["2025-08-04"]),
            ("condition_code", "text", ["J45.909"]),
        ],
    },
    {
        "name": "lab_results",
        "row_count": 325_000,
        "description": "Lab results linked to patients and encounters.",
        "columns": [
            ("id", "uuid", []),
            ("patient_id", "uuid", []),
            ("encounter_id", "uuid", []),
            ("lab_result", "text", []),
            ("result_value", "text", []),
            ("result_date", "date", ["2026-02-08"]),
        ],
    },
    {
        "name": "support_tickets",
        "row_count": 12_600,
        "description": "Support tickets with patient-linked free text.",
        "columns": [
            ("id", "uuid", []),
            ("patient_id", "uuid", []),
            ("email", "text", ["jordan.lee@example.test"]),
            ("message", "text", ["contains complaint text with date-like and phone-like tokens"]),
            ("status", "text", []),
            ("created_at", "timestamp", ["2026-03-01"]),
        ],
    },
    {
        "name": "analytics_patient_segments",
        "row_count": 118_000,
        "description": "Analytics table used for segmentation and reporting.",
        "columns": [
            ("patient_id", "uuid", []),
            ("date_of_birth", "date", ["1974-06-11"]),
            ("zip", "text", ["10027"]),
            ("diagnosis_category", "text", []),
            ("risk_band", "text", []),
            ("last_encounter_date", "date", ["2026-01-21"]),
        ],
    },
    {
        "name": "marketing_campaign_exports",
        "row_count": 42_000,
        "description": "Export used by a campaign workflow.",
        "columns": [
            ("patient_id", "uuid", []),
            ("email", "text", ["casey.nguyen@example.test"]),
            ("phone_number", "text", ["555-303-4401"]),
            ("diagnosis_category", "text", []),
            ("campaign_id", "text", []),
            ("exported_at", "timestamp", ["2026-04-01"]),
        ],
    },
    {
        "name": "ai_prompt_logs",
        "row_count": 7_800,
        "description": "Prompt logging table for an internal AI summarization experiment.",
        "columns": [
            ("id", "uuid", []),
            ("patient_id", "uuid", []),
            ("prompt_text", "text", ["contains patient detail pattern"]),
            ("model_name", "text", []),
            ("response_summary", "text", []),
            ("created_at", "timestamp", ["2026-04-13"]),
        ],
    },
    {
        "name": "audit_logs",
        "row_count": 600_000,
        "description": "Application audit logs with partial table coverage.",
        "columns": [
            ("id", "uuid", []),
            ("actor_id", "text", []),
            ("role_name", "text", []),
            ("table_name", "text", []),
            ("action", "text", []),
            ("created_at", "timestamp", ["2026-04-16"]),
        ],
    },
]


RELATIONSHIPS = [
    ("column:encounters.patient_id", "column:patients.id", EdgeType.REFERENCES, "patient FK"),
    ("column:appointment_notes.patient_id", "column:patients.id", EdgeType.REFERENCES, "patient FK"),
    ("column:claims.patient_id", "column:patients.id", EdgeType.REFERENCES, "patient FK"),
    ("column:payments.patient_id", "column:patients.id", EdgeType.REFERENCES, "patient FK"),
    ("column:medications.patient_id", "column:patients.id", EdgeType.REFERENCES, "patient FK"),
    ("column:lab_results.patient_id", "column:patients.id", EdgeType.REFERENCES, "patient FK"),
    ("column:support_tickets.patient_id", "column:patients.id", EdgeType.REFERENCES, "patient FK"),
    ("column:analytics_patient_segments.patient_id", "column:patients.id", EdgeType.JOINS_TO, "patient join"),
    ("column:marketing_campaign_exports.patient_id", "column:patients.id", EdgeType.JOINS_TO, "patient join"),
    ("column:ai_prompt_logs.patient_id", "column:patients.id", EdgeType.JOINS_TO, "patient join"),
    ("column:patients.email", "column:marketing_campaign_exports.email", EdgeType.DERIVES_FROM, "export lineage"),
    ("column:patients.phone_number", "column:marketing_campaign_exports.phone_number", EdgeType.DERIVES_FROM, "export lineage"),
    ("column:patients.date_of_birth", "column:analytics_patient_segments.date_of_birth", EdgeType.DERIVES_FROM, "analytics lineage"),
    ("column:encounters.diagnosis_code", "column:analytics_patient_segments.diagnosis_category", EdgeType.DERIVES_FROM, "rollup lineage"),
    ("column:encounters.diagnosis_code", "column:marketing_campaign_exports.diagnosis_category", EdgeType.DERIVES_FROM, "campaign lineage"),
    ("table:marketing_campaign_exports", "external:campaign_vendor", EdgeType.EXPORTED_TO, "external campaign export"),
    ("table:ai_prompt_logs", "ai_tool:internal_llm_gateway", EdgeType.SENT_TO, "AI workflow"),
]


ACCESS_GRANTS = [
    ("table:patients", "role", "clinical_reader", "read"),
    ("table:patients", "role", "analyst_role", "read"),
    ("table:patients", "role", "reporting_role", "read"),
    ("table:patients", "role", "old_service_account", "read"),
    ("table:encounters", "role", "clinical_reader", "read"),
    ("table:encounters", "role", "reporting_role", "read"),
    ("table:claims", "role", "billing_reader", "read"),
    ("table:claims", "role", "analyst_role", "read"),
    ("table:payments", "role", "billing_reader", "read"),
    ("table:lab_results", "role", "clinical_reader", "read"),
    ("table:lab_results", "role", "reporting_role", "read"),
    ("table:appointment_notes", "role", "support_role", "read"),
    ("table:appointment_notes", "role", "analyst_role", "read"),
    ("table:support_tickets", "role", "support_role", "read"),
    ("table:analytics_patient_segments", "role", "analyst_role", "read"),
    ("table:marketing_campaign_exports", "role", "marketing_ops", "export"),
    ("table:marketing_campaign_exports", "role", "analyst_role", "read"),
    ("table:ai_prompt_logs", "role", "ai_experiment_service", "write"),
    ("table:ai_prompt_logs", "role", "old_service_account", "read"),
    ("table:audit_logs", "role", "security_auditor", "read"),
]


CONTROL_ASSETS = [
    ("control:access-control", "Access control"),
    ("control:audit-controls", "Audit controls"),
    ("control:minimum-necessary", "Minimum necessary"),
    ("control:deidentification", "De-identification readiness"),
    ("control:ai-governance", "AI governance"),
    ("control:risk-analysis", "Risk analysis"),
]


def build_demo_scan() -> IntelligenceScan:
    assets: list[Asset] = [
        Asset(
            id="database:northstar",
            name="Northstar Family Clinic PostgreSQL",
            asset_type=AssetType.DATABASE,
            description="Synthetic PostgreSQL data source for the public demo.",
            risk_score=86,
        ),
        Asset(
            id="schema:public",
            name="public",
            asset_type=AssetType.SCHEMA,
            schema_name="public",
            description="Synthetic public schema.",
            risk_score=84,
        ),
    ]
    edges: list[LineageEdge] = [
        LineageEdge(
            id="edge:database-contains-public",
            source_asset_id="database:northstar",
            target_asset_id="schema:public",
            edge_type=EdgeType.CONTAINS,
            label="contains",
        )
    ]

    for control_id, name in CONTROL_ASSETS:
        assets.append(Asset(id=control_id, name=name, asset_type=AssetType.CONTROL, description=f"HIPAA-oriented {name.lower()} mapping."))

    assets.append(
        Asset(
            id="external:campaign_vendor",
            name="Campaign vendor export",
            asset_type=AssetType.EXTERNAL_DESTINATION,
            risk_score=82,
            description="External marketing operations destination in the synthetic demo.",
        )
    )
    assets.append(
        Asset(
            id="ai_tool:internal_llm_gateway",
            name="Internal LLM gateway",
            asset_type=AssetType.AI_TOOL,
            risk_score=91,
            description="Synthetic AI workflow destination receiving prompt metadata.",
            classifications=[
                Classification(
                    label=ClassificationLabel.AI_EXPOSURE_RISK,
                    confidence=0.9,
                    source="asset_type",
                    details={"destination": "model_gateway"},
                )
            ],
        )
    )

    for table in TABLES:
        table_name = str(table["name"])
        row_count = int(table["row_count"])
        table_asset = Asset(
            id=f"table:{table_name}",
            name=table_name,
            asset_type=AssetType.TABLE,
            schema_name="public",
            table_name=table_name,
            row_count_estimate=row_count,
            description=str(table["description"]),
        )
        assets.append(table_asset)
        edges.append(
            LineageEdge(
                id=f"edge:public-contains-{table_name}",
                source_asset_id="schema:public",
                target_asset_id=table_asset.id,
                edge_type=EdgeType.CONTAINS,
                label="contains",
            )
        )

        columns = table["columns"]
        assert isinstance(columns, list)
        for column_name, data_type, sample_shapes in columns:
            profile = ColumnProfile(
                table_name=table_name,
                column_name=str(column_name),
                data_type=str(data_type),
                sample_shapes=list(sample_shapes),
            )
            column_asset = Asset(
                id=f"column:{table_name}.{column_name}",
                name=f"{table_name}.{column_name}",
                asset_type=AssetType.COLUMN,
                schema_name="public",
                table_name=table_name,
                column_name=str(column_name),
                data_type=str(data_type),
                row_count_estimate=row_count,
                classifications=classify_column(profile),
            )
            assets.append(column_asset)
            edges.append(
                LineageEdge(
                    id=f"edge:{table_name}-contains-{column_name}",
                    source_asset_id=table_asset.id,
                    target_asset_id=column_asset.id,
                    edge_type=EdgeType.CONTAINS,
                    label="column",
                )
            )

    for index, (source, target, edge_type, label) in enumerate(RELATIONSHIPS, start=1):
        edges.append(
            LineageEdge(
                id=f"edge:relationship:{index}",
                source_asset_id=source,
                target_asset_id=target,
                edge_type=edge_type,
                confidence=0.88 if edge_type == EdgeType.DERIVES_FROM else 0.95,
                label=label,
                evidence={"raw_value_stored": False},
            )
        )

    grants = [
        AccessGrant(
            id=f"grant:{index}",
            asset_id=asset_id,
            principal_type=principal_type,
            principal_name=principal_name,
            permission=permission,
            source="demo_database_grant",
            last_seen_at="2026-05-14T09:00:00Z",
        )
        for index, (asset_id, principal_type, principal_name, permission) in enumerate(ACCESS_GRANTS, start=1)
    ]

    for grant in grants:
        role_id = f"role:{grant.principal_name}"
        if not any(asset.id == role_id for asset in assets):
            assets.append(
                Asset(
                    id=role_id,
                    name=grant.principal_name,
                    asset_type=AssetType.ROLE,
                    risk_score=68 if "old" not in grant.principal_name else 92,
                    description=f"Database principal from synthetic grant inventory: {grant.principal_name}.",
                )
            )
        edges.append(
            LineageEdge(
                id=f"edge:{grant.id}:read-by",
                source_asset_id=role_id,
                target_asset_id=grant.asset_id,
                edge_type=EdgeType.READ_BY,
                confidence=0.9,
                label=grant.permission,
                evidence={"source": grant.source, "raw_value_stored": False},
            )
        )

    findings = generate_findings(assets=assets, edges=edges, access_grants=grants)
    finding_assets, finding_edges = _finding_graph_objects(findings)
    assets.extend(finding_assets)
    edges.extend(finding_edges)
    _roll_up_risk_scores(assets, findings)

    return IntelligenceScan(
        workspace_id=WORKSPACE_ID,
        data_source_id=DATA_SOURCE_ID,
        scan_id="scan:northstar:2026-05-14",
        generated_at=datetime.now(UTC).isoformat(),
        assets=assets,
        edges=edges,
        access_grants=grants,
        findings=findings,
    )


def build_demo_intelligence() -> dict[str, object]:
    return to_plain(build_demo_scan())


def _finding_graph_objects(findings):
    assets: list[Asset] = []
    edges: list[LineageEdge] = []
    control_by_name = {
        "Access control": "control:access-control",
        "Audit controls": "control:audit-controls",
        "Minimum necessary": "control:minimum-necessary",
        "De-identification": "control:deidentification",
        "De-identification readiness": "control:deidentification",
        "AI governance": "control:ai-governance",
        "Risk analysis": "control:risk-analysis",
        "Lineage risk analysis": "control:risk-analysis",
        "Unique user identification": "control:access-control",
    }
    for finding in findings:
        finding_asset = Asset(
            id=finding.id,
            name=finding.title,
            asset_type=AssetType.FINDING,
            risk_score=finding.risk_score,
            description=finding.description,
        )
        assets.append(finding_asset)
        edges.append(
            LineageEdge(
                id=f"edge:{finding.id}:has-finding",
                source_asset_id=finding.asset_id,
                target_asset_id=finding.id,
                edge_type=EdgeType.HAS_FINDING,
                confidence=finding.confidence,
                label=finding.severity.value,
            )
        )
        for control_name in finding.control_mapping:
            control_id = control_by_name.get(control_name)
            if control_id:
                edges.append(
                    LineageEdge(
                        id=f"edge:{finding.id}:maps:{control_id}",
                        source_asset_id=finding.id,
                        target_asset_id=control_id,
                        edge_type=EdgeType.MAPS_TO_CONTROL,
                        confidence=0.8,
                        label=control_name,
                    )
                )
    return assets, edges


def _roll_up_risk_scores(assets: list[Asset], findings) -> None:
    max_by_asset: dict[str, int] = {}
    for finding in findings:
        max_by_asset[finding.asset_id] = max(max_by_asset.get(finding.asset_id, 0), finding.risk_score)
    for asset in assets:
        if asset.id in max_by_asset:
            asset.risk_score = max(asset.risk_score, max_by_asset[asset.id])
        if asset.asset_type == AssetType.TABLE:
            related = [finding.risk_score for finding in findings if finding.asset_id == asset.id or finding.asset_id.startswith(f"column:{asset.name}.")]
            if related:
                asset.risk_score = max(asset.risk_score, max(related))
