from __future__ import annotations

from collections import defaultdict
from itertools import count

from phi_guard_scanner.models import (
    AccessGrant,
    Asset,
    ClassificationLabel,
    EdgeType,
    Evidence,
    Finding,
    LineageEdge,
    RiskFactors,
    Severity,
)


def severity_for(score: int) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MODERATE
    return Severity.LOW


def calculate_score(factors: RiskFactors, boost: int = 0) -> int:
    base = factors.impact * factors.likelihood * factors.exposure * factors.control_gap * factors.confidence
    return min(100, max(0, round((base * 100) + boost)))


def generate_findings(
    assets: list[Asset],
    edges: list[LineageEdge],
    access_grants: list[AccessGrant],
) -> list[Finding]:
    by_id = {asset.id: asset for asset in assets}
    columns_by_table: dict[str, list[Asset]] = defaultdict(list)
    table_assets = [asset for asset in assets if asset.asset_type.value in {"table", "view", "export"}]
    findings: list[Finding] = []
    finding_counter = count(1)

    for asset in assets:
        if asset.table_name and asset.column_name:
            columns_by_table[asset.table_name].append(asset)

    table_labels = {table.name: _labels_for_table(columns_by_table[table.name]) for table in table_assets}
    outgoing = defaultdict(list)
    incoming = defaultdict(list)
    for edge in edges:
        outgoing[edge.source_asset_id].append(edge)
        incoming[edge.target_asset_id].append(edge)

    def next_id(slug: str) -> str:
        return f"finding:{next(finding_counter):03d}:{slug}"

    def append_finding(
        *,
        slug: str,
        title: str,
        asset_id: str,
        factors: RiskFactors,
        boost: int,
        description: str,
        observation: str,
        why_it_matters: str,
        control_mapping: list[str],
        remediation_summary: str,
        recommended_steps: list[str],
        human_review: str,
        blast_radius: dict[str, object],
        evidence: list[Evidence],
    ) -> None:
        score = calculate_score(factors, boost)
        findings.append(
            Finding(
                id=next_id(slug),
                title=title,
                severity=severity_for(score),
                status="open",
                risk_score=score,
                confidence=factors.confidence,
                asset_id=asset_id,
                description=description,
                observation=observation,
                why_it_matters=why_it_matters,
                control_mapping=control_mapping,
                remediation_summary=remediation_summary,
                recommended_steps=recommended_steps,
                human_review=human_review,
                blast_radius=blast_radius,
                evidence=evidence,
                risk_factors=factors,
            )
        )

    # Rule 1: direct identifier in health or payment context table.
    for table in table_assets:
        labels = table_labels[table.name]
        if ClassificationLabel.DIRECT_IDENTIFIER in labels and (
            ClassificationLabel.HEALTH_CONTEXT in labels or ClassificationLabel.PAYMENT_CONTEXT in labels
        ):
            direct_columns = _columns_with_label(columns_by_table[table.name], ClassificationLabel.DIRECT_IDENTIFIER)
            context_labels = [
                label.value
                for label in [ClassificationLabel.HEALTH_CONTEXT, ClassificationLabel.PAYMENT_CONTEXT]
                if label in labels
            ]
            factors = RiskFactors(impact=0.95, likelihood=0.72, exposure=_exposure(table), control_gap=0.78, confidence=0.9)
            append_finding(
                slug=f"{table.name}:phi-concentration",
                title=f"Direct identifiers combined with health/payment context in {table.name}",
                asset_id=table.id,
                factors=factors,
                boost=38,
                description=f"{table.name} contains direct identifiers plus {', '.join(context_labels)} signals.",
                observation=f"Columns {', '.join(column.column_name or column.name for column in direct_columns)} appear in a table with clinical or payment context.",
                why_it_matters="The combination of identifiers with health, care, or payment facts is a high-value ePHI concentration point.",
                control_mapping=["Access control", "Minimum necessary", "Risk analysis"],
                remediation_summary="Separate identifiers from analytics context, restrict raw-table access, and provide masked views for non-operational users.",
                recommended_steps=[
                    "Create role-specific views that omit direct identifiers.",
                    "Review whether each role needs raw identifiers for the declared purpose.",
                    "Add audit logging for reads and exports of this table.",
                ],
                human_review="Confirm the business purpose and whether identifiers are required for each workflow.",
                blast_radius=_blast_radius(table, edges, access_grants),
                evidence=[
                    Evidence(
                        evidence_type="classification",
                        safe_snippet=f"{table.name} has DIRECT_IDENTIFIER and {','.join(context_labels)} labels",
                        raw_value_stored=False,
                        metadata={"direct_columns": [column.column_name for column in direct_columns]},
                    )
                ],
            )

    # Rule 2: free text in patient-linked table.
    patient_linked_tables = _patient_linked_tables(table_assets, columns_by_table, edges)
    for table_name in sorted(patient_linked_tables):
        table = _table_named(table_assets, table_name)
        if table is None:
            continue
        free_text_columns = _columns_with_label(columns_by_table[table.name], ClassificationLabel.FREE_TEXT_PHI_RISK)
        for column in free_text_columns:
            factors = RiskFactors(impact=0.9, likelihood=0.78, exposure=_exposure(table), control_gap=0.82, confidence=0.84)
            append_finding(
                slug=f"{table.name}:{column.column_name}:free-text",
                title=f"Free-text PHI risk in {table.name}.{column.column_name}",
                asset_id=column.id,
                factors=factors,
                boost=42,
                description="A patient-linked free-text field may contain identifiers that are not visible from schema alone.",
                observation=f"{column.name} is a text-like field on a table that joins to patient records.",
                why_it_matters="Identifiers hidden in notes, messages, prompts, and support text can block de-identification and can leak through reports or logs.",
                control_mapping=["De-identification", "Minimum necessary", "Access control"],
                remediation_summary="Restrict raw text, provide redacted views, and audit exports of free-text content.",
                recommended_steps=[
                    "Split operational notes from analytics notes.",
                    "Run redaction before analytics or external export.",
                    "Limit raw-note access to roles with a documented need.",
                    "Add data-entry guidance for identifiers in free text.",
                ],
                human_review="Review sampled text locally to confirm whether detected patterns are patient identifiers.",
                blast_radius=_blast_radius(table, edges, access_grants),
                evidence=[
                    Evidence(
                        evidence_type="column_name+relationship",
                        safe_snippet=f"{column.name} is text-like and patient-linked",
                        raw_value_stored=False,
                        metadata={"data_type": column.data_type, "sample_shape": "contains phone/date/address-like tokens"},
                    )
                ],
            )

    # Rule 2b: embedded PHI in logs, comments, prompts, or other operational free text.
    for table in table_assets:
        free_text_columns = _columns_with_label(columns_by_table[table.name], ClassificationLabel.FREE_TEXT_PHI_RISK)
        for column in free_text_columns:
            column_labels = {classification.label for classification in column.classifications}
            if ClassificationLabel.DIRECT_IDENTIFIER not in column_labels and ClassificationLabel.HEALTH_CONTEXT not in column_labels:
                continue
            factors = RiskFactors(impact=0.92, likelihood=0.84, exposure=_exposure(table), control_gap=0.86, confidence=0.9)
            append_finding(
                slug=f"{table.name}:{column.column_name}:embedded-phi",
                title=f"Embedded PHI patterns in free-text field {table.name}.{column.column_name}",
                asset_id=column.id,
                factors=factors,
                boost=60,
                description="A free-text field contains identifier and/or health-context patterns even though the surrounding dataset may look operational.",
                observation=f"{column.name} has free-text, direct-identifier, and health-context signals from value profiling.",
                why_it_matters="Logs, messages, comments, and prompts often bypass normal schema controls and can leak PHI into observability, analytics, or support workflows.",
                control_mapping=["De-identification", "Minimum necessary", "Audit controls", "Access control"],
                remediation_summary="Redact identifiers before storing logs, split operational messages from analytics fields, and restrict/audit raw text access.",
                recommended_steps=[
                    "Add PHI redaction before this field is written.",
                    "Create a masked view for analytics and support review.",
                    "Add alerts for identifier patterns in logs and messages.",
                    "Set short retention for raw operational text.",
                ],
                human_review="Review local samples to confirm whether the detected text patterns represent real patient identifiers or synthetic test strings.",
                blast_radius=_blast_radius(table, edges, access_grants),
                evidence=[
                    Evidence(
                        evidence_type="free_text_value_profile",
                        safe_snippet=f"{column.name} contains embedded identifier/health-context patterns",
                        raw_value_stored=False,
                        metadata={
                            "labels": sorted(label.value for label in column_labels),
                            "safe_harbor_categories": _safe_harbor_categories(column),
                            "source": "masked value profiling",
                        },
                    )
                ],
            )

    # Rule 2c: sensitive mental-health context linked to identifiers.
    for table in table_assets:
        free_text_columns = _columns_with_label(columns_by_table[table.name], ClassificationLabel.FREE_TEXT_PHI_RISK)
        for column in free_text_columns:
            patterns = _value_patterns(column)
            column_labels = {classification.label for classification in column.classifications}
            if "mental_health_term" not in patterns or ClassificationLabel.DIRECT_IDENTIFIER not in column_labels:
                continue
            factors = RiskFactors(impact=1.0, likelihood=0.86, exposure=_exposure(table), control_gap=0.9, confidence=0.92)
            append_finding(
                slug=f"{table.name}:{column.column_name}:mental-health-phi",
                title=f"Sensitive mental-health context linked to identifiers in {table.name}.{column.column_name}",
                asset_id=column.id,
                factors=factors,
                boost=65,
                description="A free-text field links an identifier signal to psychiatric or mental-health context.",
                observation=f"{column.name} includes mental-health terminology and direct-identifier patterns from masked value profiling.",
                why_it_matters="Mental-health diagnoses are especially sensitive health information; linking them to names, IDs, contact details, SSNs, or MRNs creates a high-priority PHI risk signal.",
                control_mapping=["De-identification", "Minimum necessary", "Access control", "Audit controls"],
                remediation_summary="Treat the field as highly sensitive, redact identifiers before storage/export, and restrict raw text to approved care or operations workflows.",
                recommended_steps=[
                    "Add a denylist or entity detector for psychiatric diagnosis terms in operational logs.",
                    "Block direct identifiers from log and support-message ingestion.",
                    "Create an escalation review path for mental-health PHI findings.",
                    "Audit every raw-text access path for this field.",
                ],
                human_review="Confirm whether the mental-health term is tied to an identifiable patient and whether the workflow has an approved purpose.",
                blast_radius=_blast_radius(table, edges, access_grants),
                evidence=[
                    Evidence(
                        evidence_type="sensitive_health_context",
                        safe_snippet=f"{column.name} contains mental-health context plus identifier patterns",
                        raw_value_stored=False,
                        metadata={
                            "safe_harbor_categories": _safe_harbor_categories(column),
                            "sensitive_context": "mental_health",
                        },
                    )
                ],
            )

    # Rule 3: identifier flows into analytics/export/reporting.
    for edge in edges:
        source = by_id.get(edge.source_asset_id)
        target = by_id.get(edge.target_asset_id)
        if not source or not target:
            continue
        target_name = target.name.lower()
        analytics_like = any(token in target_name for token in ["analytics", "report", "export", "dashboard", "campaign"])
        if analytics_like and _has_label(source, ClassificationLabel.DIRECT_IDENTIFIER):
            factors = RiskFactors(impact=0.92, likelihood=0.8, exposure=_exposure(target), control_gap=0.84, confidence=edge.confidence)
            append_finding(
                slug=f"{source.name}:identifier-flow",
                title=f"Direct identifier flows into {target.name}",
                asset_id=target.id,
                factors=factors,
                boost=46,
                description=f"{source.name} appears to be derived into analytics or export asset {target.name}.",
                observation=f"Lineage edge {edge.edge_type.value} connects a direct identifier to {target.name}.",
                why_it_matters="Analytics and export datasets often need aggregate or tokenized values, not raw patient identifiers.",
                control_mapping=["Minimum necessary", "De-identification", "Lineage risk analysis"],
                remediation_summary="Replace raw identifiers with irreversible tokens or remove them from analytics exports.",
                recommended_steps=[
                    "Create a masked export view.",
                    "Use irreversible patient tokens for joins.",
                    "Document the business purpose for any retained identifier.",
                ],
                human_review="Confirm whether the downstream dataset is operational, reporting, marketing, or external sharing.",
                blast_radius=_blast_radius(target, edges, access_grants),
                evidence=[
                    Evidence(
                        evidence_type="lineage",
                        safe_snippet=f"{source.name} -> {target.name}",
                        raw_value_stored=False,
                        metadata={"edge_type": edge.edge_type.value, "confidence": edge.confidence},
                    )
                ],
            )

    # Rule 4: broad role access.
    grants_by_principal: dict[str, list[AccessGrant]] = defaultdict(list)
    for grant in access_grants:
        if grant.permission in {"read", "write", "admin", "export"}:
            grants_by_principal[grant.principal_name].append(grant)

    risky_role_tokens = ["analyst", "reporting", "support", "intern", "general", "service"]
    for principal, grants in grants_by_principal.items():
        if not any(token in principal.lower() for token in risky_role_tokens):
            continue
        labels = set()
        touched_tables: list[Asset] = []
        for grant in grants:
            asset = by_id.get(grant.asset_id)
            if asset and asset.asset_type.value in {"table", "view", "export"}:
                touched_tables.append(asset)
                labels |= table_labels.get(asset.name, set())
        if ClassificationLabel.DIRECT_IDENTIFIER in labels and (
            ClassificationLabel.HEALTH_CONTEXT in labels or ClassificationLabel.PAYMENT_CONTEXT in labels
        ):
            factors = RiskFactors(impact=0.9, likelihood=0.86, exposure=min(1.0, 0.35 + 0.12 * len(touched_tables)), control_gap=0.82, confidence=0.88)
            append_finding(
                slug=f"{principal}:broad-access",
                title=f"Broad PHI access for {principal}",
                asset_id=touched_tables[0].id if touched_tables else "asset:unknown",
                factors=factors,
                boost=36,
                description=f"{principal} can read assets containing identifiers and health or payment context.",
                observation=f"{principal} has access to {', '.join(table.name for table in touched_tables[:5])}.",
                why_it_matters="Roles with access to both identifiers and clinical/payment facts increase misuse and breach blast radius.",
                control_mapping=["Access control", "Minimum necessary", "Unique user identification"],
                remediation_summary="Narrow the role, separate duties, and route analytics users through masked views.",
                recommended_steps=[
                    "Split broad roles into purpose-specific roles.",
                    "Remove direct table grants where masked views are enough.",
                    "Review service-account ownership and last-use evidence.",
                ],
                human_review="Validate whether this principal is a shared account, service account, or named role with appropriate approvals.",
                blast_radius={"roles": [principal], "assets": [table.name for table in touched_tables], "record_count_estimate": sum(table.row_count_estimate or 0 for table in touched_tables)},
                evidence=[
                    Evidence(
                        evidence_type="access_grant",
                        safe_snippet=f"{principal} has read-like access to PHI assets",
                        raw_value_stored=False,
                        metadata={"grant_count": len(grants), "assets": [grant.asset_id for grant in grants]},
                    )
                ],
            )

    # Rule 5: de-identification blockers in exports or analytics tables.
    for table in table_assets:
        name = table.name.lower()
        if not any(token in name for token in ["export", "analytics", "segments", "report"]):
            continue
        blockers = _columns_with_label(columns_by_table[table.name], ClassificationLabel.DEIDENTIFICATION_BLOCKER)
        if blockers:
            factors = RiskFactors(impact=0.82, likelihood=0.78, exposure=_exposure(table), control_gap=0.76, confidence=0.82)
            append_finding(
                slug=f"{table.name}:deid-blocker",
                title=f"De-identification readiness blockers in {table.name}",
                asset_id=table.id,
                factors=factors,
                boost=25,
                description=f"{table.name} contains fields that likely block Safe Harbor-style readiness.",
                observation=f"Blocker columns include {', '.join((column.column_name or column.name) for column in blockers[:6])}.",
                why_it_matters="Export and analytics datasets usually need identifier removal, generalization, tokenization, or expert review before sharing.",
                control_mapping=["De-identification", "Minimum necessary"],
                remediation_summary="Remove direct identifiers, generalize quasi-identifiers, and review free text before export.",
                recommended_steps=[
                    "Remove email, phone, MRN, account, and SSN fields from export datasets.",
                    "Generalize dates to year or month where appropriate.",
                    "Replace DOB with age bucket.",
                    "Review free-text fields separately.",
                ],
                human_review="Confirm the intended recipient, permitted purpose, and whether an expert determination workflow applies.",
                blast_radius=_blast_radius(table, edges, access_grants),
                evidence=[
                    Evidence(
                        evidence_type="deidentification_blocker",
                        safe_snippet=f"{len(blockers)} blocker columns detected",
                        raw_value_stored=False,
                        metadata={"blocker_columns": [column.column_name for column in blockers]},
                    )
                ],
            )

    # Rule 6: joinability risk between identifiers and health/payment tables.
    for edge in edges:
        if edge.edge_type not in {EdgeType.REFERENCES, EdgeType.JOINS_TO}:
            continue
        source = by_id.get(edge.source_asset_id)
        target = by_id.get(edge.target_asset_id)
        if not source or not target or not source.table_name or not target.table_name:
            continue
        source_table = _table_named(table_assets, source.table_name)
        target_table = _table_named(table_assets, target.table_name)
        if not source_table or not target_table:
            continue
        source_labels = table_labels[source_table.name]
        target_labels = table_labels[target_table.name]
        joined_labels = source_labels | target_labels
        if ClassificationLabel.DIRECT_IDENTIFIER in joined_labels and (
            ClassificationLabel.HEALTH_CONTEXT in joined_labels or ClassificationLabel.PAYMENT_CONTEXT in joined_labels
        ):
            if source_table.name == target_table.name:
                continue
            factors = RiskFactors(impact=0.84, likelihood=0.66, exposure=max(_exposure(source_table), _exposure(target_table)), control_gap=0.68, confidence=edge.confidence)
            append_finding(
                slug=f"{source_table.name}:{target_table.name}:joinability",
                title=f"Joinability creates PHI risk between {source_table.name} and {target_table.name}",
                asset_id=source_table.id,
                factors=factors,
                boost=21,
                description="Separate tables become more sensitive when joined through patient, member, account, or encounter keys.",
                observation=f"{source.name} {edge.edge_type.value} {target.name}.",
                why_it_matters="Column-only scanners can miss PHI that emerges from relationships between identifiers and clinical or payment facts.",
                control_mapping=["Risk analysis", "Minimum necessary", "Access control"],
                remediation_summary="Treat the join path as sensitive and restrict access to combined datasets.",
                recommended_steps=[
                    "Document approved joins and purposes.",
                    "Use tokenized keys for analytics joins.",
                    "Limit users who can query both sides of the relationship.",
                ],
                human_review="Confirm whether this join is operationally required and whether combined result sets are exported.",
                blast_radius={"tables": [source_table.name, target_table.name], "edge": edge.id, "record_count_estimate": max(source_table.row_count_estimate or 0, target_table.row_count_estimate or 0)},
                evidence=[
                    Evidence(
                        evidence_type="relationship",
                        safe_snippet=f"{source.name} joins to {target.name}",
                        raw_value_stored=False,
                        metadata={"edge_type": edge.edge_type.value, "confidence": edge.confidence},
                    )
                ],
            )

    # Rule 7: audit gap for high-risk tables.
    audited_tables = {"patients", "claims", "payments", "lab_results"}
    for table in table_assets:
        labels = table_labels[table.name]
        if table.name in audited_tables:
            continue
        if ClassificationLabel.DIRECT_IDENTIFIER in labels and (
            ClassificationLabel.HEALTH_CONTEXT in labels
            or ClassificationLabel.PAYMENT_CONTEXT in labels
            or ClassificationLabel.FREE_TEXT_PHI_RISK in labels
        ):
            factors = RiskFactors(impact=0.83, likelihood=0.64, exposure=_exposure(table), control_gap=0.88, confidence=0.78)
            append_finding(
                slug=f"{table.name}:audit-gap",
                title=f"Auditability gap for high-risk table {table.name}",
                asset_id=table.id,
                factors=factors,
                boost=24,
                description=f"No audit evidence is modeled for high-risk table {table.name}.",
                observation="The demo evidence inventory does not include read/export audit coverage for this asset.",
                why_it_matters="If a privacy or security event occurs, weak auditability makes it harder to reconstruct who accessed sensitive data.",
                control_mapping=["Audit controls", "Risk analysis"],
                remediation_summary="Enable database or application-level audit logging for reads, exports, and access changes.",
                recommended_steps=[
                    "Log user, role, table, action, timestamp, request ID, and business purpose.",
                    "Protect audit logs from modification.",
                    "Review audit coverage during each scan.",
                ],
                human_review="Confirm whether audit evidence exists outside the database metadata inspected by this scan.",
                blast_radius=_blast_radius(table, edges, access_grants),
                evidence=[
                    Evidence(
                        evidence_type="audit_config",
                        safe_snippet="no audit evidence detected",
                        raw_value_stored=False,
                        metadata={"audit_evidence": "missing"},
                    )
                ],
            )

    # Rule 8: AI exposure risk.
    for table in table_assets:
        labels = table_labels[table.name]
        if ClassificationLabel.AI_EXPOSURE_RISK not in labels and "ai_" not in table.name.lower():
            continue
        if not labels & {
            ClassificationLabel.DIRECT_IDENTIFIER,
            ClassificationLabel.HEALTH_CONTEXT,
            ClassificationLabel.FREE_TEXT_PHI_RISK,
            ClassificationLabel.LINKABLE_KEY,
        }:
            continue
        factors = RiskFactors(impact=0.94, likelihood=0.82, exposure=_exposure(table), control_gap=0.9, confidence=0.86)
        append_finding(
            slug=f"{table.name}:ai-exposure",
            title=f"Potential PHI exposure in AI workflow table {table.name}",
            asset_id=table.id,
            factors=factors,
            boost=55,
            description=f"{table.name} appears to store prompt, model, embedding, or AI workflow content with PHI risk signals.",
            observation="AI/prompt labels overlap with PHI-risk labels.",
            why_it_matters="Prompt, embedding, and model logs can create hard-to-track downstream copies of sensitive data.",
            control_mapping=["AI governance", "Access control", "Audit controls"],
            remediation_summary="Block raw PHI from prompts and logs, retain sanitized metadata, and audit model workflows.",
            recommended_steps=[
                "Add PHI redaction before model calls.",
                "Store prompt metadata rather than raw prompts.",
                "Use a model/provider allowlist.",
                "Review retention for prompt and embedding stores.",
            ],
            human_review="Confirm whether raw prompts are persisted and whether any third-party model or vendor receives content.",
            blast_radius=_blast_radius(table, edges, access_grants),
            evidence=[
                Evidence(
                    evidence_type="ai_label",
                    safe_snippet=f"{table.name} contains AI workflow and PHI-risk labels",
                    raw_value_stored=False,
                    metadata={"labels": sorted(label.value for label in labels)},
                )
            ],
        )

    findings.sort(key=lambda finding: finding.risk_score, reverse=True)
    return findings


def _has_label(asset: Asset, label: ClassificationLabel) -> bool:
    return any(classification.label == label for classification in asset.classifications)


def _labels_for_table(columns: list[Asset]) -> set[ClassificationLabel]:
    return {classification.label for column in columns for classification in column.classifications}


def _columns_with_label(columns: list[Asset], label: ClassificationLabel) -> list[Asset]:
    return [column for column in columns if _has_label(column, label)]


def _value_patterns(column: Asset) -> set[str]:
    patterns: set[str] = set()
    for classification in column.classifications:
        patterns.update(str(pattern) for pattern in classification.details.get("value_patterns", []))
    return patterns


def _safe_harbor_categories(column: Asset) -> list[str]:
    pattern_to_category = {
        "name": "names",
        "street_address": "geographic subdivisions smaller than a state",
        "address_term": "geographic subdivisions smaller than a state",
        "geography": "geographic subdivisions smaller than a state",
        "zip": "ZIP/postal code",
        "dob": "dates except year",
        "date": "dates except year",
        "phone": "telephone numbers",
        "email": "email addresses",
        "ssn": "Social Security numbers",
        "mrn": "medical record numbers",
        "ip": "IP addresses",
    }
    categories = {pattern_to_category[pattern] for pattern in _value_patterns(column) if pattern in pattern_to_category}
    if _has_label(column, ClassificationLabel.FREE_TEXT_PHI_RISK):
        categories.add("free-text identifiers")
    return sorted(categories)


def _table_named(tables: list[Asset], name: str) -> Asset | None:
    return next((table for table in tables if table.name == name), None)


def _exposure(table: Asset) -> float:
    row_count = table.row_count_estimate or 0
    if row_count >= 100_000:
        return 1.0
    if row_count >= 50_000:
        return 0.86
    if row_count >= 10_000:
        return 0.72
    if row_count >= 1_000:
        return 0.56
    return 0.42


def _patient_linked_tables(
    table_assets: list[Asset],
    columns_by_table: dict[str, list[Asset]],
    edges: list[LineageEdge],
) -> set[str]:
    linked = set()
    for table in table_assets:
        if table.name == "patients":
            linked.add(table.name)
        for column in columns_by_table[table.name]:
            if column.column_name in {"patient_id", "member_id", "person_id", "mrn"}:
                linked.add(table.name)
    for edge in edges:
        if edge.edge_type in {EdgeType.REFERENCES, EdgeType.JOINS_TO} and "patient" in edge.label.lower():
            for asset_id in [edge.source_asset_id, edge.target_asset_id]:
                table_name = _table_name_from_column_asset_id(asset_id)
                if table_name:
                    linked.add(table_name)
    return linked


def _table_name_from_column_asset_id(asset_id: str) -> str | None:
    if not asset_id.startswith("column:"):
        return None
    column_ref = asset_id.removeprefix("column:")
    if "." not in column_ref:
        return None
    return column_ref.split(".", 1)[0]


def _blast_radius(table: Asset, edges: list[LineageEdge], grants: list[AccessGrant]) -> dict[str, object]:
    downstream = [
        edge.target_asset_id
        for edge in edges
        if edge.source_asset_id == table.id or edge.source_asset_id.startswith(f"column:{table.name}.")
    ]
    upstream = [
        edge.source_asset_id
        for edge in edges
        if edge.target_asset_id == table.id or edge.target_asset_id.startswith(f"column:{table.name}.")
    ]
    roles = sorted({grant.principal_name for grant in grants if grant.asset_id == table.id})
    return {
        "base_asset": table.name,
        "record_count_estimate": table.row_count_estimate or 0,
        "downstream_assets": downstream[:12],
        "upstream_assets": upstream[:12],
        "roles": roles,
    }
