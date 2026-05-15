from __future__ import annotations

import csv
import io
import json
import os
import re
import sqlite3
import tempfile
import zipfile
from collections import Counter, defaultdict
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any, Iterable
from xml.etree import ElementTree

from phi_guard_scanner.classifiers.patterns import DATE_RE, text_pattern_labels, value_pattern_labels
from phi_guard_scanner.classifiers.schema_classifier import ColumnProfile, classify_column
from phi_guard_scanner.demo import CONTROL_ASSETS, _finding_graph_objects, _roll_up_risk_scores
from phi_guard_scanner.models import (
    AccessGrant,
    Asset,
    AssetType,
    IntelligenceScan,
    EdgeType,
    LineageEdge,
    to_plain,
)
from phi_guard_scanner.rules.risk_rules import generate_findings

MAX_PROJECT_FILES = 80
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 10 * 1024 * 1024
MAX_SAMPLE_ROWS = 100
MAX_SAMPLE_VALUES_PER_COLUMN = 40
SUPPORTED_EXTENSIONS = {
    ".csv",
    ".tsv",
    ".json",
    ".jsonl",
    ".ndjson",
    ".xml",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".sql",
    ".log",
    ".txt",
    ".zip",
}


@dataclass(frozen=True)
class UploadedInput:
    filename: str
    content: bytes


@dataclass
class ImportedColumn:
    name: str
    data_type: str
    sample_values: list[str] = field(default_factory=list)


@dataclass
class ImportedRelationship:
    source_table: str
    source_column: str
    target_table: str
    target_column: str
    edge_type: EdgeType
    confidence: float
    label: str


@dataclass
class ImportedTable:
    name: str
    source_path: str
    source_format: str
    row_count_estimate: int
    columns: list[ImportedColumn]
    relationships: list[ImportedRelationship] = field(default_factory=list)


@dataclass
class ImportResult:
    project_name: str
    tables: list[ImportedTable]
    warnings: list[str] = field(default_factory=list)
    unsupported_files: list[str] = field(default_factory=list)
    parsed_files: list[str] = field(default_factory=list)


def build_uploaded_intelligence(inputs: Iterable[UploadedInput], project_name: str = "Uploaded Data Project") -> dict[str, object]:
    result = import_uploaded_project(inputs, project_name=project_name)
    scan = _build_scan_from_import(result)
    return to_plain(scan)


def import_uploaded_project(inputs: Iterable[UploadedInput], project_name: str = "Uploaded Data Project") -> ImportResult:
    result = ImportResult(project_name=project_name, tables=[])
    seen_files = 0
    for uploaded in inputs:
        if not uploaded.filename:
            result.warnings.append("Skipped unnamed upload.")
            continue
        if len(uploaded.content) > MAX_UPLOAD_BYTES:
            result.warnings.append(f"Skipped {uploaded.filename}: file exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.")
            continue
        seen_files += 1
        if seen_files > MAX_PROJECT_FILES:
            result.warnings.append(f"Stopped after {MAX_PROJECT_FILES} files to keep scan bounded.")
            break
        _parse_file(uploaded.filename, uploaded.content, result)

    result.tables = _deduplicate_table_names(result.tables)
    inferred_edges = _infer_relationships(result.tables)
    for edge in inferred_edges:
        source = next((table for table in result.tables if table.name == edge.source_table), None)
        if source:
            source.relationships.append(edge)
    return result


def _parse_file(path: str, content: bytes, result: ImportResult) -> None:
    suffix = PurePosixPath(path.replace("\\", "/")).suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        result.unsupported_files.append(path)
        return

    try:
        if suffix == ".zip":
            _parse_zip(path, content, result)
        elif suffix in {".csv", ".tsv"}:
            result.tables.append(_parse_delimited(path, content, delimiter="\t" if suffix == ".tsv" else None))
            result.parsed_files.append(path)
        elif suffix in {".json", ".jsonl", ".ndjson"}:
            result.tables.extend(_parse_json(path, content, line_delimited=suffix in {".jsonl", ".ndjson"}))
            result.parsed_files.append(path)
        elif suffix == ".xml":
            result.tables.extend(_parse_xml(path, content))
            result.parsed_files.append(path)
        elif suffix in {".sqlite", ".sqlite3", ".db"}:
            result.tables.extend(_parse_sqlite(path, content))
            result.parsed_files.append(path)
        elif suffix == ".sql":
            result.tables.extend(_parse_sql_ddl(path, content))
            result.parsed_files.append(path)
        elif suffix in {".log", ".txt"}:
            result.tables.append(_parse_log(path, content))
            result.parsed_files.append(path)
    except Exception as exc:  # noqa: BLE001 - scanner should continue through imperfect project uploads.
        result.warnings.append(f"Could not parse {path}: {exc}")


def _parse_zip(path: str, content: bytes, result: ImportResult) -> None:
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = [member for member in archive.infolist() if not member.is_dir()]
        for member in members[:MAX_PROJECT_FILES]:
            member_path = PurePosixPath(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                result.warnings.append(f"Skipped unsafe archive path {member.filename}.")
                continue
            if member.file_size > MAX_ZIP_MEMBER_BYTES:
                result.warnings.append(f"Skipped {member.filename}: archive member exceeds size limit.")
                continue
            nested_path = f"{path}/{member.filename}"
            _parse_file(nested_path, archive.read(member), result)
        if len(members) > MAX_PROJECT_FILES:
            result.warnings.append(f"{path} contains more than {MAX_PROJECT_FILES} files; remaining members were skipped.")


def _parse_delimited(path: str, content: bytes, delimiter: str | None = None) -> ImportedTable:
    text = _decode_text(content)
    sample = text[:4096]
    if delimiter is None:
        try:
            delimiter = csv.Sniffer().sniff(sample).delimiter
        except csv.Error:
            delimiter = ","

    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    try:
        header_row = next(reader)
    except StopIteration:
        return ImportedTable(
            name=_table_name_from_path(path),
            source_path=path,
            source_format="csv",
            row_count_estimate=0,
            columns=[],
        )

    header = [_clean_column_name(value, index) for index, value in enumerate(header_row)]
    column_values: dict[str, list[str]] = {column_name: [] for column_name in header}
    row_count = 0
    for row in reader:
        row_count += 1
        for index, column_name in enumerate(header):
            if index < len(row):
                _collect_sample_value(column_values[column_name], row[index])

    columns = [
        ImportedColumn(name=column_name, data_type=_infer_type(values), sample_values=values)
        for column_name, values in column_values.items()
    ]
    return ImportedTable(
        name=_table_name_from_path(path),
        source_path=path,
        source_format="tsv" if delimiter == "\t" else "csv",
        row_count_estimate=row_count,
        columns=columns,
    )


def _parse_json(path: str, content: bytes, line_delimited: bool) -> list[ImportedTable]:
    text = _decode_text(content)
    if line_delimited:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        fhir_tables = _fhir_tables_from_records(path, rows)
        if fhir_tables:
            return fhir_tables
        return [_table_from_records(_table_name_from_path(path), path, "jsonl", rows)]

    payload = json.loads(text)
    tables: list[ImportedTable] = []
    dbt_tables = _parse_dbt_manifest(path, payload)
    if dbt_tables:
        return dbt_tables
    fhir_tables = _parse_fhir_payload(path, payload)
    if fhir_tables:
        return fhir_tables
    if isinstance(payload, list):
        tables.append(_table_from_records(_table_name_from_path(path), path, "json", payload))
    elif isinstance(payload, dict):
        extracted = False
        for key, value in payload.items():
            if isinstance(value, list) and all(isinstance(item, dict) for item in value[:MAX_SAMPLE_ROWS]):
                tables.append(_table_from_records(_safe_identifier(key), path, "json", value))
                extracted = True
        if not extracted:
            tables.append(_table_from_records(_table_name_from_path(path), path, "json", [payload]))
    else:
        tables.append(_table_from_records(_table_name_from_path(path), path, "json", [{"value": payload}]))
    return tables


def _parse_log(path: str, content: bytes) -> ImportedTable:
    rows = [
        {"line_number": index, "log_message": line}
        for index, line in enumerate(_decode_text(content).splitlines(), start=1)
        if line.strip()
    ]
    return _table_from_records(_table_name_from_path(path), path, "log", rows)


def _parse_dbt_manifest(path: str, payload: Any) -> list[ImportedTable]:
    if not isinstance(payload, dict) or not isinstance(payload.get("nodes"), dict):
        return []
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    if PurePosixPath(path.replace("\\", "/")).name.lower() != "manifest.json" and "dbt_schema_version" not in metadata:
        return []

    tables: list[ImportedTable] = []
    for node_id, node in payload["nodes"].items():
        if not isinstance(node, dict) or node.get("resource_type") not in {"model", "seed", "snapshot", "source"}:
            continue
        table_name = _safe_identifier(node.get("alias") or node.get("name") or node_id.split(".")[-1])
        columns = [
            ImportedColumn(name=_safe_identifier(column_name), data_type=str(column.get("data_type") or "text"), sample_values=[])
            for column_name, column in sorted((node.get("columns") or {}).items())
            if isinstance(column, dict)
        ]
        tables.append(
            ImportedTable(
                name=table_name,
                source_path=path,
                source_format="dbt_manifest",
                row_count_estimate=0,
                columns=columns,
            )
        )
    return tables


def _parse_fhir_payload(path: str, payload: Any) -> list[ImportedTable]:
    if isinstance(payload, dict) and payload.get("resourceType") == "Bundle":
        entries = payload.get("entry", [])
        resources = [entry.get("resource") for entry in entries if isinstance(entry, dict) and isinstance(entry.get("resource"), dict)]
        return _fhir_tables_from_records(path, resources)
    if isinstance(payload, dict) and isinstance(payload.get("resourceType"), str):
        return _fhir_tables_from_records(path, [payload])
    if isinstance(payload, list):
        return _fhir_tables_from_records(path, payload)
    return []


def _fhir_tables_from_records(path: str, records: list[Any]) -> list[ImportedTable]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("resourceType"), str):
            continue
        grouped[_safe_identifier(record["resourceType"])].append(record)
    return [
        _table_from_records(resource_type, path, "fhir", rows)
        for resource_type, rows in sorted(grouped.items())
    ]


def _parse_xml(path: str, content: bytes) -> list[ImportedTable]:
    root = ElementTree.fromstring(_decode_text(content))
    root_children = list(root)
    tables: list[ImportedTable] = []
    if root_children:
        counts = Counter(_strip_namespace(child.tag) for child in root_children)
        repeated_tags = {tag for tag, count in counts.items() if count > 1}
        if repeated_tags:
            for tag in sorted(repeated_tags):
                rows = [_row_from_xml(child) for child in root_children if _strip_namespace(child.tag) == tag]
                tables.append(_table_from_records(_safe_identifier(tag), path, "xml", rows))
            return tables

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for element in root.iter():
        if element is root:
            continue
        row = _row_from_xml(element)
        if row:
            grouped[_strip_namespace(element.tag)].append(row)
    for tag, rows in grouped.items():
        if len(rows) > 1:
            tables.append(_table_from_records(_safe_identifier(tag), path, "xml", rows))
    if not tables:
        tables.append(_table_from_records(_table_name_from_path(path), path, "xml", [_row_from_xml(root)]))
    return tables


def _parse_sqlite(path: str, content: bytes) -> list[ImportedTable]:
    tables: list[ImportedTable] = []
    handle = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    temp_path = handle.name
    try:
        handle.write(content)
        handle.close()
        connection = sqlite3.connect(f"file:{temp_path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            table_names = [
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            for table_name in table_names:
                columns_info = list(connection.execute(f"PRAGMA table_info({_quote_sqlite_identifier(table_name)})"))
                row_count = connection.execute(f"SELECT COUNT(*) AS count FROM {_quote_sqlite_identifier(table_name)}").fetchone()["count"]
                columns = []
                for column in columns_info:
                    raw_column_name = str(column["name"])
                    values: list[str] = []
                    for row in connection.execute(
                        f"SELECT {_quote_sqlite_identifier(raw_column_name)} AS value "
                        f"FROM {_quote_sqlite_identifier(table_name)} "
                        f"WHERE {_quote_sqlite_identifier(raw_column_name)} IS NOT NULL"
                    ):
                        _collect_sample_value(values, str(row["value"]))
                    columns.append(
                        ImportedColumn(
                            name=raw_column_name,
                            data_type=str(column["type"] or _infer_type(values)),
                            sample_values=values,
                        )
                    )
                imported = ImportedTable(
                    name=_safe_identifier(table_name),
                    source_path=path,
                    source_format="sqlite",
                    row_count_estimate=int(row_count),
                    columns=columns,
                )
                imported.relationships.extend(_sqlite_relationships(connection, imported.name, table_name))
                tables.append(imported)
        finally:
            connection.close()
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temp_path)
    return tables


def _parse_sql_ddl(path: str, content: bytes) -> list[ImportedTable]:
    text = _decode_text(content)
    tables: list[ImportedTable] = []
    pattern = re.compile(
        r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?P<name>[\w\".\[\]`]+)\s*\((?P<body>.*?)\)\s*;",
        re.IGNORECASE | re.DOTALL,
    )
    for match in pattern.finditer(text):
        raw_name = match.group("name").strip("\"`[]")
        table_name = _safe_identifier(raw_name.split(".")[-1])
        columns: list[ImportedColumn] = []
        relationships: list[ImportedRelationship] = []
        for part in _split_sql_columns(match.group("body")):
            stripped = part.strip()
            if not stripped:
                continue
            first_word = stripped.split(maxsplit=1)[0].strip("\"`[]").lower()
            if first_word in {"primary", "foreign", "constraint", "unique", "check", "key"}:
                relationships.extend(_table_constraint_relationships(table_name, stripped))
                continue
            column_name, data_type = _parse_column_definition(stripped)
            if column_name:
                columns.append(ImportedColumn(name=column_name, data_type=data_type, sample_values=[]))
                inline_ref = _inline_reference(table_name, column_name, stripped)
                if inline_ref:
                    relationships.append(inline_ref)
        tables.append(
            ImportedTable(
                name=table_name,
                source_path=path,
                source_format="sql",
                row_count_estimate=0,
                columns=columns,
                relationships=relationships,
            )
        )
    return tables


def _build_scan_from_import(result: ImportResult) -> IntelligenceScan:
    database_name = result.project_name or "Uploaded Data Project"
    assets: list[Asset] = [
        Asset(
            id="database:uploaded",
            name=database_name,
            asset_type=AssetType.DATABASE,
            description="Uploaded project scan. Raw content is parsed in memory; scan results store sanitized metadata only.",
            metadata={
                "source_mode": "upload",
                "parsed_files": result.parsed_files,
                "unsupported_files": result.unsupported_files,
                "warnings": result.warnings,
            },
        ),
        Asset(
            id="schema:uploaded",
            name="uploaded",
            asset_type=AssetType.SCHEMA,
            schema_name="uploaded",
            description="Logical schema generated from uploaded files.",
        ),
    ]
    edges: list[LineageEdge] = [
        LineageEdge(
            id="edge:uploaded-database-schema",
            source_asset_id="database:uploaded",
            target_asset_id="schema:uploaded",
            edge_type=EdgeType.CONTAINS,
            label="contains",
        )
    ]

    for control_id, name in CONTROL_ASSETS:
        assets.append(Asset(id=control_id, name=name, asset_type=AssetType.CONTROL, description=f"HIPAA-oriented {name.lower()} mapping."))

    for table in result.tables:
        table_asset = Asset(
            id=f"table:{table.name}",
            name=table.name,
            asset_type=AssetType.TABLE,
            schema_name="uploaded",
            table_name=table.name,
            row_count_estimate=table.row_count_estimate,
            description=f"{table.source_format.upper()} asset from {table.source_path}.",
            metadata={"source_path": table.source_path, "source_format": table.source_format},
        )
        assets.append(table_asset)
        edges.append(
            LineageEdge(
                id=f"edge:uploaded-contains-{table.name}",
                source_asset_id="schema:uploaded",
                target_asset_id=table_asset.id,
                edge_type=EdgeType.CONTAINS,
                label="contains",
            )
        )
        for column in table.columns:
            profile = ColumnProfile(
                table_name=table.name,
                column_name=column.name,
                data_type=column.data_type,
                sample_shapes=column.sample_values,
            )
            column_asset = Asset(
                id=f"column:{table.name}.{column.name}",
                name=f"{table.name}.{column.name}",
                asset_type=AssetType.COLUMN,
                schema_name="uploaded",
                table_name=table.name,
                column_name=column.name,
                data_type=column.data_type,
                row_count_estimate=table.row_count_estimate,
                classifications=classify_column(profile),
                metadata={"sample_value_count": len(column.sample_values), "raw_value_stored": False},
            )
            assets.append(column_asset)
            edges.append(
                LineageEdge(
                    id=f"edge:{table.name}-contains-{column.name}",
                    source_asset_id=table_asset.id,
                    target_asset_id=column_asset.id,
                    edge_type=EdgeType.CONTAINS,
                    label="column",
                )
            )

    for index, relationship in enumerate(_all_relationships(result.tables), start=1):
        source = f"column:{relationship.source_table}.{relationship.source_column}"
        target = f"column:{relationship.target_table}.{relationship.target_column}"
        if any(asset.id == source for asset in assets) and any(asset.id == target for asset in assets):
            edges.append(
                LineageEdge(
                    id=f"edge:uploaded-relationship:{index}",
                    source_asset_id=source,
                    target_asset_id=target,
                    edge_type=relationship.edge_type,
                    confidence=relationship.confidence,
                    label=relationship.label,
                    evidence={"raw_value_stored": False, "source": "upload_inference"},
                )
            )

    grants = [
        AccessGrant(
            id=f"grant:uploaded:{index}",
            asset_id=f"table:{table.name}",
            principal_type="role",
            principal_name="uploaded_dataset_owner",
            permission="read",
            source="upload_session",
            last_seen_at=datetime.now(UTC).isoformat(),
        )
        for index, table in enumerate(result.tables, start=1)
    ]
    assets.append(
        Asset(
            id="role:uploaded_dataset_owner",
            name="uploaded_dataset_owner",
            asset_type=AssetType.ROLE,
            description="Synthetic owner role representing the local upload session.",
            risk_score=0,
        )
    )
    for grant in grants:
        edges.append(
            LineageEdge(
                id=f"edge:{grant.id}:read-by",
                source_asset_id="role:uploaded_dataset_owner",
                target_asset_id=grant.asset_id,
                edge_type=EdgeType.READ_BY,
                confidence=0.75,
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
        workspace_id="workspace:uploaded",
        data_source_id="datasource:uploaded-project",
        scan_id=f"scan:uploaded:{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}",
        generated_at=datetime.now(UTC).isoformat(),
        assets=assets,
        edges=edges,
        access_grants=grants,
        findings=findings,
    )


def _table_from_records(name: str, path: str, source_format: str, records: list[Any]) -> ImportedTable:
    rows = [_flatten_record(record) for record in records]
    headers = sorted({key for row in rows for key in row})
    columns = _columns_from_dict_rows(headers, rows)
    return ImportedTable(
        name=_safe_identifier(name),
        source_path=path,
        source_format=source_format,
        row_count_estimate=len(records),
        columns=columns,
    )


def _columns_from_rows(headers: list[str], rows: list[list[str]]) -> list[ImportedColumn]:
    column_values: dict[str, list[str]] = {header: [] for header in headers}
    for row in rows[:MAX_SAMPLE_ROWS]:
        for index, header in enumerate(headers):
            if index < len(row) and row[index] not in {None, ""}:
                _collect_sample_value(column_values[header], str(row[index]))
    return [
        ImportedColumn(name=header, data_type=_infer_type(values), sample_values=values[:MAX_SAMPLE_VALUES_PER_COLUMN])
        for header, values in column_values.items()
    ]


def _columns_from_dict_rows(headers: list[str], rows: list[dict[str, Any]]) -> list[ImportedColumn]:
    columns = []
    for header in headers:
        values: list[str] = []
        for row in rows:
            if header in row and row[header] not in {None, ""}:
                _collect_sample_value(values, str(row[header]))
        columns.append(ImportedColumn(name=_safe_identifier(header), data_type=_infer_type(values), sample_values=values[:MAX_SAMPLE_VALUES_PER_COLUMN]))
    return columns


def _collect_sample_value(values: list[str], value: str) -> None:
    cleaned = value.strip()
    if not cleaned:
        return
    if len(cleaned) > 500:
        cleaned = cleaned[:500]
    if len(values) < MAX_SAMPLE_VALUES_PER_COLUMN:
        values.append(cleaned)
        return
    if _is_interesting_value(cleaned) and not any(_is_interesting_value(existing) for existing in values):
        values[0] = cleaned
    elif _is_interesting_value(cleaned):
        for index, existing in enumerate(values):
            if not _is_interesting_value(existing):
                values[index] = cleaned
                break


def _is_interesting_value(value: str) -> bool:
    return bool(value_pattern_labels([value]) or text_pattern_labels([value]))


def _infer_relationships(tables: list[ImportedTable]) -> list[ImportedRelationship]:
    relationships: list[ImportedRelationship] = []
    table_by_name = {table.name: table for table in tables}
    column_names_by_table = {table.name: {column.name for column in table.columns} for table in tables}

    for table in tables:
        for column in table.columns:
            if not column.name.endswith("_id"):
                continue
            prefix = column.name.removesuffix("_id")
            candidates = [prefix, f"{prefix}s", f"{prefix}_records"]
            for candidate in candidates:
                if candidate in table_by_name and "id" in column_names_by_table[candidate] and candidate != table.name:
                    relationships.append(
                        ImportedRelationship(
                            source_table=table.name,
                            source_column=column.name,
                            target_table=candidate,
                            target_column="id",
                            edge_type=EdgeType.JOINS_TO,
                            confidence=0.74,
                            label="inferred key join",
                        )
                    )

    identifier_columns = {"email", "phone", "phone_number", "ssn", "mrn", "medical_record_number", "patient_id"}
    for source_table in tables:
        for target_table in tables:
            if source_table.name == target_table.name:
                continue
            target_name = target_table.name.lower()
            if not any(token in target_name for token in ["analytics", "report", "export", "dashboard", "campaign", "segment"]):
                continue
            source_columns = {column.name for column in source_table.columns}
            target_columns = {column.name for column in target_table.columns}
            for column_name in sorted((source_columns & target_columns) & identifier_columns):
                relationships.append(
                    ImportedRelationship(
                        source_table=source_table.name,
                        source_column=column_name,
                        target_table=target_table.name,
                        target_column=column_name,
                        edge_type=EdgeType.DERIVES_FROM,
                        confidence=0.68,
                        label="same-name lineage inference",
                    )
                )
    return relationships


def _all_relationships(tables: list[ImportedTable]) -> list[ImportedRelationship]:
    return [relationship for table in tables for relationship in table.relationships]


def _sqlite_relationships(connection: sqlite3.Connection, safe_table_name: str, raw_table_name: str) -> list[ImportedRelationship]:
    relationships = []
    for row in connection.execute(f"PRAGMA foreign_key_list({_quote_sqlite_identifier(raw_table_name)})"):
        relationships.append(
            ImportedRelationship(
                source_table=safe_table_name,
                source_column=_safe_identifier(row["from"]),
                target_table=_safe_identifier(row["table"]),
                target_column=_safe_identifier(row["to"]),
                edge_type=EdgeType.REFERENCES,
                confidence=0.95,
                label="sqlite foreign key",
            )
        )
    return relationships


def _table_constraint_relationships(table_name: str, definition: str) -> list[ImportedRelationship]:
    match = re.search(
        r"foreign\s+key\s*\((?P<source>[\w\"`[\]]+)\)\s+references\s+(?P<table>[\w\".`[\]]+)\s*\((?P<target>[\w\"`[\]]+)\)",
        definition,
        re.IGNORECASE,
    )
    if not match:
        return []
    return [
        ImportedRelationship(
            source_table=table_name,
            source_column=_safe_identifier(match.group("source")),
            target_table=_safe_identifier(match.group("table").split(".")[-1]),
            target_column=_safe_identifier(match.group("target")),
            edge_type=EdgeType.REFERENCES,
            confidence=0.9,
            label="sql foreign key",
        )
    ]


def _inline_reference(table_name: str, column_name: str, definition: str) -> ImportedRelationship | None:
    match = re.search(r"references\s+(?P<table>[\w\".`[\]]+)\s*\((?P<target>[\w\"`[\]]+)\)", definition, re.IGNORECASE)
    if not match:
        return None
    return ImportedRelationship(
        source_table=table_name,
        source_column=column_name,
        target_table=_safe_identifier(match.group("table").split(".")[-1]),
        target_column=_safe_identifier(match.group("target")),
        edge_type=EdgeType.REFERENCES,
        confidence=0.86,
        label="sql inline foreign key",
    )


def _parse_column_definition(definition: str) -> tuple[str, str]:
    tokens = definition.strip().split()
    if not tokens:
        return "", "text"
    column_name = _safe_identifier(tokens[0])
    constraint_words = {"primary", "not", "null", "unique", "references", "default", "check", "constraint", "collate"}
    data_type_tokens = []
    for token in tokens[1:]:
        if token.lower() in constraint_words:
            break
        data_type_tokens.append(token)
    return column_name, " ".join(data_type_tokens).strip(",") or "text"


def _split_sql_columns(body: str) -> list[str]:
    parts = []
    current = []
    depth = 0
    for char in body:
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current))
    return parts


def _flatten_record(record: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(record, dict):
        flattened = {}
        for key, value in record.items():
            key_name = f"{prefix}_{key}" if prefix else str(key)
            if isinstance(value, dict):
                flattened.update(_flatten_record(value, key_name))
            elif isinstance(value, list):
                flattened[key_name] = len(value)
            else:
                flattened[key_name] = value
        return flattened
    return {"value": record}


def _row_from_xml(element: ElementTree.Element) -> dict[str, str]:
    row = {f"attr_{_strip_namespace(key)}": value for key, value in element.attrib.items()}
    if element.text and element.text.strip() and not list(element):
        row["value"] = element.text.strip()
    for child in element:
        tag = _strip_namespace(child.tag)
        if list(child):
            row[f"{tag}_child_count"] = str(len(list(child)))
        elif child.text and child.text.strip():
            row[tag] = child.text.strip()
        for key, value in child.attrib.items():
            row[f"{tag}_attr_{_strip_namespace(key)}"] = value
    return row


def _strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _decode_text(content: bytes) -> str:
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return content.decode("latin-1", errors="replace")


def _infer_type(values: list[str]) -> str:
    non_empty = [value.strip() for value in values if value and value.strip()]
    if not non_empty:
        return "text"
    if all(_looks_int(value) for value in non_empty):
        return "integer"
    if all(_looks_float(value) for value in non_empty):
        return "numeric"
    if all(DATE_RE.match(value) for value in non_empty):
        return "date"
    if all(_looks_uuid(value) for value in non_empty):
        return "uuid"
    return "text"


def _looks_int(value: str) -> bool:
    return bool(re.fullmatch(r"[-+]?\d+", value))


def _looks_float(value: str) -> bool:
    return bool(re.fullmatch(r"[-+]?(?:\d+\.\d+|\d+)", value))


def _looks_uuid(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", value))


def _table_name_from_path(path: str) -> str:
    return _safe_identifier(PurePosixPath(path.replace("\\", "/")).stem or "uploaded_table")


def _safe_identifier(value: Any) -> str:
    text = str(value).strip().strip("\"`[]")
    text = re.sub(r"[^0-9A-Za-z_]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_").lower()
    if not text:
        return "unnamed"
    if text[0].isdigit():
        return f"col_{text}"
    return text[:96]


def _clean_column_name(value: str, index: int) -> str:
    cleaned = _safe_identifier(value)
    return cleaned if cleaned != "unnamed" else f"column_{index + 1}"


def _deduplicate_table_names(tables: list[ImportedTable]) -> list[ImportedTable]:
    counts: dict[str, int] = defaultdict(int)
    deduped = []
    for table in tables:
        counts[table.name] += 1
        if counts[table.name] > 1:
            table.name = f"{table.name}_{counts[table.name]}"
        deduped.append(table)
    return deduped


def _quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _take(iterable: Iterable[Any], limit: int) -> list[Any]:
    items = []
    for index, item in enumerate(iterable):
        if index >= limit:
            break
        items.append(item)
    return items


def _line_count(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)
