from __future__ import annotations

import io
import json
import os
import sqlite3
import tempfile
import zipfile

from phi_guard_scanner.importers import UploadedInput, build_uploaded_intelligence, import_uploaded_project


def test_csv_upload_generates_phi_findings_without_raw_evidence() -> None:
    scan_payload = build_uploaded_intelligence(
        [
            UploadedInput(
                filename="patients.csv",
                content=(
                    "patient_id,email,diagnosis_code,notes\n"
                    "1,alex.rivera@example.test,E11.9,Call 555-214-0198\n"
                ).encode(),
            )
        ],
        project_name="CSV Clinic",
    )

    assert scan_payload["findings"]
    assert scan_payload["assets"][0]["name"] == "CSV Clinic"
    assert any("patients" in finding["title"] for finding in scan_payload["findings"])
    assert all(
        evidence["raw_value_stored"] is False
        for finding in scan_payload["findings"]
        for evidence in finding["evidence"]
    )


def test_delimited_upload_finds_late_embedded_phi_in_log_text() -> None:
    safe_rows = [
        f"{index},app_node_{index % 3},52,{15000 + index},200,OK,Heartbeat check completed"
        for index in range(150)
    ]
    risky_row = (
        '151,app_node_2,82,19000,503,WARN,"'
        "Failed claim export for Patient John Q. Public DOB: 04/12/1978 MRN: ZX-44991 SSN 123-45-6789 "
        'phone 555-214-0198 email casey@example.test Diagnosis: Schizophrenia address 123 Maple St, Appleton, WI"'
    )
    content = (
        "Record_ID,System_Node,CPU_Usage_Pct,Memory_Usage_MB,Network_Latency_ms,Status_Code,Log_Message\n"
        + "\n".join([*safe_rows, risky_row])
    )

    scan_payload = build_uploaded_intelligence(
        [UploadedInput(filename="hipaa_stress_test_data.csv", content=content.encode())],
        project_name="Stress Upload",
    )

    log_column = next(asset for asset in scan_payload["assets"] if asset["id"] == "column:hipaa_stress_test_data.log_message")
    memory_column = next(asset for asset in scan_payload["assets"] if asset["id"] == "column:hipaa_stress_test_data.memory_usage_mb")
    log_labels = {classification["label"] for classification in log_column["classifications"]}
    log_patterns = {
        pattern
        for classification in log_column["classifications"]
        for pattern in classification.get("details", {}).get("value_patterns", [])
    }
    memory_labels = {classification["label"] for classification in memory_column["classifications"]}

    assert {"DIRECT_IDENTIFIER", "HEALTH_CONTEXT", "FREE_TEXT_PHI_RISK"}.issubset(log_labels)
    assert {"name", "street_address", "geography", "mental_health_term"}.issubset(log_patterns)
    assert "QUASI_IDENTIFIER" not in memory_labels
    assert any("Embedded PHI patterns in free-text field" in finding["title"] for finding in scan_payload["findings"])
    assert any("Sensitive mental-health context linked to identifiers" in finding["title"] for finding in scan_payload["findings"])
    assert max(finding["risk_score"] for finding in scan_payload["findings"]) >= 85


def test_json_upload_profiles_beyond_first_hundred_records() -> None:
    rows = [{"record_id": index, "log_message": "Routine service heartbeat"} for index in range(130)]
    rows.append(
        {
            "record_id": 131,
            "log_message": "Patient DOB: 1978-04-12 MRN: ZX-44991 email casey@example.test diagnosis I10",
        }
    )

    scan_payload = build_uploaded_intelligence(
        [UploadedInput(filename="events.json", content=json.dumps(rows).encode())],
        project_name="JSON Stress Upload",
    )
    log_column = next(asset for asset in scan_payload["assets"] if asset["id"] == "column:events.log_message")
    labels = {classification["label"] for classification in log_column["classifications"]}

    assert {"DIRECT_IDENTIFIER", "HEALTH_CONTEXT", "FREE_TEXT_PHI_RISK"}.issubset(labels)
    assert any("Embedded PHI patterns in free-text field" in finding["title"] for finding in scan_payload["findings"])


def test_zip_project_parses_nested_supported_files_and_reports_unsupported() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("exports/campaign_export.csv", "email,diagnosis_category\ncasey@example.test,asthma\n")
        archive.writestr("notes/readme.md", "not scanned")

    result = import_uploaded_project([UploadedInput(filename="project.zip", content=buffer.getvalue())])

    assert [table.name for table in result.tables] == ["campaign_export"]
    assert "project.zip/notes/readme.md" in result.unsupported_files


def test_sqlite_upload_preserves_foreign_key_relationships() -> None:
    content = _sqlite_bytes()

    result = import_uploaded_project([UploadedInput(filename="clinic.sqlite", content=content)])
    relationships = [relationship for table in result.tables for relationship in table.relationships]

    assert {table.name for table in result.tables} == {"patients", "encounters"}
    assert any(relationship.source_table == "encounters" and relationship.target_table == "patients" for relationship in relationships)


def test_json_and_xml_uploads_are_normalized_to_tables() -> None:
    result = import_uploaded_project(
        [
            UploadedInput(
                filename="bundle.json",
                content=b'{"patients":[{"id":"1","email":"alex@example.test","diagnosis_code":"E11.9"}]}',
            ),
            UploadedInput(
                filename="patients.xml",
                content=(
                    b"<patients>"
                    b"<patient><email>a@example.test</email><diagnosis_code>I10</diagnosis_code></patient>"
                    b"<patient><email>b@example.test</email><diagnosis_code>E11.9</diagnosis_code></patient>"
                    b"</patients>"
                ),
            ),
        ]
    )

    assert {"patients", "patient"}.issubset({table.name for table in result.tables})


def _sqlite_bytes() -> bytes:
    handle = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    path = handle.name
    handle.close()
    try:
        connection = sqlite3.connect(path)
        connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE patients (
                id INTEGER PRIMARY KEY,
                email TEXT,
                ssn TEXT
            );
            CREATE TABLE encounters (
                id INTEGER PRIMARY KEY,
                patient_id INTEGER REFERENCES patients(id),
                diagnosis_code TEXT,
                notes TEXT
            );
            INSERT INTO patients VALUES (1, 'alex.rivera@example.test', '123-45-6789');
            INSERT INTO encounters VALUES (1, 1, 'E11.9', 'Call 555-214-0198');
            """
        )
        connection.close()
        with open(path, "rb") as sqlite_file:
            return sqlite_file.read()
    finally:
        os.unlink(path)
