from __future__ import annotations

import json

from phi_guard_scanner.agent.contracts import ScanMode, SourceType
from phi_guard_scanner.agent.runner import scan_local_path


def test_local_agent_emits_sanitized_evidence_package(tmp_path) -> None:
    log_file = tmp_path / "app.log"
    log_file.write_text(
        "Patient Jane Q. Public DOB: 05/12/1985 Diagnosis: Schizophrenia MRN #8472910 email j.doe@gmail.com\n",
        encoding="utf-8",
    )

    package = scan_local_path(
        path=tmp_path,
        mode=ScanMode.MASKED_SAMPLE,
        project_name="Agent Log Scan",
        agent_id="test-agent",
        source_type=SourceType.LOGS,
    )

    assert package["privacy"]["raw_value_stored"] is False
    assert package["privacy"]["classification_location"] == "local_agent"
    assert package["source"]["source_type"] == "logs"
    assert package["sanitized_intelligence_graph"]["findings"]
    assert any(item["label"] == "DIRECT_IDENTIFIER" for item in package["evidence"])
    assert all(item["raw_value_stored"] is False for item in package["evidence"])
    assert all("Jane Q. Public" not in json.dumps(item) for item in package["evidence"])


def test_local_agent_parses_fhir_and_dbt_exports(tmp_path) -> None:
    (tmp_path / "bundle.json").write_text(
        json.dumps(
            {
                "resourceType": "Bundle",
                "entry": [
                    {"resource": {"resourceType": "Patient", "id": "p1", "name": [{"family": "Public"}]}},
                    {"resource": {"resourceType": "Condition", "id": "c1", "code": {"text": "diabetes"}}},
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "metadata": {"dbt_schema_version": "https://schemas.getdbt.com/dbt/manifest/v12.json"},
                "nodes": {
                    "model.project.patient_export": {
                        "resource_type": "model",
                        "name": "patient_export",
                        "columns": {
                            "email": {"data_type": "text"},
                            "diagnosis_code": {"data_type": "text"},
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    package = scan_local_path(
        path=tmp_path,
        mode=ScanMode.METADATA_ONLY,
        project_name="Export Scan",
        agent_id="test-agent",
    )
    asset_names = {asset["name"] for asset in package["sanitized_intelligence_graph"]["assets"]}

    assert "patient" in asset_names
    assert "condition" in asset_names
    assert "patient_export" in asset_names
