from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from apps.api.app.main import create_app
from phi_guard_scanner.agent.contracts import ScanMode, SourceType
from phi_guard_scanner.agent.runner import scan_local_path


client = TestClient(create_app())


@pytest.fixture(autouse=True)
def reset_demo_scan() -> None:
    client.post("/api/demo/reset")


def test_core_api_routes_return_consistent_payloads() -> None:
    summary = client.get("/api/summary")
    source = client.get("/api/source")
    graph = client.get("/api/graph")
    findings = client.get("/api/findings")
    deidentification = client.get("/api/deidentification")
    access_matrix = client.get("/api/access-matrix")
    remediations = client.get("/api/remediations")
    report = client.get("/api/report")

    assert summary.status_code == 200
    assert source.status_code == 200
    assert graph.status_code == 200
    assert findings.status_code == 200
    assert deidentification.status_code == 200
    assert access_matrix.status_code == 200
    assert remediations.status_code == 200
    assert report.status_code == 200

    findings_payload = findings.json()
    remediation_payload = remediations.json()
    assert summary.json()["open_findings"] == len(findings_payload["items"])
    assert remediation_payload["summary"]["total"] == len(findings_payload["items"])
    assert graph.json()["nodes"]
    assert graph.json()["edges"]
    assert deidentification.json()["rows"]
    assert access_matrix.json()["risky_combinations"]
    assert source.json()["mode"] == "demo"


def test_finding_detail_accepts_encoded_finding_ids() -> None:
    findings = client.get("/api/findings").json()["items"]
    finding_id = findings[0]["id"]

    detail = client.get(f"/api/findings/{quote(finding_id, safe='')}")

    assert detail.status_code == 200
    assert detail.json()["id"] == finding_id
    assert detail.json()["evidence"]


def test_remediations_are_prioritized_by_risk() -> None:
    payload = client.get("/api/remediations").json()
    scores = [task["risk_score"] for task in payload["items"]]

    assert scores == sorted(scores, reverse=True)
    assert payload["items"][0]["severity"] == "critical"
    assert payload["items"][0]["due_window"] == "7 days"
    assert payload["summary"]["estimated_risk_reduction"] > 0


def test_report_does_not_include_raw_evidence_values() -> None:
    report = client.get("/api/report").json()
    evidence_items = [
        evidence
        for finding in report["technical_findings"]
        for evidence in finding["evidence"]
    ]

    assert evidence_items
    assert all(evidence["raw_value_stored"] is False for evidence in evidence_items)


def test_upload_endpoint_replaces_active_scan_with_sanitized_results() -> None:
    content = (
        "patient_id,email,diagnosis_code,notes\n"
        "1,alex.rivera@example.test,E11.9,Call 555-214-0198 after visit\n"
        "2,jordan.lee@example.test,I10,Follow-up on 2026-01-10\n"
    )

    response = client.post(
        "/api/uploads/analyze",
        data={"project_name": "Mock Upload Clinic"},
        files=[("files", ("patients.csv", content, "text/csv"))],
    )

    assert response.status_code == 200
    assert response.json()["mode"] == "upload"
    assert response.json()["workspace"] == "Mock Upload Clinic"

    summary = client.get("/api/summary").json()
    findings = client.get("/api/findings").json()
    graph = client.get("/api/graph").json()
    deidentification = client.get("/api/deidentification").json()
    source = client.get("/api/source").json()

    assert summary["workspace"] == "Mock Upload Clinic"
    assert summary["open_findings"] == len(findings["items"])
    assert source["parsed_files"] == ["patients.csv"]
    assert any(node["type"] == "column" and "FREE_TEXT_PHI_RISK" in node["classifications"] for node in graph["nodes"])
    patient_row = next(row for row in deidentification["rows"] if row["table"] == "patients")
    assert "notes" in patient_row["blockers"]["phone"]


def test_upload_endpoint_marks_geography_and_sensitive_mental_health_context() -> None:
    content = (
        "Record_ID,System_Node,Log_Message\n"
        "1,app_node_1,Routine heartbeat\n"
        '2,app_node_2,"Patient Jane Q. Public DOB: 05/12/1985 Diagnosis: Schizophrenia address 123 Maple St, Appleton, WI phone 920-555-0199"\n'
    )

    response = client.post(
        "/api/uploads/analyze",
        data={"project_name": "Sensitive Log Upload"},
        files=[("files", ("logs.csv", content, "text/csv"))],
    )

    assert response.status_code == 200

    findings = client.get("/api/findings").json()["items"]
    deidentification = client.get("/api/deidentification").json()["rows"]
    log_row = next(row for row in deidentification if row["table"] == "logs")

    assert any("Sensitive mental-health context linked to identifiers" in finding["title"] for finding in findings)
    assert "log_message" in log_row["blockers"]["name"]
    assert "log_message" in log_row["blockers"]["geography"]


def test_upload_policy_and_intent_describe_secure_mock_pipeline() -> None:
    policy = client.get("/api/uploads/policy")
    intent = client.post("/api/uploads/intents", json={"file_name": "mock.csv"})

    assert policy.status_code == 200
    assert intent.status_code == 200
    assert policy.json()["mode"] == "mock_non_phi_only"
    assert "malware scan before parser worker" in policy.json()["production_required_controls"]
    assert intent.json()["upload_url"] == "/api/uploads/analyze"


def test_agent_scan_endpoint_ingests_sanitized_package(tmp_path) -> None:
    log_file = tmp_path / "events.log"
    log_file.write_text("MRN #8472910 email j.doe@gmail.com Diagnosis: Schizophrenia\n", encoding="utf-8")
    package = scan_local_path(
        path=tmp_path,
        mode=ScanMode.MASKED_SAMPLE,
        project_name="Agent Upload",
        agent_id="agent-test",
        source_type=SourceType.LOGS,
    )

    unauthorized = client.post("/api/agent/scans", json=package)
    response = client.post("/api/agent/scans", json=package, headers={"Authorization": "Bearer dev-agent-token"})

    assert unauthorized.status_code == 401
    assert response.status_code == 200
    assert response.json()["workspace"] == "Agent Upload"

    summary = client.get("/api/summary").json()
    audit_events = client.get("/api/audit-events").json()["items"]
    scan_runs = client.get("/api/scan-runs").json()["items"]

    assert summary["risk_score"] >= 85
    assert any(event["event_type"] == "agent_scan_ingested" for event in audit_events)
    assert any(scan["scan_id"] == package["sanitized_intelligence_graph"]["scan_id"] for scan in scan_runs)


def test_agent_scan_endpoint_rejects_raw_retention_markers(tmp_path) -> None:
    log_file = tmp_path / "events.log"
    log_file.write_text("MRN #8472910 email j.doe@gmail.com Diagnosis: Schizophrenia\n", encoding="utf-8")
    package = scan_local_path(
        path=tmp_path,
        mode=ScanMode.MASKED_SAMPLE,
        project_name="Unsafe Agent Upload",
        agent_id="agent-test",
        source_type=SourceType.LOGS,
    )
    package["evidence"][0]["raw_value_stored"] = True

    response = client.post("/api/agent/scans", json=package, headers={"Authorization": "Bearer dev-agent-token"})

    assert response.status_code == 400
    assert "raw-retention marker" in response.json()["detail"]
