from phi_guard_scanner.demo import build_demo_intelligence


def test_demo_generates_risk_findings() -> None:
    scan_payload = build_demo_intelligence()

    assert len(scan_payload["findings"]) >= 20
    assert any(finding["severity"] == "critical" for finding in scan_payload["findings"])
    assert any("AI workflow" in finding["title"] for finding in scan_payload["findings"])
    assert any("De-identification readiness blockers" in finding["title"] for finding in scan_payload["findings"])


def test_demo_evidence_never_stores_raw_values() -> None:
    scan_payload = build_demo_intelligence()

    evidence_items = [
        evidence
        for finding in scan_payload["findings"]
        for evidence in finding["evidence"]
    ]

    assert evidence_items
    assert all(evidence["raw_value_stored"] is False for evidence in evidence_items)


def test_graph_contains_core_assets() -> None:
    scan_payload = build_demo_intelligence()
    asset_ids = {asset["id"] for asset in scan_payload["assets"]}

    assert "table:patients" in asset_ids
    assert "table:marketing_campaign_exports" in asset_ids
    assert "ai_tool:internal_llm_gateway" in asset_ids
    assert "control:access-control" in asset_ids

