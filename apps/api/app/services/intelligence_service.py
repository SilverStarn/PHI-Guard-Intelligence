from __future__ import annotations

import sys
from collections import Counter, defaultdict
from functools import cached_property
from pathlib import Path
from typing import Any

try:
    from phi_guard_scanner.demo import build_demo_intelligence
    from phi_guard_scanner.importers import UploadedInput, build_uploaded_intelligence
except ModuleNotFoundError:
    scanner_path = Path(__file__).resolve().parents[3] / "scanner"
    sys.path.append(str(scanner_path))
    from phi_guard_scanner.demo import build_demo_intelligence
    from phi_guard_scanner.importers import UploadedInput, build_uploaded_intelligence

from apps.api.app.services.metadata_store import get_metadata_store


class IntelligenceService:
    def __init__(self) -> None:
        self._scan_payload: dict[str, Any] | None = None
        self.store = get_metadata_store()

    @property
    def scan_payload(self) -> dict[str, Any]:
        if self._scan_payload is None:
            self._scan_payload = self._demo_scan_payload
        return self._scan_payload

    @cached_property
    def _demo_scan_payload(self) -> dict[str, Any]:
        return build_demo_intelligence()

    def reset_demo(self) -> dict[str, object]:
        self._scan_payload = build_demo_intelligence()
        self._record_active_scan(source="demo", actor="local_user", event_type="demo_reset")
        return self.source_info()

    def analyze_upload(self, files: list[UploadedInput], project_name: str = "Uploaded Data Project") -> dict[str, object]:
        self._scan_payload = build_uploaded_intelligence(files, project_name=project_name)
        self._record_active_scan(
            source="browser_upload",
            actor="local_user",
            event_type="upload_scan_completed",
            metadata={"file_count": len(files), "raw_value_stored": False, "retention": "in_memory_only"},
        )
        return self.source_info()

    def ingest_agent_package(self, package: dict[str, Any], actor: str = "scanner_agent") -> dict[str, object]:
        scan_payload = package.get("sanitized_intelligence_graph")
        if not isinstance(scan_payload, dict) or not scan_payload.get("assets"):
            raise ValueError("Agent package must include sanitized_intelligence_graph with assets.")
        if _contains_raw_retention_marker(package):
            raise ValueError("Agent package contains a raw-retention marker set to true.")
        self._scan_payload = scan_payload
        source = package.get("source", {})
        metadata = {
            "agent": package.get("agent", {}),
            "source": source,
            "privacy": package.get("privacy", {}),
            "evidence_count": len(package.get("evidence", [])) if isinstance(package.get("evidence"), list) else 0,
        }
        self._record_active_scan(source="scanner_agent", actor=actor, event_type="agent_scan_ingested", metadata=metadata)
        return self.source_info()

    def scan_runs(self) -> dict[str, object]:
        return {"items": self.store.scan_runs()}

    def audit_events(self) -> dict[str, object]:
        return {"items": self.store.audit_events()}

    def source_info(self) -> dict[str, object]:
        database = next((asset for asset in self.scan_payload["assets"] if asset["asset_type"] == "database"), None)
        metadata = database.get("metadata", {}) if database else {}
        return {
            "mode": metadata.get("source_mode", "demo"),
            "workspace": self._workspace_name(),
            "scan_id": self.scan_payload["scan_id"],
            "generated_at": self.scan_payload["generated_at"],
            "parsed_files": metadata.get("parsed_files", []),
            "unsupported_files": metadata.get("unsupported_files", []),
            "warnings": metadata.get("warnings", []),
        }

    def summary(self) -> dict[str, object]:
        assets = self.scan_payload["assets"]
        findings = self.scan_payload["findings"]
        table_assets = [asset for asset in assets if asset["asset_type"] in {"table", "view", "export"}]
        phi_tables = [table for table in table_assets if self._table_has_phi(table["name"])]
        severity_counts = Counter(finding["severity"] for finding in findings)
        open_findings = [finding for finding in findings if finding["status"] == "open"]
        high_free_text = [
            asset
            for asset in assets
            if asset["asset_type"] == "column"
            and self._has_classification(asset, "FREE_TEXT_PHI_RISK")
            and (asset.get("risk_score", 0) >= 70 or self._table_risk(asset.get("table_name")) >= 70)
        ]
        external_destinations = [asset for asset in assets if asset["asset_type"] in {"external_destination", "ai_tool"}]
        deid = self.deidentification()["rows"]
        readiness_scores = [row["readiness_score"] for row in deid]
        readiness_score = round(sum(readiness_scores) / len(readiness_scores)) if readiness_scores else 0

        return {
            "workspace": self._workspace_name(),
            "scan_id": self.scan_payload["scan_id"],
            "generated_at": self.scan_payload["generated_at"],
            "risk_score": max((finding["risk_score"] for finding in findings), default=0),
            "critical_findings": severity_counts.get("critical", 0),
            "high_findings": severity_counts.get("high", 0),
            "open_findings": len(open_findings),
            "phi_assets": len(phi_tables),
            "free_text_fields": len(high_free_text),
            "external_destinations": len(external_destinations),
            "deidentification_readiness_score": readiness_score,
            "top_findings": findings[:5],
            "trend": [
                {"period": "Jan", "critical": 3, "high": 7, "resolved": 1},
                {"period": "Feb", "critical": 4, "high": 8, "resolved": 2},
                {"period": "Mar", "critical": 5, "high": 9, "resolved": 4},
                {"period": "Apr", "critical": 5, "high": 11, "resolved": 6},
                {"period": "May", "critical": severity_counts.get("critical", 0), "high": severity_counts.get("high", 0), "resolved": 8},
            ],
        }

    def graph(self) -> dict[str, object]:
        assets = self.scan_payload["assets"]
        edges = self.scan_payload["edges"]
        finding_asset_ids = {finding["asset_id"] for finding in self.scan_payload["findings"]}
        lineage_column_ids = {
            asset_id
            for edge in edges
            if edge["edge_type"] != "CONTAINS"
            for asset_id in (edge["source_asset_id"], edge["target_asset_id"])
            if asset_id.startswith("column:")
        }
        relevant_types = {
            "database",
            "schema",
            "table",
            "column",
            "view",
            "export",
            "role",
            "external_destination",
            "ai_tool",
            "finding",
            "control",
        }

        def include_asset(asset: dict[str, Any]) -> bool:
            asset_type = asset["asset_type"]
            if asset_type not in relevant_types:
                return False
            if asset_type != "column":
                return True
            return bool(
                asset.get("classifications")
                or asset.get("risk_score", 0) >= 40
                or asset["id"] in finding_asset_ids
                or asset["id"] in lineage_column_ids
            )

        nodes = [
            {
                "id": asset["id"],
                "label": asset["name"],
                "type": asset["asset_type"],
                "riskScore": asset.get("risk_score", 0),
                "rowCount": asset.get("row_count_estimate"),
                "description": asset.get("description", ""),
                "classifications": [item["label"] for item in asset.get("classifications", [])],
            }
            for asset in assets
            if include_asset(asset)
        ]
        node_ids = {node["id"] for node in nodes}
        graph_edges = [
            {
                "id": edge["id"],
                "source": edge["source_asset_id"],
                "target": edge["target_asset_id"],
                "type": edge["edge_type"],
                "label": edge.get("label", edge["edge_type"]),
                "confidence": edge.get("confidence", 1.0),
            }
            for edge in edges
            if edge["source_asset_id"] in node_ids and edge["target_asset_id"] in node_ids
        ]
        return {"nodes": nodes, "edges": graph_edges}

    def findings(self) -> dict[str, object]:
        return {
            "items": [
                {
                    "id": finding["id"],
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "status": finding["status"],
                    "risk_score": finding["risk_score"],
                    "confidence": finding["confidence"],
                    "asset_id": finding["asset_id"],
                    "description": finding["description"],
                    "control_mapping": finding["control_mapping"],
                    "remediation_summary": finding["remediation_summary"],
                }
                for finding in self.scan_payload["findings"]
            ]
        }

    def finding_detail(self, finding_id: str) -> dict[str, object] | None:
        return next((finding for finding in self.scan_payload["findings"] if finding["id"] == finding_id), None)

    def deidentification(self) -> dict[str, object]:
        rows = []
        assets = self.scan_payload["assets"]
        table_assets = [asset for asset in assets if asset["asset_type"] in {"table", "view", "export"}]
        columns_by_table: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for asset in assets:
            if asset["asset_type"] == "column" and asset.get("table_name"):
                columns_by_table[asset["table_name"]].append(asset)

        for table in table_assets:
            columns = columns_by_table[table["name"]]
            blocker_map = {
                "name": self._merge_column_names(
                    self._column_names(columns, {"first_name", "last_name", "full_name", "name"}),
                    self._classified_column_names(columns, "DIRECT_IDENTIFIER", "name"),
                ),
                "dob": self._merge_column_names(
                    self._column_names(columns, {"dob", "date_of_birth", "birth_date"}),
                    self._classified_column_names(columns, "QUASI_IDENTIFIER", "dob"),
                ),
                "geography": self._merge_column_names(
                    self._column_names(columns, {"address", "street_address", "city", "state"}),
                    self._classified_column_names(columns, "QUASI_IDENTIFIER", "geography"),
                    self._classified_column_names(columns, "QUASI_IDENTIFIER", "street_address"),
                    self._classified_column_names(columns, "QUASI_IDENTIFIER", "address_term"),
                ),
                "zip": self._merge_column_names(
                    self._column_names(columns, {"zip", "zipcode", "postal_code"}),
                    self._classified_column_names(columns, "QUASI_IDENTIFIER", "zip"),
                ),
                "phone": self._merge_column_names(
                    self._column_names(columns, {"phone", "phone_number", "mobile_phone"}),
                    self._classified_column_names(columns, "DIRECT_IDENTIFIER", "phone"),
                ),
                "email": self._merge_column_names(
                    self._column_names(columns, {"email", "email_address"}),
                    self._classified_column_names(columns, "DIRECT_IDENTIFIER", "email"),
                ),
                "mrn": self._merge_column_names(
                    self._column_names(columns, {"mrn", "medical_record_number"}),
                    self._classified_column_names(columns, "DIRECT_IDENTIFIER", "mrn"),
                ),
                "ssn": self._merge_column_names(
                    self._column_names(columns, {"ssn", "social_security_number"}),
                    self._classified_column_names(columns, "DIRECT_IDENTIFIER", "ssn"),
                ),
                "ip": self._classified_column_names(columns, "QUASI_IDENTIFIER", "ip"),
                "free_text": self._classified_column_names(columns, "FREE_TEXT_PHI_RISK"),
            }
            blocker_count = sum(1 for value in blocker_map.values() if value)
            if blocker_count >= 3:
                status = "Not ready"
            elif blocker_count >= 1:
                status = "Review"
            else:
                status = "Likely ready"
            readiness_score = max(0, 100 - blocker_count * 13 - (18 if table["name"].startswith("marketing") else 0))
            rows.append(
                {
                    "table": table["name"],
                    "row_count_estimate": table.get("row_count_estimate", 0),
                    "blockers": blocker_map,
                    "status": status,
                    "readiness_score": readiness_score,
                }
            )
        rows.sort(key=lambda row: (row["readiness_score"], row["table"]))
        return {"rows": rows}

    def access_matrix(self) -> dict[str, object]:
        grants = self.scan_payload["access_grants"]
        assets_by_id = {asset["id"]: asset for asset in self.scan_payload["assets"]}
        phi_asset_ids = {
            asset["id"]
            for asset in self.scan_payload["assets"]
            if asset["asset_type"] in {"table", "view", "export"} and self._table_has_phi(asset["name"])
        }
        principals = sorted({grant["principal_name"] for grant in grants})
        columns = [
            {"id": asset_id, "name": assets_by_id[asset_id]["name"], "risk_score": assets_by_id[asset_id].get("risk_score", 0)}
            for asset_id in sorted(phi_asset_ids, key=lambda item: assets_by_id[item]["name"])
        ]
        cells = []
        for principal in principals:
            for column in columns:
                matching = [grant for grant in grants if grant["principal_name"] == principal and grant["asset_id"] == column["id"]]
                if matching:
                    permission = "/".join(sorted({grant["permission"] for grant in matching}))
                    cells.append(
                        {
                            "principal": principal,
                            "asset_id": column["id"],
                            "permission": permission,
                            "risk": "high" if column["risk_score"] >= 70 else "moderate",
                        }
                    )
        risky_combinations = [
            {
                "principal": principal,
                "reason": "Can access both identifiers and clinical/payment context",
            }
            for principal in principals
            if self._principal_has_combined_phi(principal)
            ]
        return {"principals": principals, "assets": columns, "cells": cells, "risky_combinations": risky_combinations}

    def remediations(self) -> dict[str, object]:
        tasks = []
        for index, finding in enumerate(self.scan_payload["findings"], start=1):
            owner = self._owner_for_controls(finding["control_mapping"])
            effort = self._effort_for_finding(finding)
            due_window = "7 days" if finding["severity"] == "critical" else "14 days" if finding["severity"] == "high" else "30 days"
            tasks.append(
                {
                    "id": f"task:{index:03d}",
                    "finding_id": finding["id"],
                    "title": self._task_title(finding),
                    "status": "open",
                    "owner": owner,
                    "severity": finding["severity"],
                    "risk_score": finding["risk_score"],
                    "asset_id": finding["asset_id"],
                    "effort": effort,
                    "due_window": due_window,
                    "control_mapping": finding["control_mapping"],
                    "recommended_steps": finding["recommended_steps"],
                    "human_review": finding["human_review"],
                    "risk_reduction": min(45, max(12, finding["risk_score"] - 38)),
                }
            )

        by_owner = Counter(task["owner"] for task in tasks)
        by_status = Counter(task["status"] for task in tasks)
        priority_queue = tasks[:8]
        return {
            "summary": {
                "total": len(tasks),
                "critical": sum(1 for task in tasks if task["severity"] == "critical"),
                "high": sum(1 for task in tasks if task["severity"] == "high"),
                "estimated_risk_reduction": sum(task["risk_reduction"] for task in priority_queue),
                "by_owner": dict(sorted(by_owner.items())),
                "by_status": dict(sorted(by_status.items())),
            },
            "items": tasks,
        }

    def report(self) -> dict[str, object]:
        summary = self.summary()
        findings = self.scan_payload["findings"]
        mode = self.source_info()["mode"]
        message = (
            "Uploaded project scan found potential PHI risk patterns. Raw uploaded content was parsed in memory and the report stores sanitized metadata only."
            if mode == "upload"
            else "Synthetic demo scan found concentrated PHI, broad role access, de-identification blockers, free-text risk, and AI workflow exposure."
        )
        return {
            "title": f"{self._workspace_name()} PHI Risk Intelligence Report",
            "generated_at": self.scan_payload["generated_at"],
            "executive_summary": {
                "risk_score": summary["risk_score"],
                "critical_findings": summary["critical_findings"],
                "high_findings": summary["high_findings"],
                "phi_assets": summary["phi_assets"],
                "message": message,
            },
            "technical_findings": findings[:10],
            "limitations": [
                "Uploaded raw content is not persisted by the scanner result model." if mode == "upload" else "Synthetic demo data only.",
                "Potential risk findings require human review.",
                "No legal or compliance certification is provided.",
                "Finding evidence stores masked metadata and raw_value_stored=false.",
            ],
        }

    def _table_has_phi(self, table_name: str | None) -> bool:
        if not table_name:
            return False
        labels = set()
        for asset in self.scan_payload["assets"]:
            if asset["asset_type"] == "column" and asset.get("table_name") == table_name:
                labels.update(item["label"] for item in asset.get("classifications", []))
        return bool(
            labels
            & {
                "DIRECT_IDENTIFIER",
                "QUASI_IDENTIFIER",
                "HEALTH_CONTEXT",
                "PAYMENT_CONTEXT",
                "FREE_TEXT_PHI_RISK",
                "AI_EXPOSURE_RISK",
            }
        )

    def _table_risk(self, table_name: str | None) -> int:
        if not table_name:
            return 0
        table = next((asset for asset in self.scan_payload["assets"] if asset["asset_type"] == "table" and asset["name"] == table_name), None)
        return table.get("risk_score", 0) if table else 0

    @staticmethod
    def _has_classification(asset: dict[str, Any], label: str) -> bool:
        return any(item["label"] == label for item in asset.get("classifications", []))

    @staticmethod
    def _column_names(columns: list[dict[str, Any]], names: set[str]) -> list[str]:
        return sorted(column["column_name"] for column in columns if column.get("column_name") in names)

    @staticmethod
    def _merge_column_names(*groups: list[str]) -> list[str]:
        return sorted({name for group in groups for name in group})

    @staticmethod
    def _classified_column_names(columns: list[dict[str, Any]], label: str, value_pattern: str | None = None) -> list[str]:
        matched = []
        for column in columns:
            for classification in column.get("classifications", []):
                if classification["label"] != label:
                    continue
                patterns = classification.get("details", {}).get("value_patterns", [])
                if value_pattern and value_pattern not in patterns:
                    continue
                matched.append(column["column_name"])
        return sorted(set(matched))

    def _principal_has_combined_phi(self, principal: str) -> bool:
        grants = [grant for grant in self.scan_payload["access_grants"] if grant["principal_name"] == principal]
        labels = set()
        for grant in grants:
            asset = next((item for item in self.scan_payload["assets"] if item["id"] == grant["asset_id"]), None)
            if not asset or asset["asset_type"] not in {"table", "view", "export"}:
                continue
            table_name = asset["name"]
            for column in self.scan_payload["assets"]:
                if column["asset_type"] == "column" and column.get("table_name") == table_name:
                    labels.update(item["label"] for item in column.get("classifications", []))
        return "DIRECT_IDENTIFIER" in labels and bool(labels & {"HEALTH_CONTEXT", "PAYMENT_CONTEXT", "FREE_TEXT_PHI_RISK"})

    def _workspace_name(self) -> str:
        database = next((asset for asset in self.scan_payload["assets"] if asset["asset_type"] == "database"), None)
        if database and database.get("name"):
            return str(database["name"])
        return "PHI Guard Intelligence Workspace"

    def _record_active_scan(
        self,
        *,
        source: str,
        actor: str,
        event_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.store.record_scan(
            source=source,
            scan_id=str(self.scan_payload["scan_id"]),
            workspace=self._workspace_name(),
            payload=self.scan_payload,
        )
        self.store.audit(
            event_type=event_type,
            actor=actor,
            workspace=self._workspace_name(),
            metadata=metadata or {"raw_value_stored": False},
        )

    @staticmethod
    def _owner_for_controls(controls: list[str]) -> str:
        normalized = [control.casefold() for control in controls]
        if any("ai governance" in control for control in normalized):
            return "ai-platform"
        if any("audit controls" in control for control in normalized):
            return "security-logging"
        if any("access control" in control or "unique user identification" in control for control in normalized):
            return "security-engineering"
        if any("de-identification" in control or "minimum necessary" in control for control in normalized):
            return "data-governance"
        return "privacy-office"

    @staticmethod
    def _effort_for_finding(finding: dict[str, Any]) -> str:
        score = finding["risk_score"]
        steps = len(finding.get("recommended_steps", []))
        if score >= 85 or steps >= 4:
            return "M"
        if score >= 70:
            return "S"
        return "XS"

    @staticmethod
    def _task_title(finding: dict[str, Any]) -> str:
        summary = finding.get("remediation_summary", "")
        if summary:
            return summary.rstrip(".")
        return f"Remediate {finding['title']}"


def _contains_raw_retention_marker(value: Any) -> bool:
    raw_marker_keys = {"raw_value_stored", "raw_file_uploaded", "llm_receives_raw_phi"}
    if isinstance(value, dict):
        if any(value.get(key) is True for key in raw_marker_keys):
            return True
        return any(_contains_raw_retention_marker(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_raw_retention_marker(item) for item in value)
    return False
