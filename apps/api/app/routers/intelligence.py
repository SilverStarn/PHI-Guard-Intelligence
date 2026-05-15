from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, Body, File, Form, Header, HTTPException, UploadFile

from apps.api.app.services.intelligence_service import IntelligenceService
from phi_guard_scanner.importers import MAX_UPLOAD_BYTES, SUPPORTED_EXTENSIONS, UploadedInput


router = APIRouter()
service = IntelligenceService()


@router.get("/summary")
def summary() -> dict[str, object]:
    return service.summary()


@router.get("/source")
def source_info() -> dict[str, object]:
    return service.source_info()


@router.post("/demo/reset")
def reset_demo() -> dict[str, object]:
    return service.reset_demo()


@router.post("/uploads/analyze")
async def analyze_upload(
    files: list[UploadFile] = File(...),
    project_name: str = Form("Uploaded Data Project"),
) -> dict[str, object]:
    if not files:
        raise HTTPException(status_code=400, detail="At least one file is required.")

    uploaded_inputs: list[UploadedInput] = []
    for file in files:
        content = await file.read()
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail=f"{file.filename} exceeds the upload size limit.")
        _validate_mock_upload_name(file.filename or "uploaded-file")
        uploaded_inputs.append(UploadedInput(filename=file.filename or "uploaded-file", content=content))

    source = service.analyze_upload(uploaded_inputs, project_name=project_name)
    if not service.scan_payload["assets"]:
        raise HTTPException(status_code=400, detail="No analyzable assets were found.")
    return source


@router.get("/uploads/policy")
def upload_policy() -> dict[str, object]:
    return {
        "mode": "mock_non_phi_only",
        "max_file_bytes": MAX_UPLOAD_BYTES,
        "supported_extensions": sorted(SUPPORTED_EXTENSIONS),
        "raw_retention": "in_memory_until_parse_completes",
        "controls": [
            "file type validation",
            "bounded parser size limits",
            "zip member size limits",
            "sanitized metadata result",
            "raw_value_stored=false evidence contract",
            "no LLM calls with raw uploaded content",
        ],
        "production_required_controls": [
            "pre-signed encrypted object storage URL",
            "malware scan before parser worker",
            "isolated parser worker",
            "per-client KMS key",
            "automatic raw-file deletion within minutes",
            "immutable upload/scan/view/export/delete audit events",
        ],
    }


@router.post("/uploads/intents")
def create_upload_intent(payload: dict[str, object] = Body(default_factory=dict)) -> dict[str, object]:
    file_name = str(payload.get("file_name") or "upload")
    _validate_mock_upload_name(file_name)
    expires_at = datetime.now(UTC) + timedelta(minutes=10)
    return {
        "upload_intent_id": f"upload_intent:{uuid4()}",
        "mode": "local_mock_direct_analyze",
        "upload_url": "/api/uploads/analyze",
        "expires_at": expires_at.isoformat(),
        "encryption": "required_in_production",
        "malware_scan": "required_in_production",
        "raw_retention": "in_memory_until_parse_completes",
    }


@router.post("/agent/scans")
def ingest_agent_scan(
    package: dict[str, object] = Body(...),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    actor = _require_agent_token(authorization)
    try:
        return service.ingest_agent_package(package, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/scan-runs")
def scan_runs() -> dict[str, object]:
    return service.scan_runs()


@router.get("/audit-events")
def audit_events() -> dict[str, object]:
    return service.audit_events()


@router.get("/graph")
def graph() -> dict[str, object]:
    return service.graph()


@router.get("/findings")
def findings() -> dict[str, object]:
    return service.findings()


@router.get("/findings/{finding_id}")
def finding_detail(finding_id: str) -> dict[str, object]:
    finding = service.finding_detail(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("/deidentification")
def deidentification() -> dict[str, object]:
    return service.deidentification()


@router.get("/access-matrix")
def access_matrix() -> dict[str, object]:
    return service.access_matrix()


@router.get("/remediations")
def remediations() -> dict[str, object]:
    return service.remediations()


@router.get("/report")
def report() -> dict[str, object]:
    return service.report()


def _require_agent_token(authorization: str | None) -> str:
    expected = os.getenv("PHI_GUARD_AGENT_TOKEN", "dev-agent-token")
    if authorization != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="Valid scanner agent token is required.")
    return "scanner_agent"


def _validate_mock_upload_name(filename: str) -> None:
    suffix = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if suffix not in SUPPORTED_EXTENSIONS:
        raise HTTPException(status_code=415, detail=f"Unsupported upload type: {suffix or 'none'}.")
