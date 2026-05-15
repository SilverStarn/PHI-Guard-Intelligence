# PHI Guard Intelligence

PHI Guard Intelligence is a HIPAA-oriented healthcare data risk intelligence platform. It discovers where sensitive healthcare data lives, maps how it moves through database tables and downstream systems, explains potential privacy and security risks, and generates practical remediation guidance.

The public demo uses synthetic Northstar Family Clinic data.

![PHI Guard Intelligence console preview](docs/assets/console-preview.svg)

## For Buyers And Evaluators

Start here if you are reviewing this project from a healthcare, IT, security, privacy, or regulatory point of view:

- [Sales One-Pager](docs/sales-one-pager.md)
- [Market Positioning](docs/market-positioning.md)
- [Technical Brief](docs/technical-brief.md)
- [Buyer Presentation Deck](presentations/phi-guard-intelligence-buyer-deck.md)
- [Standalone HTML Presentation](presentations/phi-guard-intelligence-buyer-deck.html)

## What This MVP Demonstrates

- Metadata-first PHI/ePHI discovery without storing raw PHI.
- Flexible local import for CSV, TSV, JSON, JSONL, XML, SQLite, SQL DDL, log/text, and ZIP project uploads.
- Local scanner agent CLI that emits sanitized metadata packages before API submission.
- Secure upload policy/intent endpoints for mock-data mode and production upload planning.
- Persistent metadata-store schema for organizations, workspaces, scan runs, scanner agents, audit events, retention, assets, findings, and evidence.
- Column classification for direct identifiers, quasi-identifiers, health/payment context, free-text PHI risk, linkable keys, and de-identification blockers.
- Rule-based findings with evidence, risk score, confidence, blast radius, control mapping, remediation, and human-review caveats.
- Interactive data-risk graph for tables, columns, exports, roles, AI/log destinations, findings, and controls.
- De-identification readiness heatmap based on Safe Harbor-style identifier categories.
- Access matrix showing role exposure across sensitive assets.
- Remediation backlog that turns findings into owner, effort, due-window, and risk-reduction tasks.
- FastAPI backend, React/TypeScript frontend, Python scanner package, synthetic SQL dataset, CI, and deployment scaffolding.

## Current Stack

- Frontend: React, TypeScript, Vite, React Flow, lucide-react.
- Backend API: FastAPI.
- Scanner/rules: Python 3.12.
- Metadata store target: PostgreSQL, modeled as graph-friendly relational tables.
- Demo mode: in-memory synthetic intelligence graph generated from scanner models.
- Agent mode: local Python CLI/Docker scaffold for client-network scanning.

## Quick Start

Install Python dependencies:

```powershell
python -m pip install -r apps/api/requirements.txt -r apps/scanner/requirements-dev.txt
```

Install frontend dependencies:

```powershell
npm install
```

Run the API:

```powershell
$env:PYTHONPATH="apps/scanner"
python -m uvicorn apps.api.app.main:app --reload --port 8000
```

Run the web app:

```powershell
npm --workspace @phi-guard-intelligence/web run dev
```

Open the Vite URL printed by the web command. The app proxies `/api/*` to `http://127.0.0.1:8000` by default. Docker Compose can override that proxy target with `VITE_API_BASE_URL`.

## Demo Scenario

The synthetic clinic intentionally contains realistic risk patterns:

- `patients.ssn` is readable by `analyst_role`.
- `appointment_notes.notes` contains free-text PHI risk and joins to patients.
- `marketing_campaign_exports` contains email plus diagnosis category.
- `support_tickets.message` contains raw complaint text.
- `analytics_patient_segments` keeps DOB instead of only an age bucket.
- `reporting_role` can read both identifiers and lab results.
- `ai_prompt_logs` stores raw prompt text with patient details.
- `old_service_account` has broad read access.

## Analyzing Mock Data

Open the `Import` tab and upload one or more local mock files. Supported inputs:

```text
CSV / TSV
JSON / JSONL / NDJSON
XML
SQLite .db / .sqlite / .sqlite3
SQL files with CREATE TABLE DDL
Log and text files
ZIP archives containing supported files
```

The API parses uploaded content in memory, normalizes it into graph tables, columns, and relationships, runs the classifier and rule engine, then replaces the active scan. Use `Reset Demo` to return to the Northstar synthetic scenario.

Upload mode is intended for mock/local development data. The scan result stores sanitized metadata and finding evidence with `raw_value_stored=false`, but the backend still receives uploaded bytes during parsing. Do not upload real PHI to this local project.

## Scanner Agent

The scanner agent is the safer path for real client environments because classification and masking happen locally.

```powershell
$env:PYTHONPATH="apps/scanner"

python -m phi_guard_scanner.cli scan-files `
  --path "C:\path\to\mock-project" `
  --mode masked_sample `
  --workspace "Client Mock Scan" `
  --output scan-package.json `
  --pretty

python -m phi_guard_scanner.cli submit `
  --package scan-package.json `
  --api-url http://127.0.0.1:8000 `
  --agent-token dev-agent-token `
  --pretty
```

PostgreSQL connector first:

```powershell
$env:PHI_GUARD_POSTGRES_DSN="postgresql://readonly_user:password@host:5432/dbname"
python -m phi_guard_scanner.cli scan-postgres --mode metadata_only --schema public --output postgres-package.json --pretty
```

The package contains sanitized evidence such as:

```json
{
  "column": "patients.email",
  "label": "DIRECT_IDENTIFIER",
  "confidence": 0.96,
  "sample_shape": "j***@example.test",
  "raw_value_stored": false
}
```

Supported local agent inputs now include files/folders, SQLite, logs, FHIR bundles, dbt manifests, ZIPs, and PostgreSQL metadata scans. MySQL, SQL Server, S3, Azure Blob, and GCS are registered in the contract as next adapters.

## Important Limitations

- This project does not provide legal advice.
- It does not certify HIPAA compliance.
- It flags potential privacy and security risks requiring human review.
- The public demo uses synthetic data only.
- Upload mode is for mock/local development data only.
- The default evidence model stores masked snippets and booleans, not raw patient identifiers.

## Repository Map

```text
apps/
  api/        FastAPI service and route layer
  scanner/    Python scanner, classifiers, rules, demo graph generator
  web/        React/TypeScript user interface
demo-data/    Synthetic SQL and seed documentation
docs/         Architecture, threat model, data model, HIPAA-oriented mapping
infra/        Deployment scaffolding
reports/      Sample report outputs
tests/        Scanner unit tests
```

## Documentation

- [Architecture](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [No Raw PHI Storage](docs/no-raw-phi-storage.md)
- [HIPAA-Oriented Control Map](docs/hipaa-control-map.md)
- [Risk Scoring](docs/risk-scoring.md)
- [De-identification Readiness](docs/de-identification-readiness.md)
- [Data Model](docs/data-model.md)
- [Scanner Agent](docs/scanner-agent.md)
- [Secure Upload Pipeline](docs/secure-upload-pipeline.md)
- [Self-Hosted Mode](docs/self-hosted-mode.md)
- [Real Client Readiness](docs/real-client-readiness.md)
- [Business And Compliance Readiness](docs/business-compliance.md)
- [Demo Script](docs/demo-script.md)
- [Sales One-Pager](docs/sales-one-pager.md)
- [Market Positioning](docs/market-positioning.md)
- [Technical Brief](docs/technical-brief.md)
