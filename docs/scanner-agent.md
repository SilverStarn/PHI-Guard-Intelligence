# Scanner Agent

The scanner agent is the preferred real-client path. It runs inside the client network, classifies locally, masks evidence locally, then sends only a sanitized metadata package to the Intelligence API.

```text
client database/files
  -> local scanner agent
  -> local classification/masking
  -> sanitized metadata package
  -> PHI Guard Intelligence API
  -> dashboard/findings/report/remediation
```

## Implemented Commands

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

PostgreSQL connector:

```powershell
$env:PHI_GUARD_POSTGRES_DSN="postgresql://readonly_user:password@host:5432/dbname"

python -m phi_guard_scanner.cli scan-postgres `
  --mode metadata_only `
  --schema public `
  --workspace "Clinic Postgres Metadata" `
  --output postgres-package.json `
  --pretty
```

## Scan Modes

```text
metadata_only
  Reads schema, table, column, row-count, relationship-style metadata where available.

masked_sample
  Reads bounded local samples into agent memory, classifies them, and sends only masked shapes.

deep_local
  Reserved for larger local profiling jobs. Raw values still stay in the client environment.
```

## Source Types

Implemented now:

```text
CSV / TSV
JSON / JSONL / NDJSON
XML
SQLite
SQL DDL
ZIP folders
application logs (.log/.txt)
FHIR JSON bundles and NDJSON resources
dbt manifest.json
PostgreSQL metadata connector
```

Contract-registered next connectors:

```text
MySQL
SQL Server
S3
Azure Blob
GCS
```

Those source types are present in the agent contract so the platform shape is stable, but provider SDK adapters should be enabled only in the customer-network agent build.

## Evidence Contract

The agent sends evidence like:

```json
{
  "column": "patients.email",
  "label": "DIRECT_IDENTIFIER",
  "confidence": 0.96,
  "sample_shape": "j***@example.test",
  "raw_value_stored": false,
  "source": "value_pattern"
}
```

No raw patient values, raw notes, raw prompts, raw connection strings, or unredacted secrets should be included.

## Agent Identity

Current local-dev identity is bearer token based:

```text
Authorization: Bearer dev-agent-token
```

Production should move to:

```text
short-lived signed agent tokens
token hash storage
rotation/revocation
mTLS for high-trust deployments
workspace-scoped service accounts
least-privilege read-only DB credentials
```

## Docker

The scanner image is scaffolded at:

```text
apps/scanner/Dockerfile
```

Example:

```powershell
docker build -f apps/scanner/Dockerfile -t phi-guard-scanner .
docker run --rm -v C:\mock-data:/scan phi-guard-scanner scan-files --path /scan --mode masked_sample --workspace "Mock Data"
```
