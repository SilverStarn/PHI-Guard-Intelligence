# Architecture

PHI Guard Intelligence is organized around a metadata-first scanner, a risk reasoning layer, and a graph-centered user interface.

## System Context

```text
Healthcare data source
  -> local scanner agent
  -> local classification and masking
  -> sanitized metadata and evidence
  -> API and metadata store
  -> graph UI, findings UI, reports
```

The scanner is designed to run close to the data source. In demo mode it uses synthetic data. In business trial mode it should run inside the customer network and store only masked evidence.

## Components

### Frontend

The web app presents an operational console:

- executive risk summary
- data-risk graph
- finding detail explorer
- de-identification readiness heatmap
- access matrix
- report preview

### Backend API

The API exposes workspace-oriented endpoints for:

- summary metrics
- graph nodes and edges
- findings
- de-identification readiness
- access exposure
- report generation
- scanner-agent package ingestion
- scan run history
- audit event history
- secure upload policy and upload intents

### Scanner

The scanner is responsible for:

- schema introspection
- uploaded project parsing
- column classification
- relationship discovery
- access grant collection
- masked sample analysis
- rule execution

The scanner has two deployment modes:

```text
in-process demo scanner
local scanner agent CLI/Docker image
```

The local agent emits a sanitized package and can submit it to `/api/agent/scans`.

### Metadata Store

The first production target is PostgreSQL. Graph concepts are represented with relational tables:

- assets
- classifications
- lineage_edges
- access_grants
- findings
- finding_evidence
- remediation_tasks
- organizations
- workspaces
- users
- roles
- scanner_agents
- agent_tokens
- scan_runs
- audit_events
- secrets
- retention_policies

Neo4j is intentionally not part of the MVP. The relational edge model is enough for portfolio-scale traversal and reporting.

## Data Flow

```text
Self-hosted / agent path:

```text
PostgreSQL/files/FHIR/dbt/logs
  -> local scanner agent
  -> local masked sample profiling
  -> sanitized package
  -> /api/agent/scans
  -> persistent metadata store
  -> graph and report UI
```

Mock upload path:

```text
browser upload
  -> bounded parser
  -> sanitized scan result
  -> active workspace graph
```
```

## Trust Boundary

Raw PHI must not cross from the source environment into the hosted app by default. Evidence should be represented as booleans, confidence scores, masked shapes, counts, and metadata.

## MVP Mode

The MVP can run with the in-memory Northstar synthetic intelligence graph, a local uploaded-project intelligence graph, or a scanner-agent package. Upload parsers support CSV, TSV, JSON, JSONL, XML, SQLite, SQL DDL, logs, FHIR bundles, dbt manifests, and ZIP archives containing supported files. The parser emits the same graph/findings contract as the demo scanner, so the UI does not need source-specific screens.
