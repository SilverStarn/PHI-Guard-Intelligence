# Data Model

The metadata store is graph-friendly but relational. The durable target is PostgreSQL; the local dev API can also write scan and audit summaries to `.phi_guard/metadata-store.jsonl` when a Postgres DSN is not configured.

## Business View

The data model is designed to answer buyer-level questions:

- What data sources were scanned?
- Which assets may contain PHI risk?
- Which columns triggered classifier labels?
- How do assets relate through lineage or joins?
- Who can access sensitive assets?
- Which findings are open, how severe are they, and what evidence supports them?
- What remediation tasks, controls, and audit events prove follow-through?

This matters because healthcare privacy and security teams need more than a list of columns. They need a defensible evidence trail from discovery to remediation.

## Technical View

The model stores sanitized metadata, not raw PHI. It treats graph concepts such as assets and lineage edges as relational tables so PostgreSQL can serve the MVP without adding a separate graph database.

The canonical PostgreSQL DDL is in:

```text
infra/postgres/001_metadata_store.sql
```

Raw PHI and raw uploaded files do not belong in the metadata store. Evidence records must keep `raw_value_stored=false`.

## Tenant and Security Tables

### organizations

```text
id
name
created_at
```

### workspaces

```text
id
organization_id
name
kms_key_ref
created_at
```

### users

```text
id
organization_id
email
display_name
oidc_subject
mfa_required
created_at
```

### roles / user_roles

```text
roles:
id
workspace_id
name
permissions
created_at

user_roles:
user_id
role_id
created_at
```

### scanner_agents

```text
id
workspace_id
name
version
identity_mode      -- signed_token now, mTLS later
status
last_seen_at
created_at
```

### agent_tokens

```text
id
scanner_agent_id
token_hash
expires_at
revoked_at
created_at
```

### secrets

```text
id
workspace_id
secret_type
secret_ref         -- reference to secret manager, never plaintext
created_at
rotated_at
```

### retention_policies

```text
id
workspace_id
raw_upload_ttl_minutes
metadata_ttl_days
delete_raw_after_scan
created_at
```

### audit_events

```text
id
workspace_id
actor_id
event_type         -- upload.created, scan.completed, finding.viewed, report.exported, delete.completed
metadata_json
created_at
```

## Tables

### data_sources

```text
id
workspace_id
type
name
connection_mode
created_at
last_scan_at
```

### scan_runs

```text
id
workspace_id
data_source_id
scanner_agent_id
source             -- demo, browser_upload, scanner_agent
mode               -- metadata_only, masked_sample, deep_local
status
started_at
completed_at
summary_json
sanitized_package_sha256
```

### assets

```text
id
workspace_id
scan_run_id
data_source_id
asset_type
name
schema_name
table_name
column_name
row_count_estimate
risk_score
created_at
updated_at
```

### classifications

```text
id
asset_id
label
confidence
source
details_json
created_at
```

### lineage_edges

```text
id
workspace_id
source_asset_id
target_asset_id
edge_type
confidence
evidence_json
created_at
```

### access_grants

```text
id
workspace_id
asset_id
principal_type
principal_name
permission
source
last_seen_at
```

### findings

```text
id
workspace_id
severity
title
status
risk_score
confidence
asset_id
description
why_it_matters
control_mapping_json
remediation_summary
created_at
resolved_at
```

### finding_evidence

```text
id
finding_id
evidence_type
safe_snippet
raw_value_stored
metadata_json
```

## Sanitized Agent Package

Scanner agents send a package shaped like:

```json
{
  "package_version": "2026-05-14",
  "agent": {
    "agent_id": "clinic-prod-agent",
    "version": "0.1.0",
    "identity_mode": "signed_token"
  },
  "source": {
    "source_type": "postgres",
    "name": "Clinic EHR Postgres",
    "uri": "postgres://redacted",
    "mode": "masked_sample"
  },
  "privacy": {
    "raw_value_stored": false,
    "raw_file_uploaded": false,
    "classification_location": "local_agent",
    "llm_receives_raw_phi": false
  },
  "evidence": [
    {
      "column": "patients.email",
      "label": "DIRECT_IDENTIFIER",
      "confidence": 0.96,
      "sample_shape": "j***@example.test",
      "raw_value_stored": false
    }
  ],
  "sanitized_intelligence_graph": {}
}
```

The API rejects agent packages when any package privacy field, top-level evidence item, or finding evidence marks raw retention as true.

### remediation_tasks

```text
id
finding_id
title
description
owner
status
sql_patch
iac_patch
policy_patch
created_at
completed_at
```
