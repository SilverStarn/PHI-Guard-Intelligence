# Secure Upload Pipeline

Browser upload is useful for demos and mock files. Hosted real-PHI uploads require a stricter pipeline than the local MVP.

## Current Mock Upload Mode

The current app supports local/mock upload:

```text
browser
  -> FastAPI upload endpoint
  -> bounded in-memory parser
  -> local classifier/rule engine
  -> sanitized scan result
  -> dashboard/findings/report
```

Controls already represented:

```text
file type validation
per-file size limits
zip member size limits
zip path traversal protection
sanitized finding evidence
raw_value_stored=false
no LLM calls with raw uploaded content
```

Use:

```text
GET  /api/uploads/policy
POST /api/uploads/intents
POST /api/uploads/analyze
```

## Production Upload Mode Required For Real Clients

Real client upload should be:

```text
browser
  -> authenticated upload intent
  -> pre-signed encrypted object storage URL
  -> object-created event
  -> malware scan
  -> file type validation
  -> isolated parser worker
  -> sanitized scan result
  -> automatic raw-file deletion
  -> immutable audit events
```

Required controls:

```text
per-client KMS keys
short raw-file retention, ideally minutes
audit events for upload, scan, view, export, delete
parser sandboxing
size limits and zip-bomb protection
no raw PHI in logs, errors, traces, telemetry, or LLM calls
explicit client retention settings
malware scan before parser execution
isolated worker without broad network egress
raw object deletion confirmation
```

## Default Product Rule

Hosted PHI uploads should stay disabled until:

```text
Business Associate Agreement workflow exists
cloud provider BAA is in place
incident response workflow is tested
breach notification workflow is documented
tenant encryption and deletion controls are implemented
```

The safer real-client path is the self-hosted scanner agent.
