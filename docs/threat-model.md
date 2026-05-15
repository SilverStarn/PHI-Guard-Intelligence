# Threat Model

## Assets

- Database connection secrets.
- Sanitized schema metadata.
- Masked evidence snippets.
- Findings and remediation tasks.
- Access grant inventory.
- Reports.

## Non-Goals

- Storing raw PHI in the hosted demo.
- Providing legal conclusions.
- Certifying compliance.
- Processing real patient records in the public demo.

## Primary Risks

### Raw PHI Leakage

Risk: scanner samples or reports accidentally store patient identifiers.

Controls:

- metadata-first scan mode by default
- masked sample shapes only
- `raw_value_stored=false` evidence field
- synthetic demo data
- tests for evidence serialization

### Overbroad App Access

Risk: users see sensitive findings for workspaces they should not access.

Controls:

- workspace-level RBAC planned
- audit logging planned for scan and finding views
- least-privilege API design

### Secret Exposure

Risk: database credentials leak through logs or reports.

Controls:

- no connection strings in reports
- `.env` ignored by git
- future encrypted secrets storage
- future scanner agent identity

### Misleading Compliance Claims

Risk: users treat findings as legal determinations.

Controls:

- product wording uses "potential risk"
- findings include human-review caveats
- docs state limitations clearly

### AI Data Exposure

Risk: raw prompts, notes, or patient details are sent to an external LLM.

Controls:

- assistant receives sanitized findings only
- no raw note analysis in MVP
- AI exposure rules flag prompt, embedding, and vector-store destinations

## Residual Risk

Even sanitized metadata can reveal sensitive business information. Business deployments should run inside the customer environment unless a signed agreement, hardened infrastructure, and strong access controls are in place.

