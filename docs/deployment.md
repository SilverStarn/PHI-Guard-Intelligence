# Deployment

## Public Demo

- Synthetic data only.
- Hosted frontend.
- Hosted API in demo mode.
- No customer database connections.
- No raw PHI.

## Self-Hosted Trial

- Docker Compose inside customer network.
- Scanner agent uses read-only database credentials.
- Raw values are inspected locally only when explicitly enabled.
- Agent sends only sanitized metadata packages to PHI Guard Intelligence, or reports are generated inside the environment.
- Use `apps/scanner/Dockerfile` for the agent container.

Example:

```powershell
docker build -f apps/scanner/Dockerfile -t phi-guard-scanner .
docker run --rm -v C:\mock-data:/scan phi-guard-scanner scan-files --path /scan --mode masked_sample --workspace "Mock Data"
```

## Production SaaS

Production handling of real PHI would require business associate agreements, hardened cloud infrastructure, access logging, encryption, incident response, data retention policies, vendor review, and operational controls. The MVP is not claiming that readiness.

Additional production requirements:

- PostgreSQL metadata store using `infra/postgres/001_metadata_store.sql`.
- OIDC/SAML and MFA.
- Workspace RBAC and row-level tenant isolation.
- Scanner-agent service accounts with signed tokens or mTLS.
- KMS-backed encryption for metadata and object storage.
- Immutable audit logs for upload, scan, finding view, report export, and deletion.
- Malware scanning and isolated parser workers for hosted upload.
- Short raw upload retention, preferably measured in minutes.
