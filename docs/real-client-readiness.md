# Real Client Readiness

PHI Guard Intelligence should move into real-client use in stages. The public app should keep using synthetic or mock data until the security, legal, and operational controls are real.

## Recommended Sequence

1. Persistent PostgreSQL metadata store.
2. Scanner agent CLI and Docker image.
3. PostgreSQL connector first.
4. Read-only credential onboarding.
5. Scan runs and source history.
6. Secure upload pipeline for mock/non-PHI files.
7. Self-hosted mode for real PHI.
8. OIDC/RBAC/audit logs.
9. BAAs, policies, incident response, retention.
10. Hosted PHI uploads only after the above are proven.

## Platform Tables

Implemented in the database design:

```text
organizations
workspaces
users
roles
user_roles
scan_runs
data_sources
scanner_agents
agent_tokens
audit_events
secrets
retention_policies
assets
classifications
lineage_edges
access_grants
findings
finding_evidence
remediation_tasks
```

## Auth And Security Requirements

```text
OIDC/SAML login
MFA
workspace RBAC
service accounts for scanner agents
signed agent identity or mTLS
least-privilege read-only DB credentials
secrets manager, not .env
row-level tenant isolation
immutable audit logs
short-lived agent tokens
break-glass access review
```

## Infrastructure Requirements

```text
encrypted PostgreSQL
encrypted object storage
KMS keys per client or workspace
private networking option
backups and disaster recovery
WAF and rate limiting
dependency/container scanning
vulnerability management
penetration testing
centralized audit logging
egress controls for parser workers
```

## Compliance And Business Requirements

Before hosted PHI:

```text
Business Associate Agreement template
cloud provider BAA
incident response plan
breach notification workflow
security risk analysis and risk management process
vendor management
access review process
data retention/deletion policy
security documentation
```

Product language should remain:

```text
HIPAA-oriented risk analysis support
potential privacy/security risk
de-identification readiness support
human review required
```

Avoid:

```text
HIPAA certified
guaranteed HIPAA compliant
legal determination
```
