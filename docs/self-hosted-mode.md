# Self-Hosted Mode

Self-hosted mode is the preferred first real-client deployment model because raw PHI can stay inside the client environment.

## Shape

```text
customer network
  -> scanner agent container
  -> read-only database/files/cloud exports
  -> local classification and masking
  -> sanitized package
  -> Intelligence API or local Intelligence dashboard
```

## Client Responsibilities

```text
create read-only database credentials
allowlist scanner agent network access
store scanner secrets in customer secret manager
review generated findings
approve remediation changes
define data retention requirements
```

## Platform Responsibilities

```text
provide signed scanner image
verify agent identity
reject raw-value evidence
store sanitized metadata only
maintain audit logs
provide exportable reports and remediation backlog
document limitations and human-review caveats
```

## Production Hardening

```text
image signing
SBOM generation
container vulnerability scanning
non-root container user
read-only filesystem where possible
egress allowlist to Intelligence API only
configurable local temp directory
local temp cleanup on exit
structured logs with PHI redaction
```

## Scanner Credential Guidance

Database credentials should be:

```text
read-only
schema-scoped
time-limited where possible
rotated
stored in a secret manager
never committed to repo
never sent to hosted Intelligence API
```
