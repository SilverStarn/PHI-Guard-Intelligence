# HIPAA-Oriented Control Map

PHI Guard Intelligence maps technical observations to HIPAA-oriented concepts. It does not determine whether a legal violation occurred.

| Product finding | HIPAA-oriented concept | Product response |
| --- | --- | --- |
| Broad analyst access to patient identifiers and diagnoses | Access control / minimum necessary | Flag role exposure and recommend restricted views or narrower roles. |
| PHI in free-text notes exported to reports | De-identification / minimum necessary | Flag free-text blocker and recommend redaction, access restriction, and export review. |
| No audit evidence for high-risk table reads | Audit controls | Recommend database or application audit logging for read/export activity. |
| Direct identifiers in analytics table | De-identification / minimum necessary | Recommend tokens, buckets, generalization, or aggregate-only views. |
| PHI sent to AI prompt logs | AI governance / data security | Recommend prompt redaction, logging controls, provider allowlist, and review. |
| No asset or lineage map | Risk analysis support | Generate inventory, relationships, and ePHI movement graph. |

## Finding Language

Use:

```text
Potential access-control risk.
Potential minimum-necessary risk.
De-identification readiness blocker.
Human review required.
```

Avoid:

```text
HIPAA violation.
HIPAA certified.
Guaranteed compliant.
Legal determination.
```

