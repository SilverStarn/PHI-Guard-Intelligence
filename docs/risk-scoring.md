# Risk Scoring

The MVP scoring model is explainable:

```text
risk score = impact * likelihood * exposure * control gap * confidence
```

Each factor is normalized from 0.0 to 1.0, and the final score is scaled to 100.

## Factors

Impact:
How sensitive is the data? Direct identifiers, clinical facts, payment data, raw notes, and AI prompt content increase impact.

Likelihood:
How likely is inappropriate access, disclosure, or misuse? Broad roles, exports, logs, and external destinations increase likelihood.

Exposure:
How many records, users, roles, downstream systems, and tables are involved?

Control Gap:
Are masking, audit logging, encryption evidence, RBAC, and retention controls missing?

Confidence:
How certain is the scanner? Column name plus value pattern plus lineage is stronger than column name alone.

## Severity Bands

| Score | Severity |
| ---: | --- |
| 85-100 | Critical |
| 70-84 | High |
| 40-69 | Moderate |
| 0-39 | Low |

## Example

`patients.ssn` is readable by `reporting_role` and exported to analytics.

- Impact: 1.00
- Likelihood: 0.80
- Exposure: 0.90
- Control gap: 0.90
- Confidence: 0.95
- Score: 62 after normalization boost for direct identifiers and broad access
- Severity: High

The engine includes deterministic boosts so severe direct-identifier combinations are not under-scored by multiplication alone.

