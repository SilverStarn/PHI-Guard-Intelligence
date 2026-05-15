# De-identification Readiness

PHI Guard Intelligence supports de-identification readiness checks. It does not perform Expert Determination.

## Business Purpose

Healthcare organizations often need to know whether a dataset is ready for analytics, reporting, vendor sharing, AI experimentation, or research review. The hard part is not only finding obvious identifiers. It is finding the fields that make people re-identifiable when combined with dates, geography, account numbers, free text, or linkable keys.

PHI Guard Intelligence presents de-identification readiness as a review workflow, not as an automatic certification. The product helps a privacy, security, or data governance team identify likely blockers, explain why they matter, and decide what needs human review before a dataset is shared or reused.

## Modes

### Safe Harbor Readiness

The scanner checks for blocker categories such as:

- names
- geographic subdivisions smaller than allowed generalization
- full dates beyond year
- phone numbers
- email addresses
- SSNs
- medical record numbers
- account numbers
- IP addresses
- biometric identifiers
- full-face photo indicators
- other unique codes
- free-text fields that may hide identifiers

The product uses these categories as readiness signals and blocker categories. It does not claim that absence of a detected blocker satisfies the Privacy Rule.

### Expert Determination Support

Future support can produce artifacts for qualified expert review:

- uniqueness metrics
- k-anonymity summaries
- quasi-identifier combinations
- row-count and sparsity estimates
- transformation history

## Readiness Status

- Not ready: direct identifiers or risky free text remain.
- Review: generalized fields appear but require human validation.
- Likely ready: no obvious blockers detected in metadata and masked samples.

## Technical Implementation

The API returns de-identification rows from `/api/deidentification`. Each row includes:

```text
table
row_count_estimate
blockers
status
readiness_score
```

The frontend renders this as a heatmap so reviewers can quickly see which datasets contain names, dates of birth, geography, ZIP/postal fields, phone numbers, email addresses, MRNs, SSNs, IP addresses, or free-text risk.

Readiness scoring is intentionally simple in the MVP:

- Start from 100.
- Subtract for detected blocker categories.
- Apply extra caution to marketing/export-style datasets.
- Require human review regardless of score.

## Regulatory References

Public HHS guidance describes two HIPAA Privacy Rule de-identification methods: Expert Determination and Safe Harbor.

- HHS de-identification guidance: https://www.hhs.gov/hipaa/for-professionals/privacy/special-topics/de-identification/index.html
- HHS Privacy Rule summary and Safe Harbor categories: https://www.hhs.gov/hipaa/for-professionals/privacy/laws-regulations/index.html

PHI Guard Intelligence uses this language to support readiness review. It does not provide legal advice or certify de-identification.
