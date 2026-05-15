# Demo Data

The Northstar Family Clinic dataset is synthetic and intentionally risky. It is designed for demos, tests, screenshots, and local development.

The SQL seed creates:

- patient identifiers and demographics
- encounters, claims, payments, medications, and lab results
- patient-linked free-text notes and support tickets
- analytics and campaign export tables with intentional de-identification blockers
- AI prompt log table with synthetic prompt-risk metadata
- PostgreSQL roles and grants that create overbroad access findings

No real PHI belongs in this directory.

