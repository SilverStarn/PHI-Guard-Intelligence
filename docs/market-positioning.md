# Market Positioning

## Product Category

PHI Guard Intelligence sits between data discovery, healthcare privacy engineering, security risk analysis, and governance evidence management.

The clearest positioning:

> A healthcare data risk intelligence platform that maps potential PHI exposure, explains why each risk matters, and turns findings into remediation evidence.

It should not be sold as:

- A legal compliance certifier.
- A replacement for privacy counsel.
- A generic DLP tool.
- A generic data catalog.
- A production PHI upload service in its current MVP form.

## Buyer Personas

### CIO / CTO

Pain:

- Sensitive data is spread across clinical, billing, analytics, support, and AI systems.
- Teams cannot easily explain where PHI moves.
- Vendor and AI initiatives create new risk questions.

Message:

PHI Guard Intelligence creates a shared technical map of sensitive healthcare data risk so leadership can prioritize modernization and remediation with evidence.

Proof points:

- Metadata-first scanning.
- Graph view of assets, lineage, roles, controls, and findings.
- Scanner-agent pattern for customer-network deployment.

### CISO / Security Engineering

Pain:

- Access review lacks data sensitivity context.
- Logs and prompt stores may contain PHI.
- Audit gaps are discovered late.

Message:

PHI Guard Intelligence gives security teams a PHI-aware view of access, logging, AI exposure, and blast radius.

Proof points:

- Access matrix.
- AI/log finding rules.
- Risk scoring with control-gap and exposure factors.
- Audit event and scan-run history.

### Privacy / Compliance Officer

Pain:

- Risk analysis evidence is manual and scattered.
- De-identification reviews are hard to explain.
- Findings need human-review caveats and control mapping.

Message:

PHI Guard Intelligence turns technical scan results into privacy-reviewable evidence, control mappings, and remediation narratives.

Proof points:

- HIPAA-oriented control map.
- De-identification readiness heatmap.
- Finding detail with why-it-matters, evidence, recommended steps, and human review.
- Explicit limitation language.

### Data / Analytics Leader

Pain:

- Analytics exports may carry identifiers or quasi-identifiers.
- Free-text and operational notes block safe data sharing.
- Teams need utility without uncontrolled PHI spread.

Message:

PHI Guard Intelligence helps data teams identify de-identification blockers and build safer analytics/export workflows.

Proof points:

- Safe Harbor-style blocker categories.
- Identifier flow into analytics/export assets.
- Remediation guidance for masked views, tokenized joins, and free-text review.

### Healthcare Operations / Product

Pain:

- Teams need to move quickly with workflows, vendors, support, and AI pilots.
- Privacy risk can slow initiatives when evidence is missing.

Message:

PHI Guard Intelligence helps operational teams see privacy risk earlier, before it becomes an audit, incident, or launch blocker.

Proof points:

- Business-readable dashboard.
- Executive report.
- Remediation backlog.

## Competitive Frame

PHI Guard Intelligence is strongest when framed as a bridge:

- More contextual than a data catalog.
- More healthcare-specific than generic security dashboards.
- More technical and evidence-driven than static GRC checklists.
- More remediation-oriented than a one-time scanner.

## Messaging Pillars

### 1. See the PHI Risk Map

Show where identifiers, health/payment context, free text, AI workflows, roles, and exports connect.

### 2. Explain the Risk

Turn each finding into risk score, confidence, evidence, blast radius, control mapping, and human-review guidance.

### 3. Reduce Risk Without Copying Raw PHI

Use local classification, masked sample signals, sanitized packages, and explicit raw-retention checks.

### 4. Move From Finding to Fix

Create owner-ready remediation tasks with effort, due windows, recommended steps, and expected risk reduction.

## Objections And Responses

### "Does this make us HIPAA compliant?"

No. It supports HIPAA-oriented risk analysis and de-identification readiness review, but it does not certify compliance or replace legal review.

### "Will raw PHI go into the platform?"

The intended production architecture uses a local scanner agent and sanitized packages. The MVP upload path is for mock/local development data only.

### "How is this different from DLP?"

DLP is usually event/content-focused. PHI Guard Intelligence focuses on the data estate: schema, lineage, access, de-identification blockers, risk reasoning, and remediation evidence.

### "How is this different from a data catalog?"

Catalogs inventory data assets. PHI Guard Intelligence adds healthcare-specific PHI classification, risk scoring, control mapping, and remediation workflows.

### "Can this handle real clients?"

The architecture is designed for that path, but the current MVP should mature through the real-client readiness checklist: BAA workflow, secure upload pipeline, hardened auth, tenant isolation, deployment controls, vulnerability management, and operational policies.

## Demo Talk Track

1. "Here is the executive risk picture."
2. "Here is the graph showing how PHI moves."
3. "Here is why this finding matters."
4. "Here is the evidence we store, and what we do not store."
5. "Here is how privacy, security, and data teams turn the finding into remediation."
6. "Here is what must mature before production PHI processing."

## Short Taglines

- Know where PHI risk lives before it becomes an incident.
- A risk intelligence map for healthcare data, access, AI, and de-identification.
- From PHI discovery to evidence-backed remediation.
- Healthcare privacy engineering for modern data teams.

