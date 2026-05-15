# No Raw PHI Storage

The most important design rule is simple: the PHI Guard Intelligence app should not store raw PHI by default.

## Allowed Evidence

Examples of allowed evidence:

```json
{
  "email_detected": true,
  "sample_shape": "j***@example.test",
  "date_pattern": "mm/dd/yyyy",
  "identifier_confidence": 0.94,
  "row_count_estimate": 184203,
  "raw_value_stored": false
}
```

## Disallowed Evidence

The app must not store:

- full patient names
- SSNs
- medical record numbers
- raw clinical notes
- unredacted addresses
- raw prompt text containing patient details
- unmasked support ticket messages

## Scan Modes

### Metadata Only

Reads table names, column names, data types, constraints, row estimates, permissions, and relationship metadata.

### Metadata Plus Masked Sample

Optionally inspects tiny local samples and persists only masked shapes, pattern booleans, and confidence scores.

### Deep Local Scan

Runs inside the customer environment and should still avoid sending raw values to the Intelligence service.

## Demo Policy

The public demo uses synthetic Northstar Family Clinic data and marks every evidence item with `raw_value_stored=false`.

## Upload Mode Policy

Upload mode is intended for mock/local development files. Uploaded bytes are received by the backend and parsed in memory, but the active scan result stores only:

- table and column names
- inferred data types
- row-count estimates
- pattern labels and confidence scores
- relationship metadata
- masked/sanitized evidence

The scanner result must still mark finding evidence with `raw_value_stored=false`. Do not upload real PHI to this portfolio project.
