# data-security v0.2 — PHI Coverage (WI-S2)

**Date:** 2026-06-11 · Measured **per-data-type**, no aggregate (WI-S2).

## Covered at v0.2 (net-new)

- HIPAA-aligned identifiers (Task 8): medical record number (context-required), ICD-10
  diagnostic codes (dotted form), NPI (Luhn over the 80840 issuer prefix).
- Context-required / distinctive so they fire only on genuine PHI (byte-identical eval, WI-S5).

## NOT covered (v0.3)

- HL7/FHIR deep parsing, lab result patterns, free-text clinical notes (ML, Q3 → v0.3).

## Honest estimate

**~30-40% `[estimate]`** of PHI — the high-signal structured identifiers are covered; clinical
free-text + full HL7/FHIR are deferred. Estimate, not a benchmark.
