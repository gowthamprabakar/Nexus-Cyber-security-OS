# data-security v0.2 — PII Coverage (WI-S2)

**Date:** 2026-06-11 · Measured **per-data-type**, no aggregate (WI-S2).

## Covered at v0.2

- The v0.1 7-label PII set (SSN, credit card w/ Luhn, AWS key, JWT, email, phone, generic API
  token) — unchanged, byte-identical precedence (WI-S5).
- Per-label confidence scoring + privacy hash (`classifiers/scored.py`); label-only output.

## NOT covered (v0.3)

- Date-of-birth, postal addresses, names (ML/NER, Q3 → v0.3); multi-locale (US-only).

## Honest estimate

**~50-60% `[estimate]`** of common PII — strong on structured identifiers, absent on
free-text/NER PII. Estimate, not a benchmark.
