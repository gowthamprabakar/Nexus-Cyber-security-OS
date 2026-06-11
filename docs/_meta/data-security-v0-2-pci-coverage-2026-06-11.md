# data-security v0.2 — PCI Coverage (WI-S2)

**Date:** 2026-06-11 · Measured **per-data-type**, no aggregate (WI-S2).

## Covered at v0.2

- PAN with Luhn (v0.1) + the v0.2 expansion (Task 9): CVV (context), card expiration
  (context + MM/YY), Track 1/2 magnetic-stripe sentinels.
- A valid-Luhn PAN dominates as CREDIT_CARD; TRACK_DATA catches stripe-format content.

## NOT covered (v0.3)

- Tokenised PAN detection, P2PE-scoped data, ML classification (Q3 → v0.3).

## Honest estimate

**~55-65% `[estimate]`** of PCI cardholder data — PAN + CVV + expiration + track are covered;
tokenised/encrypted-form detection deferred. Estimate, not a benchmark.
