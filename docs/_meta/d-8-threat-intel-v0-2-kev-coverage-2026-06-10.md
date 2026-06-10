# D.8 Threat Intel v0.2 — CISA KEV Catalog Coverage (WI-T1)

**Date:** 2026-06-10 · Measured **per-feed**, no aggregate (WI-T1).

## Covered at v0.2

- Live CISA Known Exploited Vulnerabilities JSON polling (`CisaKevLiveReader`), public
  (no credential), with a `dateAdded` persistent cursor (dedup of new entries).
- Parsing through the shared offline normalizer (byte-identical entries): cveID,
  vendor/product, vulnerabilityName, dateAdded, shortDescription, requiredAction,
  dueDate, `knownRansomwareCampaignUse` (conservative "Known" → True), CWEs.

## NOT covered (v0.3+)

- Historical catalog **diffing** beyond the dateAdded cursor (no per-field change log).
- The KEV `catalogVersion` / count reconciliation metadata.
- Driving the live reader from the agent's continuous run loop (built + e2e-tested;
  correlation→OCSF wiring is v0.3).

## Honest estimate

**~80–90% `[estimate]`** — the KEV catalog is a small, flat, well-bounded schema and
v0.2 surfaces essentially all of its per-entry fields. The gap is purely operational
(change-diffing / catalog metadata), not field coverage. Estimate, not a benchmark.
