# D.8 Threat Intel v0.2 — NVD CVE Feed Coverage (WI-T1)

**Date:** 2026-06-10 · Measured **per-feed**, no aggregate (WI-T1).

## Covered at v0.2

- Live NVD CVE 2.0 REST API polling (`NvdLiveReader`), incremental via
  `lastModStartDate` + a `lastModified` persistent cursor (dedup).
- Parsing through the **shared offline normalizer** so live records are byte-identical
  to the file path: CVE id, English description, published/lastModified, vulnStatus,
  CVSS v3.1 → v3.0 base score + severity, reference URLs.
- `NVD_API_KEY` header auth (never stored/logged, WI-T8).

## NOT covered (v0.3+)

- CVSS **v4.0** and **v2.0** metrics (v3.1/v3.0 only).
- CPE / `configurations` (affected-product matching) — not parsed.
- CWE weakness mapping, change-history, and rejected-CVE handling.
- Driving the live reader from the agent's continuous run loop (built + e2e-tested
  through normalization; correlation→OCSF wiring is v0.3, see verification record).

## Honest estimate

**~45–55% `[estimate]`** of the fields a CIEM-grade CVE consumer wants — strong on the
correlation-relevant core (id, severity, dates), absent on product-matching (CPE) and
CVSS v4. Estimate, not a measured benchmark.
