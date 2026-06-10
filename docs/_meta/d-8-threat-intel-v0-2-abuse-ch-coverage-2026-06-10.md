# D.8 Threat Intel v0.2 — abuse.ch Feeds Coverage (WI-T1)

**Date:** 2026-06-10 · Measured **per-feed**, no aggregate (WI-T1). Three abuse.ch
feeds, each measured separately below.

## URLhaus

- **Covered:** recent malicious URLs (`/downloads/json_recent/`) → `URL` IOCs (value,
  threat label, date_added), HTTP-polled.
- **Not (v0.3):** payload/hash linkage, host/registrar enrichment, online/offline
  status history, tag taxonomy.
- **Estimate:** **~55–65% `[estimate]`** of URLhaus per-entry fields.

## ThreatFox

- **Covered:** IOCs (`/api/v1/`) mapped by `ioc_type` → `IP` / `DOMAIN` / `URL` /
  `FILE_HASH`; threat_type + first_seen. Unmapped types (e.g. mutex) dropped.
- **Not (v0.3):** malware-family linkage, confidence levels, reporter/reference graph,
  the POST query-filter API (v0.2 reads the recent set).
- **Estimate:** **~50–60% `[estimate]`**.

## MalwareBazaar

- **Covered:** recent samples (`/api/v1/`) → `FILE_HASH` IOCs (sha256, signature,
  first_seen).
- **Not (v0.3):** md5/sha1/imphash/ssdeep variants, file-type/YARA/vendor-intel
  metadata, the sample-download + tag graph.
- **Estimate:** **~40–50% `[estimate]`** (sha256 + signature only).

## Note

All three are HTTP-polled (Q7, no TAXII) through the injectable transport seam and
normalized to the internal `IocType` vocabulary. Wiring them into the continuous run
loop's correlation→OCSF path is v0.3 (built + e2e-tested through normalization).
