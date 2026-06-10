# Runbook — CISA KEV Live Feed (D.8 v0.2)

Live polling of the CISA Known Exploited Vulnerabilities catalog. **Public, no credential.**

## Setup

Ensure outbound HTTPS to `www.cisa.gov`. No API key required.

## Run (gated live)

```bash
NEXUS_LIVE_THREAT_INTEL=1 uv run pytest \
  packages/agents/threat-intel/tests/integration/test_continuous_ingestion_e2e.py -v -k kev
```

## Notes

- Incremental: pass the last `dateAdded` cursor as `since` to fetch only newer entries.
  The reader returns `(entries, cursor)`; persist the cursor.
- Recommended poll interval: daily (the KEV catalog updates daily–weekly).
- `knownRansomwareCampaignUse` is conservative: only `"Known"` → `True`.
