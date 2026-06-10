# Runbook — NVD CVE Live Feed (D.8 v0.2)

Live continuous-mode polling of the NVD CVE 2.0 REST API.

## Setup

1. (Recommended) Request an NVD API key — https://nvd.nist.gov/developers/request-an-api-key
   (raises the rate limit). Export it; it rides in the `apiKey` header and is never logged:
   ```bash
   export NVD_API_KEY=<your-key>
   ```
2. Ensure outbound HTTPS to `services.nvd.nist.gov`.

## Run (gated live)

```bash
NEXUS_LIVE_THREAT_INTEL=1 uv run pytest \
  packages/agents/threat-intel/tests/integration/test_continuous_ingestion_e2e.py::test_live_nvd_poll_e2e -v
```

## Notes

- Incremental: pass the last `lastModified` cursor as `since` to fetch only new/changed
  CVEs (dedup). The reader returns `(records, cursor)`; persist the cursor between polls.
- Recommended poll interval: ~2h (per NVD guidance).
- v0.2 parses CVSS v3.1→v3.0 + core fields; CPE/configurations + CVSS v4 are v0.3.
