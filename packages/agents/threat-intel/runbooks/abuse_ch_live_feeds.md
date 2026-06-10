# Runbook — abuse.ch Live Feeds (D.8 v0.2)

HTTP-polled IOC feeds: **URLhaus**, **ThreatFox**, **MalwareBazaar** (Q7, no TAXII).

## Setup

Ensure outbound HTTPS to `urlhaus.abuse.ch`, `threatfox-api.abuse.ch`,
`mb-api.abuse.ch`. abuse.ch may require an Auth-Key for some endpoints — supply it via
the injected transport's headers when prompted by abuse.ch's terms.

## Run (gated live)

```bash
NEXUS_LIVE_THREAT_INTEL=1 uv run pytest \
  packages/agents/threat-intel/tests/integration/test_continuous_ingestion_e2e.py -v \
  -k "urlhaus or threatfox or malwarebazaar"
```

## Notes

- All three normalize to the internal `IocType` vocabulary (URL / IP / DOMAIN / FILE_HASH);
  unmapped ThreatFox `ioc_type`s are dropped.
- Use the `HttpPoller` conditional-GET (ETag / Last-Modified) + per-feed `RateLimiter`
  to respect abuse.ch rate limits on continuous polling.
- Coverage per feed is documented separately (WI-T1) in `docs/_meta/d-8-*-abuse-ch-coverage-*`.
