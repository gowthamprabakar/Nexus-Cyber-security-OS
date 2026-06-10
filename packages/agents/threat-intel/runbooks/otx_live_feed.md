# Runbook — AlienVault OTX Live Feed (D.8 v0.2)

Live polling of the OTX subscribed-pulses feed. **API key required.**

## Setup

1. Create an OTX account + copy your API key — https://otx.alienvault.com/api
2. Subscribe to the pulses you want surfaced (the feed returns _subscribed_ pulses).
3. Export the key; it rides in the `X-OTX-API-KEY` header, read per-call, never stored:
   ```bash
   export OTX_API_KEY=<your-key>
   ```

## Run (gated live)

```bash
NEXUS_LIVE_THREAT_INTEL=1 OTX_API_KEY=$OTX_API_KEY uv run pytest \
  packages/agents/threat-intel/tests/integration/test_continuous_ingestion_e2e.py -v -k otx
```

## Notes

- A missing key raises `OtxReaderError` (the reader never silently no-ops).
- Indicator types map IPv4/IPv6/domain/hostname/URL/URI/FileHash-\* → internal `IocType`;
  unmapped types are dropped.
- Pulse metadata depth (tags, TLP, references) is v0.3.
