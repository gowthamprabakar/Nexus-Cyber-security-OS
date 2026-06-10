# D.8 Threat Intel v0.2 — AlienVault OTX Coverage (WI-T1)

**Date:** 2026-06-10 · Measured **per-feed**, no aggregate (WI-T1).

## Covered at v0.2

- Live OTX subscribed-pulses polling (`/api/v1/pulses/subscribed`, `read_otx`), with
  `X-OTX-API-KEY` header auth read per-call from `OTX_API_KEY` and never stored on a
  repr-able field (WI-T8).
- Pulse-indicator normalization: OTX `type` (IPv4/IPv6/domain/hostname/URL/URI/
  FileHash-SHA256/SHA1/MD5) → internal `IocType`; carries the pulse name. Unmapped
  indicator types dropped.

## NOT covered (v0.3+)

- Pulse **metadata** depth: adversary/malware-family tags, TLP, references,
  author/subscriber graph, pulse modification history.
- Indicator pagination across large subscription sets (v0.2 reads the returned page).
- Driving the live reader from the agent's continuous run loop (built + e2e-tested;
  correlation→OCSF wiring is v0.3).

## Honest estimate

**~45–55% `[estimate]`** — the indicator → IOC normalization (the correlation-relevant
slice) is solid; the pulse-context metadata that makes OTX rich is largely deferred.
Estimate, not a measured benchmark.
