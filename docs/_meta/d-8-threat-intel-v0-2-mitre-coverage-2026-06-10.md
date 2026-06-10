# D.8 Threat Intel v0.2 — MITRE ATT&CK Coverage (WI-T1)

**Date:** 2026-06-10 · Measured **per-feed**, no aggregate (WI-T1).

## Covered at v0.2

- Live MITRE ATT&CK **Enterprise** TAXII 2.1 collection polling via `TaxiiClient`
  (`MitreAttackLiveReader`), with `more`/`next` pagination, a `modified` cursor, and
  reconnect-on-failure (WI-T9). CC-BY-4.0 attribution unchanged (H4).
- `attack-pattern` (technique) parsing through the shared offline parser: technique id
  (T-code), name, tactics (kill-chain phases), reference URL.
- `intrusion-set` + `uses` relationships consumed by the basic threat-actor matcher
  (Task 14): actor → technique profiles.

## NOT covered (v0.3+)

- ATT&CK **Mobile** and **ICS** matrices (Enterprise only).
- Sub-techniques relationship depth, `mitigates` / `detects` relationships, software
  (malware/tool) → technique graphs beyond actor `uses`.
- Full campaign attribution (multi-signal TTP analysis) — v0.2 is a coverage heuristic.

## Honest estimate

**~30–40% `[estimate]`** of the full ATT&CK knowledge graph — solid on Enterprise
techniques + actor-uses edges (the correlation-relevant slice), absent on Mobile/ICS,
mitigations, and the deeper relationship graph. Estimate, not a benchmark.
