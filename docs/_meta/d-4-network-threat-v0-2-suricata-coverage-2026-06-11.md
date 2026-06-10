# D.4 Network Threat v0.2 — Suricata Sensor Coverage (WI-N1)

**Date:** 2026-06-11 · Measured **per-sensor**, no aggregate (WI-N1).

## Covered at v0.2

- Live Suricata **real-time** eve.json subscription (push, socket/pipe) via
  `SuricataRealtimeSubscriber` — bounded-queue backpressure + graceful shutdown, alongside
  the v0.1 offline `read_suricata_alerts` (Q1 coexist, no preempt).
- Live alert normalization (`suricata_normalize.py`) byte-identical to the offline
  `SuricataAlert` + metadata enrichment (signature_id / classtype / severity / action).
- Rule-pack management (`suricata/rule_packs.py`): bundled ET-Open subset + custom packs +
  atomic hot-reload.
- Cross-sensor correlation with Zeek by the connection 4-tuple.

## NOT covered (v0.3+)

- Non-`alert` eve.json event types (flow / http / fileinfo / tls) beyond what the offline
  reader handles.
- Real-time **preempt** of the heartbeat (Q1 — both modes coexist at v0.2).
- Full ET-Pro / commercial ruleset ingestion; rule-body parsing (only sid/classtype/msg).

## Honest estimate

**~50–60% `[estimate]`** of the Suricata signal a network-IDS consumer wants — strong on
the real-time alert subscription + normalization + rule-pack + cross-sensor join, absent
on non-alert event types and full ruleset depth. Estimate, not a measured benchmark.
