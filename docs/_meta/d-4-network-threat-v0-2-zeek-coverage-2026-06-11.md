# D.4 Network Threat v0.2 — Zeek Sensor Coverage (WI-N1)

**Date:** 2026-06-11 · Measured **per-sensor**, no aggregate (WI-N1).

## Covered at v0.2

- Live Zeek **real-time** log subscription (push, Broker API / log socket) via
  `ZeekRealtimeSubscriber` — reuses the sensor-agnostic Task-2 consumer machinery (no
  duplication), alongside the offline DNS reader (Q1/Q2 coexist).
- Live normalization (`zeek_normalize.py`): `conn` → `ZeekConn`
  (uid/4-tuple/duration/bytes/conn_state); `dns` → `DnsEvent` (the **same** schema the
  offline DNS reader produces — query lowercased + trailing dot stripped, kind classified).
- Cross-sensor correlation with Suricata by the connection 4-tuple.

## NOT covered (v0.3+)

- Zeek log types beyond `conn` + `dns` (http / ssl / files / weird / notice).
- Zeek `notice.log` framework integration + intel framework hits.
- Behavioral connection models (v0.3) — only the typed records + cross-sensor join here.

## Honest estimate

**~45–55% `[estimate]`** of the Zeek signal a network-IDS consumer wants — solid on the
real-time conn/dns subscription + DnsEvent reuse + cross-sensor join, absent on the wider
log-type surface + the notice/intel frameworks. Estimate, not a measured benchmark.
