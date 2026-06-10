# D.3 Runtime Threat v0.2 — Tracee Sensor Coverage (WI-R1)

**Date:** 2026-06-10 · Measured **per-sensor**, no aggregate (WI-R1).

## Covered at v0.2

- Live Tracee **real-time** kernel-event subscription (push, event pipe/gRPC) via
  `TraceeRealtimeSubscriber` — reuses the sensor-agnostic Task-2 consumer machinery
  (bounded-queue backpressure + graceful shutdown), alongside the offline
  `tracee_alerts_read` (Q1 / Q2 coexist).
- Live normalization (`tracee_normalize.py`): mirrors the offline field extraction
  (eventName / process / container / metadata Severity+Description / kubernetes
  pod+namespace), plus a **syscall context** (syscall name + pathname/flags/return-value
  from args).
- Cross-sensor correlation with Falco by `(container_id, pid)` (`cross_sensor.py`).
- Basic MITRE technique mapping from the event name (heuristic confidence, Q3).

## NOT covered (v0.3+)

- **Tetragon** advanced kernel telemetry (Q2 — v0.3).
- Full Tracee event-arg taxonomy beyond pathname/flags/return-value.
- Active baseline **drift** detection (Q5 — passive at v0.2).
- Policy/signature engine integration; the eBPF capability/kernel-version negotiation.

## Honest estimate

**~50–60% `[estimate]`** of the Tracee signal a CWPP consumer wants — solid on the
real-time subscription + syscall context + cross-sensor join, absent on Tetragon, the
full arg taxonomy, and drift. Estimate, not a measured benchmark.
