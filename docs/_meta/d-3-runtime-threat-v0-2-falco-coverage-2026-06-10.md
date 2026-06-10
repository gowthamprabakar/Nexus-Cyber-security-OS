# D.3 Runtime Threat v0.2 — Falco Sensor Coverage (WI-R1)

**Date:** 2026-06-10 · Measured **per-sensor**, no aggregate (WI-R1).

## Covered at v0.2

- Live Falco **real-time** event subscription (push, gRPC outputs service) via
  `FalcoRealtimeSubscriber` — bounded-queue backpressure + graceful shutdown, alongside
  the v0.1 offline `falco_alerts_read` (heartbeat coexists, Q1).
- Rule-pack management (`falco/rule_packs.py`): default pack + custom packs + atomic
  hot-reload.
- Live normalization (`falco_normalize.py`): rule/priority/time + **process-tree**
  (proc.name/pid/ppid/pname/cmdline) + **container/k8s** (container.id/image/name,
  k8s.pod/ns) context, byte-identical to the offline `FalcoAlert`.
- Basic MITRE technique mapping from rule + tags (heuristic confidence, Q3).

## NOT covered (v0.3+)

- Falco **field-level** detail beyond proc/container/k8s + fd.name (full output_fields
  taxonomy, syscall args).
- Real-time **preempt** of the heartbeat (Q1 — both modes coexist at v0.2; preempt v0.3).
- Active baseline **drift** detection on the collected data (Q5 — passive at v0.2).
- Plugins / source-plugin events; the modern Falco JSON schema variants beyond the
  parsed core.

## Honest estimate

**~55–65% `[estimate]`** of the Falco signal a CWPP consumer wants — strong on the
real-time subscription + process/container context + the rule→technique core, absent on
deep field extraction, drift, and preempt. Estimate, not a measured benchmark.
