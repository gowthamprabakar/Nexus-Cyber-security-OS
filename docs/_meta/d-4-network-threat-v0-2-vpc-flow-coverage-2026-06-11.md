# D.4 Network Threat v0.2 — VPC Flow Logs Coverage (WI-N1)

**Date:** 2026-06-11 · Measured **per-sensor**, no aggregate (WI-N1).

## Covered at v0.2

- Live **AWS** VPC Flow Logs via CloudWatch Logs (`vpc_flow_realtime_aws.py`) through the
  hoisted charter CredentialResolver (Pattern A), parsing each log event with the shared
  offline parser (v2-v5 field orders) → byte-identical `FlowRecord`s.
- Flow normalization + **source/dest/port aggregation** (`vpc_flow_normalize.py`): roll-up
  by `(src_ip, dst_ip, dst_port, protocol)` with bytes/packets/flow-count + ACCEPT/REJECT.
- Connection-rate (fan-out / sweep) anomaly detection + static-intel uplift (Tor-exit +
  known-bad IPs).

## NOT covered (v0.3+)

- **Azure NSG flow logs** + **GCP VPC flow logs** (Q3 — AWS only at v0.2).
- VPC flow v5 custom fields beyond the v2 superset (pkt-srcaddr, tcp-flags, flow-direction).
- Behavioral baselining of flow volumes (v0.3); microsegmentation recommendations (v0.3).

## Honest estimate

**~40–50% `[estimate]`** of the flow-telemetry signal a network consumer wants — AWS live
ingestion + aggregation + fan-out detection are solid, but Azure/GCP providers, the full
v5 field surface, and behavioral models are deferred. Estimate, not a measured benchmark.
