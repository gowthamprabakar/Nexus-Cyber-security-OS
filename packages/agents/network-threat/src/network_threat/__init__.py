"""Nexus Network Threat Agent — D.4 / Agent #6.

The second Phase-1b agent and the seventh under ADR-007 (F.3 / D.1 / D.2 /
D.3 / F.6 / D.7 / D.4). Mirrors D.3's three-feed pattern, applied to the
network domain instead of the workload domain.

Three input feeds (concurrent via TaskGroup):
  - Suricata alert ndjson (rule-based IDS)
  - AWS VPC Flow Logs v5 (operator-pinned filesystem source)
  - DNS logs (BIND query log + Route 53 Resolver Query Logs)

Three detectors:
  - port_scan — connection-rate heuristic
  - beacon    — periodicity analysis (in-memory single-window)
  - dga       — entropy + n-gram heuristic

Six-stage pipeline:
  INGEST → PATTERN_DETECT → ENRICH → SCORE → SUMMARIZE → HANDOFF

Output: OCSF v1.3 Detection Finding (class_uid 2004) with
`types[0]="network_threat"` discriminator. v0.1 emits findings only;
Tier-1 block actions (block_ip_at_waf) deferred to Phase 1c (need
Track-A WAF substrate).
"""

from __future__ import annotations

# D.4 Network Threat v0.2 (Cycle 7 — Group A real-time-class consumer #2, inherits the
# D.3 precedent) — Level 1 -> Level 2: live Suricata + Zeek real-time subscription + live
# AWS VPC flow logs, cross-sensor correlation, DGA/beacon refinement, and a TTL-bounded
# auto-expiring IP-block action (Q4 safety invariant; no permanent/private-range blocks).
# ADR-010 version-extension bump. OCSF emission stays class_uid 2004 (verified, WI-N5).
__version__ = "0.2.0"
