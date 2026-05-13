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

__version__ = "0.1.0"
