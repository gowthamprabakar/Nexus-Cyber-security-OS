# `nexus-network-threat-agent`

Network Threat Agent — agent **#6 of 18** for Nexus Cyber OS. **Seventh agent under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / **D.4**). Second Phase-1b agent; mirrors D.3's three-feed pattern, applied to the network domain.

> **Status:** v0.1 bootstrap. See the [D.4 plan](../../../docs/superpowers/plans/2026-05-13-d-4-network-threat-agent.md) for the 16-task execution roadmap. This README is replaced with the full operator-facing content at Task 16.

## What it does (target)

Three-feed network-threat surface:

- **Suricata** — rule-based IDS alert ndjson (offline-mode in v0.1).
- **VPC Flow Logs v5** — AWS native flow records (operator-pinned filesystem source).
- **DNS logs** — BIND query log + AWS Route 53 Resolver Query Logs.

Three detectors: `port_scan` / `beacon` / `dga`. DGA uses entropy + n-gram heuristic in v0.1 (ML model deferred to Phase 1c). Output: OCSF v1.3 Detection Finding (`class_uid 2004`, `types[0]="network_threat"`) per detection, plus a markdown report with beacons and DGA domains pinned above per-section sections.

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md).
