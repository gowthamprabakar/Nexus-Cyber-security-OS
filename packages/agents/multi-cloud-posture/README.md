# `nexus-multi-cloud-posture-agent`

Multi-Cloud Posture Agent — D.5; **third Phase-1b agent**; **eighth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / **D.5**). Lifts CSPM coverage from AWS-only (F.3) to **Azure + GCP**.

> **Status:** v0.1 bootstrap. See the [D.5 plan](../../../docs/superpowers/plans/2026-05-13-d-5-multi-cloud-posture.md) for the 16-task execution roadmap. This README is replaced with the full operator-facing content at Task 15.

## What it does (target)

Four-feed offline forensic analysis:

- **Azure Defender for Cloud** — findings JSON snapshots
- **Azure Activity Log** — JSON snapshots
- **GCP Security Command Center** — findings JSON snapshots
- **GCP Cloud Asset Inventory IAM** — JSON snapshots

Emits OCSF v1.3 Compliance Findings (`class_uid 2003`) — **identical wire shape to F.3** — with a `CloudProvider` discriminator. Phase 1c adds live SDK calls (`azure-mgmt-security` + `google-cloud-securitycenter`).

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md).
