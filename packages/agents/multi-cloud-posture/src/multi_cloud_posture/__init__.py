"""Nexus Multi-Cloud Posture Agent — D.15 / Agent #8 under ADR-007.

The third Phase-1b agent. Lifts CSPM coverage from AWS-only (F.3) to
Azure + GCP. Emits OCSF v1.3 Compliance Findings (`class_uid 2003`) —
identical wire shape to F.3 cloud-posture — with a `CloudProvider`
discriminator on `finding_info.types[0]`.

Four-feed shape (offline filesystem mode in v0.1):

- Azure Defender for Cloud findings JSON
- Azure Activity Log JSON
- GCP Security Command Center findings JSON
- GCP Cloud Asset Inventory IAM JSON

Five-stage pipeline:

  INGEST → NORMALIZE → SCORE → SUMMARIZE → HANDOFF

Live SDK calls (`azure-mgmt-security`, `azure-mgmt-monitor`,
`google-cloud-securitycenter`, `google-cloud-asset`) are deferred to
Phase 1c. v0.1 reads operator-pinned filesystem snapshots — mirrors
F.3 (LocalStack) + D.4 (filesystem-only) patterns.

v0.2 (Level 2 — live Azure + GCP). Per the v0.2 plan
(docs/superpowers/plans/2026-06-09-d-5-multi-cloud-posture-v0-2.md), an ADR-010
version-extension: live Azure + GCP SDKs, single-subscription / single-project
credential resolution + discovery + region scoping, native rule engines (Azure
from zero, GCP expanded), and Defender/SCC provenance tagging — additive only,
with the OCSF 2003 wire shape + offline eval cases byte-stable. D.15 imports the
cloud-agnostic seams directly from `cloud_posture` (2nd consumer; no charter
hoist — that fires at D.2 per ADR-007).
"""

from __future__ import annotations

__version__ = "0.2.0"
