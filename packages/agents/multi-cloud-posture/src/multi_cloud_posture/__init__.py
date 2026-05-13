"""Nexus Multi-Cloud Posture Agent — D.5 / Agent #8 under ADR-007.

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
"""

from __future__ import annotations

__version__ = "0.1.0"
