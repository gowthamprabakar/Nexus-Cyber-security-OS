"""Nexus Data Security Agent — D.5 (DSPM) / Agent #11 under ADR-007.

The first of the 7 unbuilt agents shipped under the 2026-05-20
Path-B-breadth-first operating rule. Lifts platform coverage from
CSPM-only into DSPM — the first agent that discovers and classifies
sensitive data at rest. Emits OCSF v1.3 Compliance Findings
(`class_uid 2003`) — identical wire shape to F.3 cloud-posture +
multi-cloud-posture + k8s-posture — with `finding_info.types[0] =
"data_security"` discriminator + a `DataSecurityFindingType` enum
(4 detectors) on top.

Scope (v0.1, Option A — locked 2026-05-20):

- AWS S3 only, offline-mode (boto3 inventory snapshots staged by
  operator to filesystem).
- 4 deterministic detector rules: s3_bucket_public,
  s3_bucket_unencrypted, s3_object_sensitive_in_untrusted_location,
  s3_oversharing_iam.
- Agent-local PII / sensitive-data classifier (regex + Luhn).
- F.3 cloud-posture cross-correlation via operator-pinned
  `--cloud-posture-workspace` flag.
- Single-tenant (`semantic_store=None` default).
- Hard privacy contract: classifier returns label only; matched
  substring NEVER returned, NEVER logged, NEVER rendered.

Seven-stage pipeline:

  INGEST → CLASSIFY → DETECT → CORRELATE → SCORE → SUMMARIZE → HANDOFF

Live boto3 SDK calls, RDS / DynamoDB scanning, Azure / GCP storage,
Snowflake / Bedrock / Vertex training-data forensics, and multi-tenant
production are deferred per the 2026-05-20 version-roadmap (D.5 v0.2
through v0.5+).
"""

from __future__ import annotations

# data-security v0.2 (Cycle 10 — DSPM; the 5th OCSF 2003 emitter) — Level 1 -> Level 2
# INFRASTRUCTURE: live multi-cloud data discovery (S3 + Azure Blob + GCS, sample-based,
# Q4), expanded PII/PHI/PCI classification (Q2), privacy-framework mapping (GDPR/PCI-DSS/
# HIPAA, Q6), data-residency tracking (Nexus's moat, WI-S10), D.2 IAM consumption (Q5), and
# continuous-monitoring infrastructure. Per Path 1: continuous mode is INFRASTRUCTURE here;
# wiring it into agent.run() is the Phase C consolidated retrofit (NOT a v0.3 carry-forward).
# Privacy invariants are code-level (assert_privacy_contract, privacy hash, residency
# boundary). OCSF emission stays class_uid 2003 Compliance Finding (verified, WI-S5). ADR-010.
__version__ = "0.2.0"
