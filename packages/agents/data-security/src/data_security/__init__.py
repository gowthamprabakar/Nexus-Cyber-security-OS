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

__version__ = "0.1.0"
