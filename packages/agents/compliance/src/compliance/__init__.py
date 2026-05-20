"""Nexus Compliance Agent — D.6 / Agent #13 under ADR-007.

The third of the 7 unbuilt agents shipped under the 2026-05-20 Path-B-
breadth-first operating rule. Maps sibling-agent findings (F.3 Cloud
Posture + D.5 Data Security) to compliance-framework controls and
emits framework-level compliance findings + a posture-summary report.

Scope (v0.1, locked 2026-05-21):

- 1 framework: CIS AWS Foundations Benchmark v3.0 (~50 paraphrased
  controls bundled as YAML).
- 2 sibling-workspace correlators: F.3 Cloud Posture + D.5 Data
  Security findings, read-only, operator-pinned via per-workspace
  flags.
- Per-control PASS/FAIL roll-up: one ``ComplianceFinding`` per
  (control, status-change) tuple. FAIL if any contributing source-
  finding >= MEDIUM. PASS controls omitted from output in v0.1
  (added in v0.2 for attestation export).
- OCSF v1.3 Compliance Finding (``class_uid 2003``) re-exported from
  ``cloud_posture.schemas`` with
  ``finding_info.types[0]="compliance_cis_aws_v3_<control_id>"``
  discriminator. Deterministic (no LLM in loop).

Seven-stage pipeline:

  INGEST -> ENRICH -> CORRELATE -> AGGREGATE -> SCORE -> SUMMARIZE
  -> HANDOFF

Additional frameworks (SOC2 / PCI-DSS / HIPAA / NIST 800-53), live
F.6 audit-chain read, periodic posture deltas, PASS-finding emission
for attestation export, and multi-tenant production are deferred per
the 2026-05-20 version-roadmap (D.6 v0.2 through v0.5+).
"""

from __future__ import annotations

__version__ = "0.1.0"
