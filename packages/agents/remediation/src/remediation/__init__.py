"""Nexus Remediation Agent — A.1 / Agent #10 under ADR-007.

The **first "do" agent** in the platform. Closes the detect→cure loop by
generating + optionally executing remediation artifacts from OCSF findings
produced by any detect agent (initially D.6 Kubernetes Posture; v0.2+
expands to D.1 / F.3 / D.5).

Three operational modes (per the 2026-05-16 user direction "make it
production action"):

- **`recommend`** (default; lowest blast radius) — generate artifacts only.
- **`dry-run`** — apply against `kubectl --dry-run=server`; reports diff.
- **`execute`** — apply for real, with mandatory rollback-timer + post-validation.

Seven-stage pipeline:

  INGEST → AUTHZ → GENERATE → DRY-RUN → EXECUTE → VALIDATE → ROLLBACK

Each mode runs a subset of stages (see `runbooks/remediation_workflow.md`
for the mode/stage matrix).

Safety primitives (Tier-1 essentials applied across all modes):

- Pre-authorized action allowlist (in ExecutionContract)
- Mode-escalation gate (dry-run + execute require explicit contract auth)
- Blast-radius cap (max_actions_per_run; default 5)
- Mandatory dry-run before execute
- Rollback timer + post-validation (re-run detector; auto-revert on failure)
- Hash-chained audit per stage (pre/post-patch SHA-256)
- Idempotency (correlation_id derived from source finding ID)
- Workspace-scoped state
- 3-way cluster-access exclusion (artifact-target / kubeconfig / in-cluster)

Emits OCSF v1.3 Compliance / Remediation Activity (`class_uid 2007`) —
**first agent to produce this class.** Downstream consumers (D.7 / fabric
/ Meta-Harness / S.1 console when shipped) subscribe to this class.

Plan: `docs/superpowers/plans/2026-05-16-a-1-remediation-agent.md`.
"""

from __future__ import annotations

__version__ = "0.1.0"
