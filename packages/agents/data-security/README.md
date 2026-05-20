# `nexus-data-security-agent`

Data Security Agent (DSPM) — **D.5**; **first of the 7 unbuilt agents** under the [2026-05-20 Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md); **eleventh under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / **D.5**). Lifts platform coverage from CSPM-only into DSPM — the first agent that discovers + classifies sensitive data at rest.

> **Bootstrap (Task 1) — 2026-05-20.** Package scaffold + pyproject + smoke tests only. No detectors, no classifier, no driver yet. See [`docs/superpowers/plans/2026-05-20-d-5-data-security-v0-1.md`](../../../docs/superpowers/plans/2026-05-20-d-5-data-security-v0-1.md) for the full 16-task plan.

## Scope (v0.1, Option A)

AWS S3 only, offline-mode (boto3 inventory snapshots staged by the operator to filesystem). 4 deterministic detector rules:

- `s3_bucket_public`
- `s3_bucket_unencrypted`
- `s3_object_sensitive_in_untrusted_location`
- `s3_oversharing_iam`

Agent-local PII / sensitive-data classifier (regex + Luhn). F.3 cloud-posture cross-correlation via operator-pinned `--cloud-posture-workspace` flag. Single-tenant (`semantic_store=None` default). Deterministic — no LLM in the loop. **Hard privacy contract: classifier returns label only; matched substring NEVER returned, NEVER logged, NEVER rendered.**

## Deferred to D.5 v0.2 / v0.3 / v0.4 / v0.5+

- **v0.2:** live boto3 SDK calls; classifier expansion (date-of-birth, addresses, healthcare IDs); AWS Macie cross-validation.
- **v0.3:** RDS + DynamoDB + RDS-snapshot scanning.
- **v0.4:** Azure Blob + Azure SQL + GCP Cloud Storage + BigQuery.
- **v0.5+:** Snowflake + EFS + Kinesis; Bedrock / Vertex training-data forensics; Presidio custom classifier engine; toxic-combination detection cross-correlating D.6 / F.3.
- **Multi-tenant production** blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan.

Full version trajectory: [`docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md` §11](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md#11-d5-data-security--dspm-operator-id-conflicts-with-multi-cloud-postures-self-claim).

## ADR-007 conformance

D.5 is the **eleventh** agent under the reference template. Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader`). **Not** in the v1.3 always-on class — D.5 honours every budget axis. **Does not consume** the v1.4 candidate (sub-agent spawning primitive); single-driver per the agent spec.

**Schema reuse (Q1).** D.5 re-exports F.3's `class_uid 2003 Compliance Finding` schema verbatim (lands in Task 2) — `Severity`, `AffectedResource`, `CloudPostureFinding`, `build_finding`, `FindingsReport`, `FINDING_ID_RE`. Adds `DataSecurityFindingType` enum (4 detectors) + `ClassifierLabel` enum (7 labels + NONE) on top.

## Quick start

Package is currently at Bootstrap stage (Task 1). CLI + driver land in Tasks 12 / 14 / 15. To run the smoke tests:

```bash
uv run pytest packages/agents/data-security -q
```

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `cloud-posture`, `eval-framework`) is Apache 2.0; the agent itself is BSL.
