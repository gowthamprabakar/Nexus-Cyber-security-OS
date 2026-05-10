# `nexus-identity`

Identity Agent — agent **#3 of 18** for Nexus Cyber OS. CIEM (Cloud Infrastructure Entitlement Management) for AWS. **Second consumer of [ADR-007 v1.1](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (the LLM-adapter hoist).

> **Status:** D.2 plan in flight. This README will be expanded as tasks land.

## What it does

Maps AWS principals (IAM users, roles, groups, federated identities) to their effective permissions, surfaces overprivilege, dormant identities, and risky permission paths. Emits OCSF v1.3 Identity / Entitlement Findings (class chosen in D.2 Task 2) wrapped with `NexusEnvelope`, plus a markdown summary that pins high-risk principals at the top, plus a hash-chained audit log.

## License

BSL 1.1 — agent-specific code per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). The runtime substrate (`nexus-charter`, `nexus-eval-framework`) ships under Apache 2.0.

## See also

- [D.2 plan](../../../docs/superpowers/plans/2026-05-11-d-2-identity-agent.md).
- [Cloud Posture Agent](../cloud-posture/) (F.3 reference template).
- [Vulnerability Agent](../vulnerability/) (D.1 second-template validation).
- [`charter.llm_adapter`](../../charter/src/charter/llm_adapter.py) — shared LLM adapter (no per-agent `llm.py`).
