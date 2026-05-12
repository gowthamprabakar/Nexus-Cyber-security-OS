# `nexus-audit-agent`

Audit Agent — agent **#14 of 18** for Nexus Cyber OS. The append-only hash-chained log writer the other agents cannot disable. **Last Phase-1a foundation pillar** ([F.6](../../../docs/superpowers/plans/2026-05-12-f-6-audit-agent.md)).

## What it does

Wraps the existing per-invocation audit primitives (`charter.audit.AuditLog`, `charter.verifier.verify_audit_log`) and the [F.5 memory-engine](../../charter/src/charter/memory/) audit emissions (`episode_appended` / `playbook_published` / `entity_upserted` / `relationship_added`) as a **queryable surface for compliance teams**.

Operators ask questions like:

```bash
audit-agent query \
    --tenant 01HV0... \
    --since 2026-05-01 \
    --action episode_appended \
    --agent-id cloud_posture \
    --format markdown
```

Output formats: `markdown` (default), `csv`, `json`. The hash chain is verified end-to-end on every read; a detected tamper is pinned at the top of the report and exits the CLI with status 2.

## ADR-007 conformance

Built against the [reference NLAH template](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) — fifth agent under it (F.3 / D.1 / D.2 / D.3 / **F.6**). Introduces ADR-007 v1.3: the **always-on agent class**. An always-on agent honours only `wall_clock_sec` from its `BudgetSpec`; every other budget axis logs a structlog warning and proceeds. F.6 is the first member of the class; the allowlist (one entry) lives in `charter.audit`.

## Quick start

```bash
# 1. Run the local eval suite (10/10 should pass)
uv run audit-agent eval packages/agents/audit/eval/cases

# 2. Run via the eval-framework (resolves through nexus_eval_runners entry-point)
uv run eval-framework run --runner audit --cases packages/agents/audit/eval/cases

# 3. Query the production audit chain
uv run audit-agent query --tenant <tenant_id> --since 2026-05-01
```

See [`runbooks/audit_query_operator.md`](runbooks/audit_query_operator.md) for the full operator workflow.
