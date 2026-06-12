# `nexus-audit-agent`

Audit Agent — agent **#14 of 18** for Nexus Cyber OS. The append-only hash-chained log writer the other agents cannot disable. **Last Phase-1a foundation pillar** ([F.6](../../../docs/superpowers/plans/2026-05-12-f-6-audit-agent.md)) — closes the Phase-1a substrate (F.1–F.6 ✓).

> **v0.2 — operator Cycle 11 (`__version__` 0.1.0 → 0.2.0, 2026-06-12).** The institutional-integrity cycle; audit is the **first OCSF 6003 (API Activity) emitter** — the fleet now has **10 OCSF emitters** across 3 classes (5×2003 + 4×2004 + 1×6003). Keeping the offline `run()`/6003 eval byte-identical (WI-F5), this cycle adds: **cross-agent audit aggregation** (`aggregation/` — enumerate + verify + tenant-isolate + time-order chains across the 10 closed-cycle agents → unified OCSF 6003); a **Merkle indexing layer** (`merkle/` — tree + O(log n) membership proofs); **tamper detection + alerts** (`tamper/` — categorized: genesis/missing-entry/hash-mismatch/timestamp-skew; an OCSF 6003 alert always surfaces on a break, **never auto-repair**, WI-F2/F9); a **broad typed query filter** (`query/` — time-range + tenant + action + agent-id + status); **compliance-evidence integration** (`compliance_integration/` — Merkle proofs tie each compliance finding to its source audit entry, with a downstream verify API; consumes compliance v0.2 #477); and code-level **read-only** (`readonly.assert_audit_readonly`, WI-F8) + **cross-tenant admin** (`tenant_authz.assert_admin_for_cross_tenant`, WI-F11) invariants. Single gated lane `NEXUS_LIVE_AUDIT` (WI-F4 e2e). Setup: [`runbooks/`](runbooks/); per-source coverage (no aggregate, WI-F1) + the closure record under `docs/_meta/audit-v0-2-*`.
>
> **F.6 deviation profile — PRESERVED (WI-F10).** F.6 is the **always-on class** (ADR-007 v1.3): it reads the audit log **directly**, intentionally outside the budget gate, via the **single** standing `BY_DESIGN_EXEMPT` tool-proxy entry. v0.2 added **no new exemptions** — the institutional auditor that other agents cannot disable also cannot be turned into a chain-rewriter (the read-only invariant makes an accidental mutation fail loudly).
>
> **Honest scope (WI-F3 / Path 1):** continuous monitoring is **INFRASTRUCTURE** at v0.2; wiring it into the agent's `run()` loop is the **Phase C consolidated retrofit** (after all 17 v0.2 cycles), NOT a v0.3 carry-forward. Sigstore-style epoch signing (Q2), a SQL-like query DSL (Q3), and external SIEM forwarders (Q1) are v0.3+. Automatic chain repair is **never** built (architectural invariant).

## What it does

Wraps the per-invocation audit primitives (`charter.audit.AuditLog`, `charter.verifier.verify_audit_log`) and the [F.5 memory-engine](../../charter/src/charter/memory/) audit emissions (`episode_appended` / `playbook_published` / `entity_upserted` / `relationship_added`) as a **queryable surface for compliance teams**. Emits [OCSF v1.3 API Activity](../../../docs/_meta/decisions/ADR-009-memory-architecture.md) (`class_uid 6003`) — the canonical OCSF class for action-records, with the chain hashes riding in the `unmapped` slot.

Operators ask questions like:

```bash
audit-agent query \
    --tenant 01HV0T0000000000000000TENA \
    --workspace /tmp/audit-ws \
    --source /var/log/nexus/audit-2026-05-01.jsonl \
    --since 2026-05-01 \
    --action episode_appended \
    --agent-id cloud_posture \
    --format markdown
```

The hash chain is verified end-to-end on every read. A detected tamper pins at the top of the markdown report (above the per-action sections) and exits the CLI with **status 2** — a downstream cron job's pipeline can distinguish "tooling failure (1)" from "tamper (2)" without parsing stderr.

## ADR-007 conformance

Built against the [reference NLAH template](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) — fifth agent under it (F.3 / D.1 / D.2 / D.3 / **F.6**). Introduces **ADR-007 v1.3** — the **always-on agent class**. An always-on agent honours only `wall_clock_sec` from its `BudgetSpec`; every other budget axis logs a structlog warning and proceeds. F.6 is the first member; the allowlist (one entry) lives in `charter.audit` in v0.1.

## Quick start

```bash
# 1. Run the local eval suite (10/10 should pass)
uv run audit-agent eval packages/agents/audit/eval/cases

# 2. Run via the eval-framework (resolves through nexus_eval_runners entry-point)
uv run eval-framework run --runner audit --cases packages/agents/audit/eval/cases

# 3. Drive against an ExecutionContract — ingest + report
uv run audit-agent run \
    --contract path/to/contract.yaml \
    --source /var/log/nexus/audit-2026-05-01.jsonl \
    --source /var/log/nexus/audit-2026-05-02.jsonl

# 4. Query for compliance — operator-facing
uv run audit-agent query \
    --tenant 01HV0T0000000000000000TENA \
    --workspace /tmp/audit-ws \
    --source /var/log/nexus/audit-2026-05-01.jsonl \
    --since 2026-05-01 \
    --until 2026-05-31 \
    --format markdown
```

See [`runbooks/audit_query_operator.md`](runbooks/audit_query_operator.md) for the full operator workflow.

## Architecture

```
F.5 audit emissions ──┐
charter.audit.jsonl ──┼──→ audit-agent ingest ──→ Postgres `audit_events` (RLS-scoped)
control_plane.auth ──┘                              │
                                                    ▼
compliance team / Meta-Harness ──→ audit-agent query (5-axis filter)
                                                    │
                                          chain integrity verified
                                          via charter.verifier on every read
```

Two ingest tools — `audit_jsonl_read` (filesystem chain) and `episode_audit_read` (F.5 `episodes` table) — fan out concurrently via `asyncio.TaskGroup` in the agent driver. Both emit the same `AuditEvent` shape; the F.6 chain verifier handles jsonl in sequential mode (full chain-link enforcement) and memory in non-sequential mode (per-entry hash recompute only — the episodes table isn't chain-structured in F.5).

The Postgres-backed [`audit_events`](../../charter/src/charter/memory/models.py) table sits alongside F.5's four memory tables in one alembic head (`alembic_version_memory`). Per-tenant Row-Level Security ships in the `0003_audit_events` migration; `MemoryService.session(tenant_id=...)`'s `SET LOCAL` plumbs the active tenant through. `(tenant_id, entry_hash)` UNIQUE → idempotent re-ingest at the schema level.

## Output contract

Three artifacts land in the charter-managed workspace:

| File          | Format                                | Purpose                                                                                                                     |
| ------------- | ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `report.md`   | Markdown                              | Operator summary — chain integrity → volume by action → volume by agent → tamper pin (only on break) → per-action sections. |
| `events.json` | `AuditQueryResult.model_dump_json()`  | Wire shape consumed by Meta-Harness, Investigation, and downstream tools.                                                   |
| `audit.jsonl` | `charter.audit.AuditEntry` JSON-lines | The Audit Agent's own chain entry for this run. The auditor can audit the auditor.                                          |

## Tests

```bash
uv run pytest packages/agents/audit -q
```

129 tests, 96% coverage on `audit/*`. Skip-by-default integration test against live Postgres is in `charter/tests/integration/` (gated by `NEXUS_LIVE_POSTGRES=1`).

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). The substrate this agent consumes (`charter`, `eval-framework`) is Apache 2.0; the agent itself is BSL.
