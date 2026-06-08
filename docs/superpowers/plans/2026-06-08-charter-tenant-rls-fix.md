# Charter tenant-RLS fix — Implementation Plan (`set_config` + cross-agent regression sweep)

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement task-by-task. **Pause for operator review after each numbered task** (ADR-011). **Task 1 is SAFETY-CRITICAL** (charter substrate) — no auto-merge; verify against merged-branch HEAD.

**Goal:** Fix the `SET LOCAL app.tenant_id = $1` tenant-RLS bug at [`charter/memory/service.py:96`](../../../packages/charter/src/charter/memory/service.py) — `SET LOCAL` → **`SELECT set_config('app.tenant_id', :tid, true)`** — restoring multi-tenant row-level-security on real Postgres, proven end-to-end against an actual Postgres instance. Parallel SAFETY-CRITICAL substrate cycle under γ sequencing.

**Label:** LOW-RISK (this plan doc). The cycle itself is **1 SAFETY-CRITICAL task (the fix) + 3 LOW-RISK tasks** (regression proof, live-doc updates, verification).

**Why this matters:** unblocks multi-tenant RLS and the **v2.0 security-graph substrate** — the single largest residual Wiz gap (~14–19 weighted pts, [PR #245 benchmark §7](../../_meta/competitive-benchmark-2026-06-08.md)). A single-line charter change that unblocks ~half the Wiz-comparison story.

**Verification bar:** the gated **`NEXUS_LIVE_POSTGRES=1`** suite green **end-to-end against actual Postgres** (not a SQLAlchemy mock) — [`test_memory_live_postgres.py`](../../../packages/charter/tests/integration/test_memory_live_postgres.py) goes from **1 PASS / 5 FAIL → all green**, plus 2 new RLS tests.

**Effort:** ~1–2 weeks (the fix is hours; the real-Postgres proof + live-doc sweep + verification carry the rest).

**Source brainstorm:** [`2026-06-07-charter-tenant-rls-fix-brainstorm.md`](../brainstorms/2026-06-07-charter-tenant-rls-fix-brainstorm.md) (PR #247, merged). This plan decomposes its §6 under the locked §5 Q-locks.

---

## Operator-confirmed Q-locks

| #      | Lock                                                                                          | Plan consequence                                                                                                                                                                                               |
| ------ | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Q1** | **Honest-minimal regression scope** — charter RLS tables + `audit_events`, NOT 5-agent wiring | Task 2 proves the charter substrate + the `audit_events` policy. Wiring None-defaulted agents (A.4/Compliance/D.7) is **out of scope** (each agent's own v0.2).                                                |
| **Q2** | **Policy test now; F.6 GUC-rewire is a fast-follow**                                          | Task 2 adds an `audit_events` RLS isolation test at the charter/Postgres level. **F.6's read-path rewire** (route reads through the GUC for true enforcement) is a documented fast-follow, **not this cycle**. |
| **Q3** | **Live docs only; preserve dated records**                                                    | Task 3 updates living docs (roadmap sketch, ADR-006, `service.py` docstring, ~8 agent READMEs). **No** edits to dated verification records / plans; the merged benchmark gets a **footnote**, not a body edit. |
| **Q4** | **Keep `semantic_store=None` guards**                                                         | The no-op-with-log guards stay — still-correct defensive scaffolding until each agent wires multi-tenant. **Not removed** this cycle.                                                                          |
| **Q5** | **Add the missing `relationships` RLS test**                                                  | Task 2 adds the 4th-table isolation test (`episodes`/`playbooks`/`entities` exist; `relationships` was missing).                                                                                               |

---

## The fix (Task 1, in full)

```python
# packages/charter/src/charter/memory/service.py  (session() ctx mgr, ~line 96)
# BEFORE:
await session.execute(
    text("SET LOCAL app.tenant_id = :tid").bindparams(tid=tenant_id)
)
# AFTER:
await session.execute(
    text("SELECT set_config('app.tenant_id', :tid, true)").bindparams(tid=tenant_id)
)
```

`set_config(name, value, is_local=true)` is the **parameter-safe** equivalent of `SET LOCAL`; the `true` (is_local) argument scopes the GUC to the transaction (reverts on COMMIT/ROLLBACK) — **behaviorally identical**, no edge-case difference (rollback / savepoint / txn-mode pooling all safe; statement-mode pooling breaks the same way `SET LOCAL` already did and is documented must-not-use). The docstring at lines 86–90 is updated to describe `set_config`. **Single-file change** — `grep` confirmed no other `SET LOCAL` sites; the 5 RLS policies already read `current_setting('app.tenant_id', true)` correctly.

**5 RLS policies satisfied:** `episodes` / `playbooks` / `entities` / `relationships` ([`0002_memory_rls.py:52-72`](../../../packages/charter/alembic/versions/)) + `audit_events` ([`0003_audit_events.py:95-99`](../../../packages/charter/alembic/versions/)).

---

## Depends on / Defers

**Depends on:** the F.5 LTREE substrate-fix precedent (same real-Postgres CI lane, `charter-f5-live.yml` / `NEXUS_LIVE_POSTGRES=1`); ADR-009 memory architecture; ADR-011 cadence.

**Defers (out of scope — honor the Q-locks):**

- **F.6 Audit read-path GUC-rewire** (true RLS enforcement on `audit_events` reads) → **fast-follow** (Q2). F.6 reads currently bypass the seam with app-side filtering; this cycle proves the _policy_, not the F.6 rewire.
- **Per-agent `semantic_store` wiring** (A.4 Meta-Harness, Compliance, D.7 Investigation) → each agent's own v0.2 (Q1). The fix _unblocks_ them; wiring is agent work.
- **Removing the `semantic_store=None` no-op guards** → not done (Q4).
- **Agent source-docstring / NLAH-README sweep** → rides with each agent's wiring cycle (Q3).
- **v2.0 security-graph design** → Track 3, after this lands.
- **Any other charter fix · Wazuh · detection-agent work** → not this cycle.

## Cross-cutting concerns

1. **SAFETY-CRITICAL discipline on Task 1:** full review; verify against merged-branch HEAD; operator approval gate; the substrate-seal guard tripping _is the seal working_.
2. **Verification against actual Postgres**, never a SQLAlchemy mock — the gated live suite is the proof.
3. **No retro-editing dated records** (Q3) — verification records, plan docs, brainstorms stay as written; the merged benchmark gets a footnote only.
4. **No agent-wiring scope creep** (Q1) — if a task starts wiring `semantic_store` into an agent, it has left scope → STOP.

## Risks

1. **Revert safety:** one-line change → one-line revert if the live suite regresses.
2. **Real-Postgres lane availability:** the proof needs Postgres 16 + pgvector up (`docker compose -f docker/docker-compose.dev.yml up -d postgres`; `NEXUS_LIVE_POSTGRES=1`). Operator-run or the `charter-f5-live.yml` CI lane.
3. **Connection-pool mode:** txn-mode pooling required (statement-mode breaks GUCs) — already documented in the memory bootstrap runbook; verification notes the assumption.

---

## Tasks

> Task 1 SAFETY-CRITICAL; Tasks 2–4 LOW-RISK. Each task = one PR (ADR-011), no auto-merge.

|     # | Risk                | Title                                        | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ----: | ------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|  Plan | LOW-RISK            | Plan doc                                     | This document.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **1** | **SAFETY-CRITICAL** | The fix — `SET LOCAL` → `set_config`         | One-line change at [`service.py:96`](../../../packages/charter/src/charter/memory/service.py) + docstring (lines 86–90) update. **Charter substrate touch.** No auto-merge; verify against merged-branch HEAD; expect the substrate-seal guard. ~existing unit tests stay green (aiosqlite silently skips; behavior unchanged off-Postgres).                                                                                                                                                                                                                                                                                                                                                                                                            |
|     2 | LOW-RISK            | Charter RLS regression proof (real Postgres) | Bring [`test_memory_live_postgres.py`](../../../packages/charter/tests/integration/test_memory_live_postgres.py) green (1/6 → 6/6). **Add** the missing `relationships` RLS isolation test (Q5) **and** an `audit_events` RLS isolation test (Q2 — proves the policy; tenant A's events invisible to tenant B via raw SQL). Keystone: `NEXUS_LIVE_POSTGRES=1` → **8 tests green**.                                                                                                                                                                                                                                                                                                                                                                      |
|     3 | LOW-RISK            | Live-doc updates (Q3)                        | Remove the "multi-tenant blocked by SET LOCAL" caveat from **living** docs only: [`agent-version-roadmaps` sketch](../sketches/2026-05-20-agent-version-roadmaps.md) (master blocked-agent map), [ADR-006](../../_meta/decisions/ADR-006-openai-compatible-provider.md), the `service.py` docstring, and the ~8 user-facing agent READMEs (synthesis/compliance/curiosity/data-security/threat-intel/meta-harness/supervisor). **Preserve** dated verification records + plan docs unchanged; add a one-line **footnote** to [`competitive-benchmark-2026-06-08.md`](../../_meta/competitive-benchmark-2026-06-08.md) ("compiled while the bug was open; fixed in PR #NNN") — do **not** edit its body. **Keep** the `semantic_store=None` guards (Q4). |
|     4 | LOW-RISK            | Verification record + closure                | `docs/_meta/charter-tenant-rls-fix-verification-2026-XX-XX.md`: the fix proven **end-to-end against actual Postgres** (8 live tests green); RLS isolation confirmed across all 4 memory tables + `audit_events`; multi-tenant trust restored for charter + the `audit_events` policy; **v2.0 security-graph substrate dependency unblocked**; deferred handoffs recorded (F.6 GUC-rewire fast-follow per Q2; per-agent `semantic_store` wiring to each agent's v0.2; `None`-guards retained per Q4).                                                                                                                                                                                                                                                    |

---

## File map (target)

```
packages/charter/src/charter/memory/service.py          # Task 1 — the fix + docstring (SAFETY-CRITICAL)
packages/charter/tests/integration/test_memory_live_postgres.py   # Task 2 — +relationships +audit_events RLS tests
docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md    # Task 3 — unblock the master map
docs/_meta/decisions/ADR-006-openai-compatible-provider.md       # Task 3 — drop "blocked on SET LOCAL" clause
packages/agents/{synthesis,compliance,curiosity,data-security,threat-intel,meta-harness,supervisor}/README.md  # Task 3
docs/_meta/competitive-benchmark-2026-06-08.md          # Task 3 — footnote only (NO body edit)
docs/_meta/charter-tenant-rls-fix-verification-2026-XX-XX.md (NEW)  # Task 4
```

**Not touched:** dated verification records + plan docs (historical truth); agent source docstrings / NLAH READMEs / `None`-guards (ride with each agent's wiring cycle); any non-RLS charter code.

## Watch-items (carry-forward to verification record)

- **WI-1** — Task 1 is the only substrate touch; the seal is otherwise empty.
- **WI-2** — F.6 audit read-path GUC-rewire is a tracked **fast-follow** (Q2), not closed by this cycle.
- **WI-3** — per-agent `semantic_store` wiring (A.4/Compliance/D.7) handed to each agent's v0.2 (Q1).
- **WI-4** — connection-pool mode assumption (txn-mode) recorded; statement-mode remains unsupported.
- **WI-5** — `None`-guards retained (Q4); their removal rides with each agent's wiring cycle.

## Done definition

1. `service.py:96` uses `set_config('app.tenant_id', :tid, true)`; docstring updated.
2. `NEXUS_LIVE_POSTGRES=1` suite green **end-to-end against actual Postgres** — all existing 5 + new `relationships` + new `audit_events` RLS tests (8 total) pass.
3. RLS isolation proven (tenant A cannot read tenant B's rows via raw SQL) across `episodes`/`playbooks`/`entities`/`relationships` + `audit_events`.
4. Living docs updated; dated records preserved; benchmark footnoted; `None`-guards retained.
5. Verification record filed; v2.0-graph dependency marked unblocked; fast-follow + wiring handoffs recorded.

## ADR-011 cadence

- **Task 1 SAFETY-CRITICAL:** no auto-merge; verify against merged-branch HEAD; operator approval gate; expect the substrate-seal guard.
- **Tasks 2–4 LOW-RISK:** standard review; CI green on required checks; per-task PR. The live-Postgres proof (Task 2) is the keystone gate before Tasks 3–4.

## Reference template

The **F.5 LTREE substrate-fix** cycle (same shape: a single charter substrate fix, proven against the real-Postgres `NEXUS_LIVE_POSTGRES=1` lane, with a tight regression proof and doc closure). This cycle is structurally that, on a one-line change.

---

— drafted 2026-06-08 (charter tenant-RLS fix plan; parallel SAFETY-CRITICAL substrate cycle under γ sequencing).
