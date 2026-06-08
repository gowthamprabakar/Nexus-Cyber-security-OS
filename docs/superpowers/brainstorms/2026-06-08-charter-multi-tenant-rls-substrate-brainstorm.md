# Charter multi-tenant RLS substrate — 4-bug investigation (Brainstorm) — 2026-06-08

> **DRAFT ONLY.** No plan doc, no execution. The `set_config` fix (PR #251) is merged; this brainstorm scopes the **remaining 3 substrate bugs** that block the live-Postgres RLS keystone into ONE coherent cycle. Operator reviews after F.3 v0.2 Task 2 ships.

- **Status:** brainstorm — investigation + Q-lock surfacing. Awaiting operator review; **do not draft the plan doc yet.**
- **Branch:** `docs/charter-multi-tenant-rls-substrate-brainstorm`
- **Scope:** the charter memory substrate's live-Postgres RLS proof — fix the 3 remaining bugs so `NEXUS_LIVE_POSTGRES=1` reaches **6 passed**. No detection-agent work, no v2.0 graph, no Wazuh.
- **Why one cycle:** none of the 3 can be live-verified in isolation — the live suite fails in _setup_ (LTREE) before reaching pgvector or RLS, and RLS can't be demonstrated until both LTREE and the role model are fixed. The 6/6 keystone only exists when all land together.
- **Evidence:** the real-Postgres lane (PR #252, `charter-f5-live.yml`) run against the merged `set_config` fix: [run 27116108088](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/27116108088) (6 errors, LTREE) → [run 27116230656](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/27116230656) (+LTREE fix → **2 passed / 4 failed**).
- **Sources:** [`models.py`](../../../packages/charter/src/charter/memory/models.py) · [`0002_memory_rls.py`](../../../packages/charter/alembic/versions/) · [`test_memory_live_postgres.py`](../../../packages/charter/tests/integration/test_memory_live_postgres.py) · F.5 LTREE stack (PRs #43–#51) · the SET LOCAL fix plan/brainstorm.

---

## §0. Executive summary — the live RLS keystone is blocked by 4 bugs, not 1

The SET LOCAL plan assumed "1 PASS / 5 FAIL → 6 PASS after the `set_config` fix." That premise was **wrong**: the 5 failures were never SET LOCAL failures. Empirically, after the merged `set_config` fix **and** the LTREE fix, the suite is **2 passed / 4 failed**, and the 4 are pre-existing substrate bugs:

| #   | Bug                                    | Where                                                                            | Blocks                   | Status                                    |
| --- | -------------------------------------- | -------------------------------------------------------------------------------- | ------------------------ | ----------------------------------------- |
| 1   | **`postgresql.LTREE` AttributeError**  | [`models.py:106`](../../../packages/charter/src/charter/memory/models.py)        | all 6 tests (in _setup_) | **fix exists but orphaned off main** (§1) |
| 2   | **pgvector `cosine_distance` missing** | `_PortableVector` TypeDecorator                                                  | the ANN test             | pre-existing (§2)                         |
| 3   | **RLS not enforced**                   | [`0002_memory_rls.py`](../../../packages/charter/alembic/versions/) + role model | the 3 RLS tests          | pre-existing (§3)                         |
| 4   | **SET LOCAL → `set_config`**           | `service.py:96`                                                                  | (the GUC plumbing)       | ✅ **merged (PR #251)**                   |

**Bug 4 is necessary but far from sufficient.** The live RLS proof is a multi-bug substrate effort. §1–§4 below; Q-locks in §5; memory-note correction in §7.

---

## §1. Axis 1 — LTREE: the orphaned-stack archaeology

**Bug:** `models.py:106` calls `dialect.type_descriptor(postgresql.LTREE())`, but `postgresql.LTREE` does **not exist in any SQLAlchemy 2.0.x** (confirmed: 2.0.50 raises `ImportError`). It only fires on the Postgres path, so unit (aiosqlite) tests pass and every live test errors in setup. The operator's "SQLAlchemy too old" reading is a **red herring** — no version has `postgresql.LTREE`; the code is simply wrong.

**The fix already exists — `acfc830`** (F.5 LTREE Task 2): a private `_LtreeColumn(UserDefinedType[str])` that emits `LTREE` DDL, used in `_PortableLtree.load_dialect_impl`'s Postgres branch. **Why it isn't on main:**

- F.5 LTREE shipped as a **stacked-PR chain**: Task 2 (PR #45, the fix) was based on **Task 1's branch** (`feat/f5-ltree-task-1-grep-audit`), not main. PR #45 shows **MERGED** — but it merged into **#44's branch**, and **PR #44 (the stack base) is still OPEN / never merged to main.** So the whole stack (Tasks 2/3/6/7 merged _into each other_; Tasks 1/4/5/8 still OPEN) **never reached main.**
- Net: the SAFETY-CRITICAL LTREE fix was "merged" within the stack and **silently orphaned** off main. `git merge-base --is-ancestor acfc830 origin/main` = **NO**.

**Revival path:** cherry-pick `acfc830` (models.py, +25/−2, clean — proved in lane run 27116230656) onto a fresh branch off current main, plus its companion mocked tests (PR #46's content). Do **not** try to untangle the abandoned stack. → **Q1.**

## §2. Axis 2 — pgvector `cosine_distance`

**Bug:** `test_pgvector_ann` fails with `AttributeError: ... EpisodeModel.embedding ... no attribute 'cosine_distance'`. The `embedding` column uses `_PortableVector(TypeDecorator, impl=JSON)` whose `load_dialect_impl` returns `pgvector.sqlalchemy.Vector(dim)` on Postgres. The **DDL type** is correct (Vector), but a `TypeDecorator` does **not** proxy the wrapped type's custom comparator, so the ORM attribute `EpisodeModel.embedding` exposes the `impl=JSON` comparator — which has no `cosine_distance` / `l2_distance` / `max_inner_product`.

**Fix shape:** give `_PortableVector` a `comparator_factory` (or `class Comparator(TypeDecorator.Comparator)`) that proxies pgvector's distance operators on Postgres, so `search_similar`'s `.cosine_distance(...)` resolves. Preserves the aiosqlite JSON fallback. (Alternative: use `Vector` directly for the column and drop portability — heavier.) → **Q2.**

## §3. Axis 3 — RLS not enforced (FORCE + non-superuser role)

**Bug:** the 3 RLS tests fail with tenant B seeing tenant A's rows (`assert [1] == []`) **even with `set_config` working**. Root cause is twofold:

1. [`0002_memory_rls.py`](../../../packages/charter/alembic/versions/) uses `ALTER TABLE … ENABLE ROW LEVEL SECURITY` but **not `FORCE`** — the **table owner bypasses RLS** without `FORCE`.
2. Both the app and the test connect as **`nexus`**, which the postgres image creates as a **SUPERUSER** — and **superusers bypass RLS unconditionally** (FORCE doesn't even apply to them). No separate non-superuser application role exists (grep found none).

So RLS can _never_ be demonstrated as currently wired. **Fix shape:** (a) add `FORCE ROW LEVEL SECURITY` to all five policy tables (episodes/playbooks/entities/relationships/audit_events); (b) introduce a dedicated **NOSUPERUSER** application role (e.g. `nexus_app`) with `GRANT`s but not ownership; (c) the app engine DSN **and** the live-test fixtures connect as that role (compose/CI provisions it). **Downstream impact:** charter/control-plane engine creation + the compose/CI Postgres setup must adopt the app role — the largest blast radius of the three. → **Q3.**

## §4. Axis 4 — the integrated 6/6 keystone

The _real_ keystone only exists when **all four** are present: `set_config` (merged) + LTREE (`_LtreeColumn`) + pgvector comparator + RLS FORCE/role. Only then does `NEXUS_LIVE_POSTGRES=1 pytest test_memory_live_postgres.py` reach **6 passed**, proving: alembic upgrade (both extensions), CRUD across the four Postgres-native types, pgvector ANN top-K, and **true tenant isolation** (A-cannot-see-B via raw SQL as a non-superuser). The lane (PR #252) is the home; it should flip from `workflow_dispatch`-only to triggering on charter-substrate PRs **in the same change that makes it green.** The cycle's verification bar is this 6/6 run, against actual Postgres — not a mock.

---

## §5. Proposed Q-locks (operator decides) 🔒

|      # | Question           | Options                                                                                                                 | **Recommendation**                                                                                                 |
| -----: | ------------------ | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Q1** | **LTREE revival**  | Cherry-pick `acfc830` + its mocked tests onto a fresh branch · Reconstruct from scratch                                 | **Cherry-pick `acfc830`** — proven code (lane-verified), clean apply; don't untangle the orphaned stack.           |
| **Q2** | **pgvector fix**   | `comparator_factory` on `_PortableVector` (keeps portability) · Use `Vector` directly (drops JSON fallback)             | **`comparator_factory`** — preserves the aiosqlite path the unit tests rely on.                                    |
| **Q3** | **RLS role model** | `FORCE` + dedicated `nexus_app` NOSUPERUSER role (app + tests use it) · `FORCE` only                                    | **`FORCE` + non-superuser role** — `FORCE` alone is still bypassed by the superuser connection; both are required. |
| **Q4** | **Cycle scope**    | All 3 remaining bugs as ONE cycle · Separate cycles                                                                     | **One cycle** — none is live-verifiable alone; the 6/6 keystone needs them together.                               |
| **Q5** | **psycopg2 home**  | Move `psycopg2-binary` from root dev → charter dev dep (this cycle touches charter + trips WI-1 anyway) · Leave at root | **Move to charter dev dep here** — the proper home; no extra cost since this cycle already trips WI-1.             |

---

## §6. Proposed task breakdown (preview — NOT a plan doc)

|   # | Risk                | Task                                                                                                                          |
| --: | ------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
|   1 | **SAFETY-CRITICAL** | Revive LTREE fix (`acfc830` `_LtreeColumn`) + mocked unit tests                                                               |
|   2 | **SAFETY-CRITICAL** | pgvector `comparator_factory` (restore `cosine_distance`)                                                                     |
|   3 | **SAFETY-CRITICAL** | RLS `FORCE` + `nexus_app` non-superuser role (migration + engine DSN + compose/CI) + fixtures connect as app role             |
|   4 | LOW-RISK            | Integrated 6/6 proof via `charter-f5-live.yml`; wire the lane to charter-substrate PRs; move psycopg2 to charter dev dep (Q5) |
|   5 | LOW-RISK            | Verification record + memory-note correction (§7) + living-doc updates                                                        |

Each SAFETY-CRITICAL task trips the WI-1 substrate seal by design (the seal working). Verification bar: the lane at 6/6.

## §7. Memory-note correction (explicit)

The project memory `project_kg_loop_charter_ltree_substrate_bug` records the F.5 LTREE bug as **"RESOLVED 2026-05-20 … commit acfc830 … CI run 26088948053 PASS."** **This is wrong on two counts:** (1) `acfc830` merged into the orphaned F.5 stack, **not main** — current `main` still has the broken `postgresql.LTREE()`; (2) run 26088948053 was a **failure** (alembic passed; the 5 ORM/RLS tests failed). The correct status: **LTREE remains broken on main; the fix is orphaned and must be revived.** The brainstorm flags this so strategy stops resting on a false "resolved."

## §8. Guardrails (DRAFT ONLY)

❌ No plan doc yet · ❌ No code · ❌ No execution · ❌ No detection-agent / v2.0 / Wazuh work · ❌ Don't untangle the orphaned F.5 stack (revive the fix cleanly instead) · ✅ One coherent substrate cycle · ✅ All 4 axes investigated · ✅ Memory-note correction surfaced · ✅ Held for operator review after F.3 v0.2 Task 2 ships.

---

## §9. Next step

**Operator reviews + locks Q1–Q5 after F.3 v0.2 Task 2 ships.** On lock, the plan doc decomposes §6 into per-task PRs (3 SAFETY-CRITICAL + 2 LOW-RISK). No code until the plan is locked. This cycle runs as the single parallel substrate cycle (γ sequencing), unblocking the v2.0 security-graph substrate once 6/6 lands.

— drafted 2026-06-08 (charter multi-tenant RLS substrate brainstorm; 4-bug investigation).
