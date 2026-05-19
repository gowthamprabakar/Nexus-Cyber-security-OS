# F.5 LTREE substrate fix — `_PortableLtree` against real Postgres

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Pause for review after each numbered task.

**Goal.** Fix the **one** charter F.5 substrate defect surfaced by the KG-loop closure plan and confirmed in CI run [`26082292289`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26082292289): `_PortableLtree.load_dialect_impl` at [`packages/charter/src/charter/memory/models.py:106`](../../../packages/charter/src/charter/memory/models.py#L106) calls `postgresql.LTREE()`, which **SQLAlchemy 2.0.49 (this workspace's pin) does not expose** as an attribute. The F.5 baseline alembic migration cannot materialize against real Postgres because the `playbooks` table's `path` column uses `_PortableLtree`. All 6 F.5 live-lane tests have always errored at fixture setup against any real Postgres (no live run anywhere had been green before this plan). **One bug, one fix, one minimal surface — no other charter touch, no agent touch, no other carry-forward addressed here.**

## Settled context (fixed input — do not re-litigate)

- **The bug is empirically confirmed in CI.** The diagnostic workflow at [`.github/workflows/f5-ltree-diagnostic.yml`](../../../.github/workflows/f5-ltree-diagnostic.yml) (branch `diagnostic/f5-ltree-bug-repro`, draft PR #42) ran against a CI-provisioned `pgvector/pgvector:pg16` service container on 2026-05-19 and produced **6 errors in 5.36s**, every one with the same stack frame at `models.py:106` → `AttributeError: module 'sqlalchemy.dialects.postgresql' has no attribute 'LTREE'`. The failure is **not environment-specific**; it is at the charter/SQLAlchemy layer. Recorded in [`kg-loop-closure-verification-2026-05-18.md`](../../_meta/kg-loop-closure-verification-2026-05-18.md) §13.2.

- **Charter's own F.5 live lane (`packages/charter/tests/integration/test_memory_live_postgres.py`) has never run green in CI.** The bug existed because nothing exercised the Postgres dialect path of `_PortableLtree`; aiosqlite unit tests fall through to the `String(512)` fallback at `models.py:107` and never touch the broken Postgres branch.

- **The KG-loop-closure plan (2026-05-18) explicitly deferred this fix.** Its watch-item 1 forbade any charter change; the live test at [`packages/agents/cloud-posture/tests/integration/test_kg_loop_live_postgres.py`](../../../packages/agents/cloud-posture/tests/integration/test_kg_loop_live_postgres.py) works around the bug by using `Base.metadata.create_all(tables=[EntityModel.__table__, RelationshipModel.__table__])` instead of `alembic upgrade head` — the §13.3 letter-vs-spirit deviation. This plan resolves §13.2; §13.3 becomes newly-unblocked but is **NOT addressed here** (see hard scope boundary).

- **SQLAlchemy 2.0.49 is pinned at the workspace root.** It does not ship a `LTREE` type on the `postgresql` dialect. (Verified: `uv run python -c "from sqlalchemy.dialects import postgresql; print(hasattr(postgresql, 'LTREE'))"` returns `False` at this commit's HEAD.) Whether a later 2.0.x release ships LTREE natively is irrelevant to the plan — see "Alternatives considered" below for why a version bump is rejected.

- **The `playbooks` table's `path` column is the only consumer of `_PortableLtree`.** Charter's procedural-store code at [`packages/charter/src/charter/memory/procedural.py`](../../../packages/charter/src/charter/memory/procedural.py) reads + writes this column; subtree containment (`<@` / `@>`) is gated behind a dialect check (it already does the right thing on aiosqlite via a SQL-LIKE fallback). **Nothing outside `_PortableLtree` references `postgresql.LTREE` directly.** Task 1 of this plan empirically verifies this with a grep audit (same shape as KG-loop Task 2).

- **The fix is private to charter.** `_PortableLtree` is underscore-prefixed: a private type. Its public consumer is `PlaybookModel.path` in the ORM model declaration; that declaration does not change. The class shape (`impl = String`; `cache_ok = True`; `load_dialect_impl(dialect)` method) does not change. **The fix is internal to the function body of `load_dialect_impl`.**

## Hard scope boundary (stated up-front)

**This plan fixes the LTREE column-type defect in `_PortableLtree.load_dialect_impl` ONLY.**

Specifically out of scope, each named so it doesn't drift mid-execution:

- **NOT** any other charter change. The diff is confined to (a) `packages/charter/src/charter/memory/models.py` in the `_PortableLtree` region (lines 92-107 today) plus an import, and (b) the new test file. No other file under `packages/charter/src/` is modified. **If any task's diff touches another charter source file, that is scope creep and the task is rejected.**
- **NOT** any change to any other charter type (`_PortableJSONB`, `_PortableVector`, `_PortableArray`, etc.). They may have analogous issues; not addressed here.
- **NOT** any agent change. `packages/agents/*/src/` diffs must be empty for every task.
- **NOT** the cross-run AFFECTS-edge dedup debt (KG-loop §13.1). Separate future plan.
- **NOT** the KG-loop §13.3 letter-vs-spirit deviation (the `Base.metadata.create_all(tables=...)` workaround in the cloud-posture live test). This plan resolves §13.2 which §13.3 depends on, but does NOT retro-point the KG-loop test at `alembic upgrade head`. Task 6 of this plan **notes** that §13.3 becomes newly-unblocked for a future follow-up plan; it does **not** execute that follow-up.
- **NOT** a SQLAlchemy version bump. Rejected explicitly in §"Alternatives considered."
- **NOT** the cleanup of the diagnostic branch `diagnostic/f5-ltree-bug-repro` outside Task 7's narrow act of closing PR #42 + deleting the throwaway workflow + deleting the branch.

**Three knobs locked: one substrate file, one column-type fix, one permanent CI workflow.**

## Root cause + chosen fix approach

### Root cause

`packages/charter/src/charter/memory/models.py:106` reads:

```python
return dialect.type_descriptor(postgresql.LTREE())  # type: ignore[attr-defined]
```

`sqlalchemy.dialects.postgresql.LTREE` does not exist in SQLAlchemy 2.0.49. The `# type: ignore[attr-defined]` comment that already sits on the line is evidence that the original author knew the attribute was off-stock and chose to suppress the mypy warning rather than implement a proper type — the bug shipped with a known-broken Postgres path that was never exercised. The runtime `AttributeError` fires the moment SQLAlchemy compiles DDL for the `playbooks.path` column against a Postgres dialect, which is exactly what `alembic upgrade head` does during F.5's live lane.

### Chosen fix: minimal inline `UserDefinedType` emitting `LTREE` DDL

Replace `postgresql.LTREE()` at line 106 with a small private `UserDefinedType` defined in the same file. Approximate shape (to be finalized in Task 2):

```python
from sqlalchemy.types import UserDefinedType

class _LtreeColumn(UserDefinedType[str]):
    """Minimal `ltree` column emitter for the Postgres branch of `_PortableLtree`.

    SQLAlchemy 2.0.49 does not ship `postgresql.LTREE`. This emitter
    keeps the substrate's behaviour identical to what `postgresql.LTREE`
    would have done if it existed: emits `LTREE` as the column DDL,
    round-trips values as strings (Python `str` <-> SQL `ltree`). No
    additional bind / result processing — `path` values are
    dot-separated strings on both sides of the protocol, so the
    default `str` round-trip is correct.
    """

    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:
        return "LTREE"
```

Then update `_PortableLtree.load_dialect_impl`:

```python
def load_dialect_impl(self, dialect: Any) -> Any:
    if dialect.name == "postgresql":
        return dialect.type_descriptor(_LtreeColumn())
    return dialect.type_descriptor(String(512))
```

That's the entire substrate diff. ~10 lines added, 1 line changed, 1 `# type: ignore[attr-defined]` comment removed (no longer needed). The `_PortableLtree` class shape, its `impl`, its `cache_ok`, its method signature, and the aiosqlite fallback are **all unchanged**.

### Why this is least-invasive

- **Zero new third-party dependencies.** No `sqlalchemy-utils`, no other pin. `UserDefinedType` is already imported transitively wherever `TypeDecorator` is in scope (both are part of `sqlalchemy.types`).
- **Zero schema shape change.** The column's DDL is identical to what `postgresql.LTREE()` would have emitted (`LTREE`). Alembic-generated tables produced by `alembic upgrade head` post-fix will have a `path LTREE` column identical to the documented F.5 schema.
- **Zero behaviour change anywhere except the Postgres dialect path of this one type.** aiosqlite tests still use the `String(512)` fallback at line 107 (unchanged). All non-Postgres code paths are untouched.
- **Zero blast radius beyond `_PortableLtree`.** No public type renamed; no public method signature changed; no class added to the import surface. `_LtreeColumn` is underscore-prefixed and lives below `_PortableLtree` in the same module — no other file imports it.
- **Reversible by a one-line revert.** Roll back Task 2's commit and the substrate returns to the pre-fix state (which has the bug but doesn't block KG-loop because of the §13.3 workaround).

### Alternatives considered

| Option                                                                        | What it would do                                                                                                                                       | Why rejected                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **B. Add `sqlalchemy-utils` dep + use `LtreeType`**                           | `from sqlalchemy_utils import LtreeType` and use it in place of `postgresql.LTREE()`.                                                                  | Adds a third-party transitive dep + pin maintenance + lock-file churn. `LtreeType` does considerably more than we need (it ships a `Ltree` Python class with operator overloading, etc.); we already round-trip values as plain strings throughout `procedural.py`, so the extra surface is dead weight + future-rot risk. **Wider blast radius than necessary; option A is strictly less invasive.**                                                                                                                                                                                                                                                                                                                                                                             |
| **C. Upgrade SQLAlchemy to a version that ships `postgresql.LTREE` natively** | Bump `sqlalchemy` pin in `packages/charter/pyproject.toml` (and possibly the workspace root) to the first 2.0.x release that adds the LTREE attribute. | (a) Widens blast radius beyond LTREE to every SA-internals change between 2.0.49 and the target version — release notes between 2.0.x patch releases include bug fixes that subtly alter dialect behaviour; cannot be verified safe without re-running every existing live-DB test, which we DON'T have for everything yet. (b) Requires `uv.lock` regeneration + re-test of every workspace member's SQLAlchemy-using code (charter, control-plane, eval-framework where applicable). (c) When `postgresql.LTREE` did land natively (later 2.0.x) it's effectively the same `UserDefinedType` shape as Option A — adopting it later is a one-line swap. **Defer to a future "SQLAlchemy upgrade" plan if/when one exists; that plan's scope is the version bump, not this bug.** |
| **D. Drop the `playbooks` table entirely (or its LTREE column)**              | Remove or restructure the `path` column to avoid LTREE on Postgres.                                                                                    | F.5's design pinned LTREE specifically because subtree containment (`<@` / `@>`) is one of the procedural store's load-bearing queries. Removing or restructuring the column is a schema change that breaks F.5's design contract. **Rejected: out of scope for "fix the one bug."**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **E. Skip `playbooks` migration when running against real Postgres**          | Branch the alembic baseline migration to skip the `playbooks` table on Postgres.                                                                       | Inverse of Option D — leaves the schema half-applied; F.5 design says all three engines (`episodes` / `playbooks` / `entities` + `relationships`) are present in the same DB. **Rejected: violates F.5's design contract; leaves a worse latent bug.**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

**Option A is chosen.** It is the unique option that fixes the one bug, adds no dependencies, changes no public surface, leaves no schema-shape drift, and reverts in one line.

## ADR-010 eligibility test (substrate-scoped)

ADR-010 was written for **within-agent** version extensions. This plan is a **substrate fix**, not an agent extension, but the conformance test is still useful as a discipline check. Adapted:

| #   | Condition                                         | Result   | Evidence                                                                                                                                                                                      |
| --- | ------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Same package                                      | **PASS** | Every file modified lives under `packages/charter/`.                                                                                                                                          |
| 2   | Additive surface (no rename / remove / repurpose) | **PASS** | `_PortableLtree` class shape preserved; `_LtreeColumn` is a new private class living alongside; no public symbol renamed or removed.                                                          |
| 3   | OCSF schema stability                             | **N/A**  | Charter substrate; no OCSF surface.                                                                                                                                                           |
| 4   | F.6 audit-chain vocabulary additive               | **N/A**  | No audit-action change.                                                                                                                                                                       |
| 5   | CLI surface unchanged                             | **PASS** | No CLI touch.                                                                                                                                                                                 |
| 6   | Python public API params unchanged                | **PASS** | `_PortableLtree`'s constructor and `load_dialect_impl` signature unchanged. `_LtreeColumn` is private (underscore-prefixed) and not exported. `PlaybookModel.path` type annotation unchanged. |

**3 PASS + 2 N/A.** Clean conformance.

## Scope (in / out)

In scope:

1. `_LtreeColumn` `UserDefinedType` added in `packages/charter/src/charter/memory/models.py` immediately before `_PortableLtree`.
2. `_PortableLtree.load_dialect_impl` Postgres branch swaps `postgresql.LTREE()` → `_LtreeColumn()`; `# type: ignore[attr-defined]` comment removed.
3. Mocked unit test asserting the Postgres dialect path of `_PortableLtree.load_dialect_impl` returns a type whose `get_col_spec()` produces `"LTREE"` (no live DB required).
4. Permanent CI workflow `.github/workflows/charter-f5-live.yml` running `packages/charter/tests/integration/test_memory_live_postgres.py` against a CI-provisioned Postgres service container, gated by `NEXUS_LIVE_POSTGRES=1`, paths-filtered to charter substrate + the workflow file.
5. Live proof: F.5 live lane (all 6 tests) goes GREEN in CI on the patched branch.
6. KG-loop regression guard: the existing `.github/workflows/kg-loop-live.yml` workflow continues to pass on the patched branch.
7. Cleanup: throwaway diagnostic at `.github/workflows/f5-ltree-diagnostic.yml` deleted; `diagnostic/f5-ltree-bug-repro` branch deleted; draft PR #42 closed.
8. Companion verification record at `docs/_meta/f5-ltree-substrate-fix-verification-2026-05-19.md`.

Out of scope (explicit):

- ❌ Any other charter source file change.
- ❌ Any other `_Portable*` type review or change.
- ❌ Any agent change.
- ❌ SQLAlchemy version bump.
- ❌ KG-loop §13.1 cross-run AFFECTS dedup fix.
- ❌ KG-loop §13.3 retro-point of the cloud-posture live test back to `alembic upgrade head`. **Newly-unblocked** by this plan; Task 6's verification record notes this; the retro-point is a separate follow-up plan.

## Reversibility and rollback

The plan is reversible at any point.

- **If Task 2 (substrate fix) lands broken:** revert Task 2's commit. Substrate returns to pre-fix state; F.5 live lane goes red again; KG-loop still works (§13.3 workaround is independent of this fix).
- **If Task 4 / 5 (permanent workflow + live proof) reveal an unforeseen failure mode:** revert Tasks 4 + 5; the throwaway diagnostic at Task 7 stays in place (uncommitted cleanup) so the red signal remains available for the next attempt.
- **If Task 6 (KG-loop regression guard) shows KG-loop regressing:** revert Task 2 immediately; the LTREE fix was breaking KG-loop's loop somehow. (Not expected — the fix is at the substrate layer and KG-loop doesn't materialize `playbooks` — but the regression-guard task exists precisely to catch any surprise.)
- **The throwaway diagnostic branch `diagnostic/f5-ltree-bug-repro` + PR #42 stay in place until Task 7.** Their continued red signal is part of the safety net — if Task 5's green proof against the new permanent workflow ever later regresses, the diagnostic provides a parallel test of the same invariant from a different angle (different paths-filter, different default branch state).

## Resolved questions (decisions baked into this plan)

- **Q1: Why not use `sqlalchemy-utils.LtreeType`?** Answered above. Adds dep + dead-weight features for our use case; Option A is strictly less invasive.
- **Q2: Why not bump SQLAlchemy?** Answered above. Wider blast radius; defer to a separate plan when one exists.
- **Q3: Should the fix also add Postgres-specific operator overloading (`<@` / `@>`) on `_LtreeColumn`?** No. `procedural.py` already does dialect-gated SQL emission for those operators (see `procedural.py` line ~183's comment: _"`path LIKE prefix || '.%'` — same semantics for the LTREE …"_). The Python-side operator surface is unchanged.
- **Q4: Does the existing `_PortableLtree.impl = String` line need to change?** No. `impl` is the **fallback** SQLAlchemy type used when `load_dialect_impl` is not specialized; on the Postgres branch we specialize via `load_dialect_impl`, so `impl = String` is correct for the non-Postgres fallback path and unused on Postgres.
- **Q5: Does the LTREE column require any extension to be installed?** Yes — Postgres needs `CREATE EXTENSION ltree`. The F.5 baseline migration already does this (`packages/charter/alembic/versions/0001_memory_baseline.py` calls `CREATE EXTENSION IF NOT EXISTS ltree` per its docstring). The fix does NOT add or remove the extension call.

## Architecture (one-page)

```
                  ┌──────────────────────────────────────────────────────┐
                  │  packages/charter/src/charter/memory/models.py        │
                  │  (BEFORE)                                             │
                  │                                                       │
                  │  class _PortableLtree(TypeDecorator[str]):            │
                  │      impl = String                                    │
                  │      cache_ok = True                                  │
                  │                                                       │
                  │      def load_dialect_impl(self, dialect):            │
                  │          if dialect.name == "postgresql":             │
                  │              return dialect.type_descriptor(          │
                  │                  postgresql.LTREE()  # 💥 BROKEN      │
                  │              )                                        │
                  │          return dialect.type_descriptor(String(512))  │
                  └──────────────────────────────────────────────────────┘

                                          │
                                  Task 2 substrate fix
                                          ▼

                  ┌──────────────────────────────────────────────────────┐
                  │  packages/charter/src/charter/memory/models.py        │
                  │  (AFTER)                                              │
                  │                                                       │
                  │  class _LtreeColumn(UserDefinedType[str]):   ← NEW    │
                  │      cache_ok = True                                  │
                  │      def get_col_spec(self, **kw):                    │
                  │          return "LTREE"                               │
                  │                                                       │
                  │  class _PortableLtree(TypeDecorator[str]):  (same)    │
                  │      impl = String                          (same)    │
                  │      cache_ok = True                        (same)    │
                  │                                                       │
                  │      def load_dialect_impl(self, dialect):            │
                  │          if dialect.name == "postgresql":             │
                  │              return dialect.type_descriptor(          │
                  │                  _LtreeColumn()  ← FIXED              │
                  │              )                                        │
                  │          return dialect.type_descriptor(String(512))  │
                  └──────────────────────────────────────────────────────┘

Behaviour:
  postgresql dialect → DDL emits `path LTREE` (identical to what
                       `postgresql.LTREE()` would have done)
  aiosqlite dialect  → DDL emits `path VARCHAR(512)` (unchanged)

Blast radius diagram:
  packages/charter/src/charter/memory/models.py        ← ~10 lines added,
                                                         1 line changed
  packages/charter/tests/test_portable_ltree.py        ← NEW unit test
  .github/workflows/charter-f5-live.yml                ← NEW permanent
                                                         CI workflow
  .github/workflows/f5-ltree-diagnostic.yml            ← DELETED at Task 7

Everything else in packages/charter/ untouched.
Every agent untouched.
Every other workflow untouched.
```

## Execution status

| #   | Status     | Commit    | Risk label          | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --- | ---------- | --------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | ✅ done    | `d8ce9aa` | LOW-RISK            | Empirical grep audit confirming `postgresql.LTREE` is referenced nowhere outside `packages/charter/src/charter/memory/models.py:106`. Same shape as KG-loop Task 2: 3-4 search surfaces (`postgresql.LTREE`, `from .*ltree`, `LtreeType`, `LTREE\(\)`) run against `packages/`. Audit doc lands at `docs/_meta/f5-ltree-fix-task-1-grep-audit-2026-05-19.md`. **Hash-pin this row.**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 2   | ⬜ pending | —         | **SAFETY-CRITICAL** | `packages/charter/src/charter/memory/models.py` — add `_LtreeColumn` `UserDefinedType` immediately before `_PortableLtree`; change line 106's `postgresql.LTREE()` → `_LtreeColumn()`; remove the `# type: ignore[attr-defined]` comment on that line. ~10 lines added, 1 line changed. **Touches the sealed substrate — verified-against-HEAD sentence required** in the PR body per ADR-011 Discipline 3. Watch-item 1 reframed to "charter UNTOUCHED EXCEPT lines 92-110 of models.py"; the diff must show that and nothing else under `packages/charter/src/`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 3   | ⬜ pending | —         | LOW-RISK            | `packages/charter/tests/test_portable_ltree.py` (NEW): ~5-6 mocked unit tests. Assert: (a) `_LtreeColumn().get_col_spec()` returns `"LTREE"`; (b) `_PortableLtree.load_dialect_impl(<postgres-dialect-mock>)` returns a type whose `get_col_spec()` is `"LTREE"`; (c) `_PortableLtree.load_dialect_impl(<aiosqlite-dialect-mock>)` returns a `String(512)` descriptor (the fallback, unchanged); (d) the `_PortableLtree` class's public attributes (`impl`, `cache_ok`) are still set the same way; (e) `cache_ok = True` on `_LtreeColumn` (load-bearing for SQLAlchemy 2.x compiler caching). No live DB; pure SQLAlchemy dialect mocking. Catches regression at the unit-test layer in CI even without a Postgres service.                                                                                                                                                                                                                                                                                                                              |
| 4   | ⬜ pending | —         | LOW-RISK            | `.github/workflows/charter-f5-live.yml` (NEW): **permanent** CI workflow for F.5's live-Postgres lane. Same shape as `.github/workflows/kg-loop-live.yml` (the KG-loop keystone-proof workflow) — `pgvector/pgvector:pg16` service container, `POSTGRES_USER=nexus` / `POSTGRES_PASSWORD=nexus_dev` / `POSTGRES_DB=nexus`, healthcheck `pg_isready -U nexus`, `uv pip install psycopg2-binary` (the F.5 lane drives `alembic upgrade head`), `NEXUS_LIVE_POSTGRES=1 uv run pytest -v packages/charter/tests/integration/test_memory_live_postgres.py`. Paths-filtered on PR + push-to-main for `packages/charter/alembic/**`, `packages/charter/src/charter/memory/**`, `packages/charter/tests/integration/test_memory_live_postgres.py`, and the workflow file itself. **This workflow is PERMANENT** — the F.5 LTREE bug existed because nothing exercised charter's Postgres dialect in CI; from this PR forward it is exercised on every relevant PR.                                                                                                  |
| 5   | ⬜ pending | —         | **SAFETY-CRITICAL** | **THE LOAD-BEARING LIVE PROOF.** The new `charter-f5-live.yml` workflow runs on the patched branch and ALL 6 F.5 live tests go GREEN. The same provisioning shape that produced the red diagnostic CI run [`26082292289`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26082292289) now produces a green run on this branch. **Verified-against-HEAD sentence required** in the PR body. CI URL + green-result evidence captured in the PR body and in Task 8's verification record. **Agent does NOT merge** — full report → review → merge.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 6   | ⬜ pending | —         | LOW-RISK            | **Regression guard for the KG-loop keystone proof.** Trigger or verify a run of `.github/workflows/kg-loop-live.yml` against the patched branch's HEAD; assert it still passes (3 tests, same 2.46s-ish green pattern as run [`26055249482`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26055249482)). The LTREE fix is at the substrate layer; KG-loop tests don't materialize `playbooks`; the regression is not expected. The task makes that expectation empirical at execution-time. Also: **note** that KG-loop §13.3 (the cloud-posture live test's `Base.metadata.create_all(tables=...)` workaround) becomes newly-unblocked — a future plan can retro-point the cloud-posture live test back to `alembic upgrade head` if desired. **Do NOT execute that retro-point here; it is a separate follow-up.**                                                                                                                                                                                                             |
| 7   | ⬜ pending | —         | LOW-RISK            | **Cleanup of the throwaway diagnostic.** Delete `.github/workflows/f5-ltree-diagnostic.yml`; close draft PR #42 with a comment naming this plan's verification record (Task 8) as the green-replacement-of-record; delete the branch `diagnostic/f5-ltree-bug-repro`. The diagnostic served its purpose (it captured the red signal at run [`26082292289`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26082292289)); the permanent workflow added in Task 4 is its replacement. Cleanup is named here so it doesn't dangle.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 8   | ⬜ pending | —         | LOW-RISK            | Companion verification record at `docs/_meta/f5-ltree-substrate-fix-verification-2026-05-19.md`. **Plan-closer — gets full A.1-grade review per the established discipline; agent does NOT quick-merge this PR.** Sections (per the KG-loop verification record's shape): per-task surface table (7 hash-pins); gate-results table; A.1-§8-style live-loop evidence (Postgres version, alembic migration result, HEAD, invocation, result — for the GREEN F.5 live run on the permanent workflow); ADR-010 conformance re-run (3 PASS + 2 N/A); watch-item-1 + watch-item-2 audits; coverage delta; KG-loop regression evidence (Task 6); breaking-change note (none — DDL identical to what `postgresql.LTREE()` would have emitted); permanent-limitation carryover (none new); hard-scope-boundary preserved; **explicit note that KG-loop §13.3 is newly-unblocked but NOT addressed here**; forward references; next-plan gate (other `_Portable*` types, SQLAlchemy version bump, KG-loop §13.3 retro-point, cross-run dedup — all named separately). |

## Compatibility contract

- **The `playbooks` table's `path` column DDL.** On Postgres, `CREATE TABLE playbooks (... path LTREE ...)` — identical to what `postgresql.LTREE()` would have produced if it existed. Confirmed by inspecting the DDL emitted in Task 4's CI run.
- **`PlaybookModel.path` Python attribute type.** Unchanged — `str` end-to-end (already round-tripped as Python `str` per `procedural.py`'s usage).
- **The aiosqlite fallback.** Unchanged — `String(512)`.
- **Substrate-internal helpers.** `_PortableLtree`, `EntityModel`, `RelationshipModel`, `PlaybookModel`, `EpisodeModel` — public surfaces unchanged.
- **The `neo4j>=5.24.0` dependency in `packages/agents/cloud-posture/pyproject.toml`.** Untouched (this plan is charter-scoped; the KG-loop dormancy decision stands).
- **The new private `_LtreeColumn` type.** Underscore-prefixed; not exported; not added to any `__all__`. If a future plan wants to make it public or move it to a shared location, that is a deliberate decision at that plan's time, not a side effect of this plan.

## Watch-items (carried into execution)

1. **`packages/charter/` UNTOUCHED EXCEPT lines 92-110 of `models.py` and the new `tests/test_portable_ltree.py`.** Every task's diff against `origin/main` must satisfy `git diff --stat origin/main..HEAD packages/charter/` showing **only** those two files. Any other charter file change is a scope violation and the task is rejected. (This is the inverse of the KG-loop plan's WI-1 — charter is now the _target_ of a precisely-bounded change rather than UNTOUCHED in absolute terms.)
2. **NO AGENT MODIFIED.** Per-task `git diff --stat origin/main..HEAD packages/agents/<agent>/` must return empty for every one of the 9 other agent dirs AND for `cloud-posture`. If anything under any `packages/agents/*/src/` changes, the task is rejected.
3. **Other carry-forwards remain separately sequenced.** This plan does not address KG-loop §13.1 (cross-run dedup) or execute KG-loop §13.3's retro-point. Task 6 only **notes** that §13.3 becomes unblocked; Task 8's verification record names the follow-up explicitly. Any task whose diff touches `packages/agents/cloud-posture/tests/integration/test_kg_loop_live_postgres.py` is a scope violation.
4. **The diagnostic workflow + branch + PR #42 stay in place until Task 7.** Their cleanup is the last step before the verification record. This preserves the red signal as a parallel safety net until the permanent workflow has demonstrably replaced it.

## ADR-011 compliance

- **Discipline 1 (labelling at PR-open):** Each task PR's title carries its risk label (`[SAFETY-CRITICAL]` for Tasks 2 and 5; `[LOW-RISK]` for the others). Plan PRs that ship under this plan must match the row's risk label.
- **Discipline 2 (branch protection):** Structurally enforced via `bypass_actors: []`.
- **Discipline 3 (verified-against-HEAD sentence):** Required for Tasks 2 and 5. Tasks 2's PR body asserts that gates ran against the branch's actual HEAD post-commit; Task 5's PR body asserts that the CI run URL it cites is the one that ran on the same branch HEAD it is being merged.
- **Discipline 4 (Report → Review → Merge):** All SAFETY-CRITICAL tasks pause for full report → review → merge; agent does not merge. Task 8 (plan-closer) also pauses for full A.1-grade review per the discipline established by the KG-loop plan-closer.

## Cross-references

- [ADR-009 Memory Architecture](../../_meta/decisions/ADR-009-memory-architecture.md) — the architecture this substrate implements, amended 2026-05-18 by the KG-loop plan.
- [ADR-010 Within-agent version extension template](../../_meta/decisions/ADR-010-within-agent-version-extension-template.md) — adapted for substrate scope in the eligibility test above.
- [ADR-011 PR-flow + branch-protection discipline](../../_meta/decisions/ADR-011-pr-flow-discipline.md) — every SAFETY-CRITICAL task in this plan follows it verbatim.
- [KG-loop closure verification record](../../_meta/kg-loop-closure-verification-2026-05-18.md) — §13.2 is the source-of-record for this bug; §13.3 is what becomes newly-unblocked (but is NOT addressed here).
- [`packages/charter/src/charter/memory/models.py`](../../../packages/charter/src/charter/memory/models.py) — the file being modified (lines 92-107 today).
- [`packages/charter/tests/integration/test_memory_live_postgres.py`](../../../packages/charter/tests/integration/test_memory_live_postgres.py) — F.5's own live lane; the load-bearing proof's target.
- [`.github/workflows/kg-loop-live.yml`](../../../.github/workflows/kg-loop-live.yml) — the CI-pattern template for Task 4's new permanent workflow.
- [`.github/workflows/f5-ltree-diagnostic.yml`](../../../.github/workflows/f5-ltree-diagnostic.yml) — the throwaway diagnostic that captured the red signal at CI run `26082292289`; deleted at Task 7.
- **Red-signal CI run (current bug state):** <https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26082292289>
- **KG-loop keystone proof (regression target for Task 6):** <https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26055249482>

---

**This is a PLAN DOC ONLY.** No task has been executed. Stopping for full plan review per the same discipline as the KG-loop plan (PR #32 / #33-#40 sequence).
