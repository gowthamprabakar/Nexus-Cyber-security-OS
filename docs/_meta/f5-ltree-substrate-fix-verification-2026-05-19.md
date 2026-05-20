# F.5 LTREE substrate-fix verification record (v0.1, 2026-05-19)

**Companion record for** [`docs/superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md`](../superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md). Records the full execution of the F.5 LTREE substrate-fix plan against the user-stated requirements, the watch-items, the ADR-010 eligibility conditions, the keystone live proof, and the carry-forward debts. Plan-closer; same A.1 v0.1.1-grade discipline as [`a1-v0-1-1-verification-2026-05-17.md`](a1-v0-1-1-verification-2026-05-17.md) and [`kg-loop-closure-verification-2026-05-18.md`](kg-loop-closure-verification-2026-05-18.md). **Agent does not quick-merge this PR.**

Plan written 2026-05-19; execution arc 2026-05-19 → 2026-05-20; verification record landed 2026-05-20 (file named for the plan-spec date and the date of the keystone CI evidence).

---

## §1. What this plan delivered

**Goal achieved.** The F.5 LTREE substrate defect at `packages/charter/src/charter/memory/models.py:106` is empirically fixed. The line `postgresql.LTREE()` — which does not exist in SQLAlchemy 2.0.49 — is replaced by a new private `_LtreeColumn(UserDefinedType[str])` defined immediately above `_PortableLtree` in the same file. The new class emits `"LTREE"` as the column DDL on the Postgres dialect path, exactly as `postgresql.LTREE()` would have if it existed.

**For the first time in F.5's history (since v0.1 shipped 2026-05-12), charter's F.5 baseline alembic migration completes end-to-end against a real Postgres instance in a clean reproducible environment.** Proven by CI run [`26088948053`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26088948053): `test_alembic_upgrade_head_creates_all_tables_and_extensions` PASSED on the new permanent `charter-f5-live.yml` workflow.

**One bug, one fix, one minimal surface.** The substrate diff is `+25 / −2` in one file. The diff is bounded; no other charter file changed; no agent file changed; the plan's hard scope boundary held end-to-end.

**Three follow-ups carried forward** as named, tracked debts (§11 below): the SET LOCAL `$1` tenant-RLS bug newly-surfaced by the permanent CI workflow on its first run, the cross-run AFFECTS-edge dedup debt carried from KG-loop §13.1, and the KG-loop §13.3 letter-vs-spirit deviation now newly-unblocked but not retro-pointed here.

---

## §2. Per-task surface table

| #    | Risk                | PR                                                                        | Commit(s)                                              | What landed                                                                                                                                                                                                                                                                                                         |
| ---- | ------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Plan | LOW-RISK            | [#43](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/43) | `dc3a8c3` (merged → main as `c3e398c`)                 | The plan doc itself (~530 lines); 8 tasks across 4 risk tiers                                                                                                                                                                                                                                                       |
| 1    | LOW-RISK            | [#44](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/44) | `d8ce9aa` (audit) + `2954e68` (row-1 hash-pin)         | Empirical 5-surface grep audit confirming `postgresql.LTREE` referenced in exactly ONE place (`models.py:106`). Zero third-party LTREE library usage anywhere. Empirically ruled out Option B (sqlalchemy-utils)                                                                                                    |
| 2    | **SAFETY-CRITICAL** | [#45](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/45) | `acfc830` (substrate fix) + `37016d7` (row-2 hash-pin) | `+25 / −2` in `packages/charter/src/charter/memory/models.py`. New private `_LtreeColumn(UserDefinedType[str])`; one-line swap at line 106; obsolete `# type: ignore[attr-defined]` removed. Verified-against-HEAD                                                                                                  |
| 3    | LOW-RISK            | [#46](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/46) | `f760fd8` (test file) + `b1301d9` (row-3 hash-pin)     | `packages/charter/tests/test_portable_ltree.py` (NEW, 141 lines) — 6 mocked unit tests; `_FakeDialect` duck-typed dialect; full coverage of `_LtreeColumn` + `_PortableLtree` routing + class-shape preservation                                                                                                    |
| 4    | LOW-RISK            | [#47](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/47) | `32897b8` (workflow) + `d8bc969` (row-4 hash-pin)      | `.github/workflows/charter-f5-live.yml` (NEW, 121 lines) — permanent CI workflow. `pgvector/pgvector:pg16` service, `POSTGRES_USER=nexus`, paths-filtered to charter substrate. **Closes the root cause that allowed the LTREE bug to live latent**                                                                 |
| 5    | **SAFETY-CRITICAL** | [#48](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/48) | `01e1fc9` (evidence-of-record + row-5 hash-pin)        | `docs/_meta/f5-ltree-fix-task-5-live-proof-2026-05-19.md` (NEW). **Rescoped live proof**: 1 PASS (LTREE empirically fixed) + 5 separately-tracked FAIL (SET LOCAL `$1` bug — out of scope per operator directive 2026-05-20). Verified-against-HEAD                                                                 |
| 6    | LOW-RISK            | [#49](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/49) | `70bca20` (evidence-of-record + row-6 hash-pin)        | `docs/_meta/f5-ltree-fix-task-6-kg-loop-regression-guard-2026-05-19.md` (NEW). **Adapted** regression guard: structural-orthogonality argument (kg-loop-live.yml not on main yet because PR #38 still open; importing across plans would violate WI-2/WI-3). Three empirical anchors; predicted future confirmation |
| 7    | LOW-RISK            | [#50](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/50) | `da22112` (audit-trail + row-7 hash-pin)               | `docs/_meta/f5-ltree-fix-task-7-diagnostic-cleanup-2026-05-20.md` (NEW). Diagnostic retired: PR #42 CLOSED, branch `diagnostic/f5-ltree-bug-repro` DELETED from origin, workflow file retired. Red-signal CI run `26082292289` preserved as immutable history                                                       |
| 8    | LOW-RISK            | _this PR_                                                                 | _this commit_                                          | **This verification record.** Plan-closer; full A.1-grade review; three carry-forward debts named verbatim with named owners                                                                                                                                                                                        |

Plan PR + Task 1 + Task 3 + Task 4 + Task 6 + Task 7 + Task 8 = LOW-RISK class. Task 2 + Task 5 = SAFETY-CRITICAL with verified-against-HEAD sentences in their PR bodies, full report → review → merge discipline, agent did not merge. Matches plan row labelling exactly.

---

## §3. Local gates (final aggregate)

All gates run against the Task 7 branch HEAD before this Task 8 commit. The full plan branch sequence is stacked, so the aggregate state is the cumulative effect of Tasks 1-7 + this commit.

| Gate                                                             | Result                                                                                                                                         |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `uv run ruff check .`                                            | All checks passed                                                                                                                              |
| `uv run ruff format --check .`                                   | 434 files already formatted (+1 vs. plan base = `test_portable_ltree.py`; new doc files under `docs/_meta/` were prettier-formatted on commit) |
| `uv run mypy --strict` (modified + new files)                    | Success: no issues found across `models.py`, `test_portable_ltree.py`                                                                          |
| `uv run pytest -q`                                               | **2728 passed, 23 skipped** — `+6 vs. plan-base 2722 / 23` (the 6 mocked unit tests from Task 3)                                               |
| `uv run pytest packages/charter/tests/test_portable_ltree.py -v` | 6 passed in 0.23s                                                                                                                              |

The aiosqlite-fallback path remains exercised by every existing test (no regression introduced); the Postgres-dialect path is now exercised by Task 3's mocked tests + Task 5's live CI lane.

---

## §4. The keystone live proof — A.1-§8-style evidence

Per the discipline established by [`a1-safety-verification-2026-05-16.md`](a1-safety-verification-2026-05-16.md) §8 and re-used by [`kg-loop-closure-verification-2026-05-18.md`](kg-loop-closure-verification-2026-05-18.md) §4.

```
DATE:                       2026-05-19 (CI run); plan-closer record landed 2026-05-20
CI RUN URL:                 https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26088948053
CI RUN STATUS:              completed / failure (overall — rescope rationale at §4.1)
HEAD AT RUN:                d8bc969 (Task 4 branch tip after row-4 hash-pin)
WORKFLOW:                   .github/workflows/charter-f5-live.yml (Task 4, commit 32897b8)
RUNNER IMAGE:               ubuntu-24.04
POSTGRES SERVICE IMAGE:     pgvector/pgvector:pg16
POSTGRES PROVISIONING:      POSTGRES_USER=nexus / POSTGRES_PASSWORD=nexus_dev / POSTGRES_DB=nexus
HEALTHCHECK:                pg_isready -U nexus (5s interval, 10 retries)
SYNC DRIVER:                psycopg2-binary installed at job-step (CI-only)
SCHEMA INSTALLATION:        Real `alembic upgrade head` against the migrated DB —
                            F.5 baseline migration `0001_memory_baseline` + RLS migration
                            `0002_memory_rls` complete to head for the first time in F.5's history
TESTS RUN:                  6 (charter F.5 live lane)
TESTS PASSED:               1 — test_alembic_upgrade_head_creates_all_tables_and_extensions
TESTS FAILED:               5 — all with PostgresSyntaxError on `SET LOCAL app.tenant_id = $1::VARCHAR`
                            (a SEPARATE substrate bug; out of scope per operator directive 2026-05-20)
RESULT:                     LTREE bug PROVEN FIXED (1 PASS) + SET LOCAL bug PROVEN NEWLY-VISIBLE (5 FAIL)
COMPARISON (CONTROL):       Pre-fix diagnostic CI run 26082292289 (2026-05-19, branch
                            diagnostic/f5-ltree-bug-repro): 6 ERRORS at fixture setup, every
                            one with AttributeError at models.py:106. F.5 baseline never completed.
```

### §4.1 — Why this proof is rescoped

Plan row 5 originally said: _"the same provisioning shape that produced the red diagnostic CI run [`26082292289`] now produces a green run on this branch."_ The post-Task-2 CI run on the same provisioning shape **does not produce a fully green run.** It produces 1 PASS + 5 FAIL with different root causes. The operator's directive on 2026-05-20 — verbatim — was:

> _"Park the SET LOCAL tenant-RLS bug. Close this LTREE plan honestly with what's proven."_

Honoring that directive, this proof is honestly rescoped from "6 GREEN" to "1 PASS (the LTREE-fix-dependent test) + 5 FAIL (a separately-tracked tenant-RLS substrate bug, out of scope)." See [`f5-ltree-fix-task-5-live-proof-2026-05-19.md`](f5-ltree-fix-task-5-live-proof-2026-05-19.md) for the full evidence-of-record, including the change-in-failure-mode table that establishes structurally that the 5 post-fix failures are NOT LTREE failures.

### §4.2 — The change in failure mode IS the proof

| Test                                                          | Pre-fix (run `26082292289`)    | Post-fix (run `26088948053`) | What this confirms                                   |
| ------------------------------------------------------------- | ------------------------------ | ---------------------------- | ---------------------------------------------------- |
| `test_alembic_upgrade_head_creates_all_tables_and_extensions` | ERROR (LTREE at fixture setup) | ✅ **PASSED**                | **LTREE bug FIXED.** Keystone proof.                 |
| `test_crud_round_trip_on_all_four_tables`                     | ERROR (LTREE)                  | FAIL (`SET LOCAL $1`)        | LTREE no longer blocks; SET LOCAL is the new ceiling |
| `test_pgvector_ann_…`                                         | ERROR (LTREE)                  | FAIL (`SET LOCAL $1`)        | Same                                                 |
| `test_rls_isolates_tenants_on_episodes`                       | ERROR (LTREE)                  | FAIL (`SET LOCAL $1`)        | Same                                                 |
| `test_rls_isolates_tenants_on_playbooks`                      | ERROR (LTREE)                  | FAIL (`SET LOCAL $1`)        | Same                                                 |
| `test_rls_isolates_tenants_on_entities`                       | ERROR (LTREE)                  | FAIL (`SET LOCAL $1`)        | Same                                                 |

**Six pre-fix errors of one root cause → 1 post-fix PASS + 5 post-fix fails of a DIFFERENT root cause.** The change in failure mode is itself the proof that one bug went away and a different, previously-masked bug is now visible.

---

## §5. ADR-010 conformance — re-run honestly

Adapted to substrate scope per the plan's §"ADR-010 eligibility test (substrate-scoped)."

| #   | Condition                                         | Result   | Evidence                                                                                                                                                                                                                                                       |
| --- | ------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Same package                                      | **PASS** | Every file modified lives under `packages/charter/` (substrate) or `.github/workflows/` (CI config) or `docs/_meta/` (records).                                                                                                                                |
| 2   | Additive surface (no rename / remove / repurpose) | **PASS** | `_PortableLtree` class shape preserved; `_LtreeColumn` is a new private class living alongside; no public symbol renamed or removed. The `_PortableLtree.load_dialect_impl` signature is unchanged; only the function body changes one expression on one line. |
| 3   | OCSF schema stability                             | **N/A**  | Substrate, no OCSF surface.                                                                                                                                                                                                                                    |
| 4   | F.6 audit-chain vocabulary additive               | **N/A**  | No audit-action change.                                                                                                                                                                                                                                        |
| 5   | CLI surface unchanged                             | **PASS** | No CLI touch.                                                                                                                                                                                                                                                  |
| 6   | Python public API params unchanged                | **PASS** | `_PortableLtree`'s constructor and `load_dialect_impl` signature unchanged. `_LtreeColumn` is private (underscore-prefixed); not exported; not in any `__all__`. `PlaybookModel.path` type annotation unchanged.                                               |

**3 PASS + 2 N/A** — matches the plan's stated eligibility-test result.

---

## §6. Watch-items — final audit

Four watch-items were declared at plan open. Each was verified per-task and is verified one final time at plan close.

### WI-1 — `packages/charter/` UNTOUCHED EXCEPT `models.py` lines 92-130 + `tests/test_portable_ltree.py`

**Held.** `git diff --stat <plan-base>..HEAD packages/charter/` across the entire plan branch sequence returns exactly:

```
packages/charter/src/charter/memory/models.py    | 27 +++++++++++++++++++++++++--
packages/charter/tests/test_portable_ltree.py    | 141 ++++++++++++++++++++++++++
```

Two files. The substrate fix is `+25 / −2` in `models.py`; the new test file is `+141` in `tests/`. **No other charter file touched.** The bounded inversion of WI-1 ("charter is the target, but precisely") held exactly as the plan specified.

### WI-2 — NO AGENT MODIFIED (all 10 agents incl. cloud-posture)

**Held.** Per-agent `git diff --stat <plan-base>..HEAD packages/agents/<agent>/` returns empty for every one of: `audit`, `cloud-posture`, `identity`, `investigation`, `k8s-posture`, `multi-cloud-posture`, `network-threat`, `remediation`, `runtime-threat`, `vulnerability`. The Task 6 evidence-of-record **cites** agent test code (the KG-loop live test source) but does NOT modify it.

### WI-3 — Other carry-forwards remain separately sequenced

**Held.** This plan resolved §13.2 (the LTREE bug); it did NOT execute KG-loop §13.1 (cross-run dedup) or KG-loop §13.3 (the letter-vs-spirit deviation retro-point). The plan's hard scope boundary held. The newly-surfaced SET LOCAL `$1` bug from Task 5 is also separately sequenced.

The three carry-forwards (§11) are recorded explicitly with named owners.

### WI-4 — Diagnostic preserved through Tasks 1-6, retired by Task 7

**Resolved at Task 7.** PR #42 closed, branch `diagnostic/f5-ltree-bug-repro` deleted from origin, workflow file retired alongside the branch. The red-signal CI run `26082292289` remains immutable on GitHub Actions; closing the PR + deleting the branch does not erase it.

---

## §7. Coverage delta

| Lane                  | Pre-plan (main @ `c3e398c`)                                                                                         | Post-plan (this branch)                                                                                                              | Delta                                                                                                |
| --------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| Full repo pytest      | 2722 passed, 23 skipped                                                                                             | 2728 passed, 23 skipped                                                                                                              | **+6 passed** (Task 3's mocked unit tests)                                                           |
| Charter unit tests    | 6 tests against `_PortableLtree` aiosqlite-fallback only (existed in `test_models.py` / `test_procedural_store.py`) | + 6 NEW tests covering `_LtreeColumn` get_col_spec + `_PortableLtree` Postgres-dialect routing + fallback + class-shape preservation | +6 tests; new coverage of the Postgres-dialect path that previously had ZERO test coverage           |
| Charter F.5 live-lane | Never run green anywhere (LTREE blocked all 6 tests at fixture setup)                                               | 1 PASS (alembic-upgrade-head) + 5 FAIL (SET LOCAL, separately tracked)                                                               | **1 net new PASS on real Postgres — first F.5 live-lane PASS ever**                                  |
| CI workflows          | 2 (`ci.yml`, `lint.yml`)                                                                                            | 3 (`ci.yml`, `lint.yml`, `charter-f5-live.yml`)                                                                                      | +1 permanent CI workflow that catches LTREE-class latent substrate regressions automatically forever |

---

## §8. KG-loop regression evidence

Per Task 6 (commit `70bca20`, evidence-of-record [`f5-ltree-fix-task-6-kg-loop-regression-guard-2026-05-19.md`](f5-ltree-fix-task-6-kg-loop-regression-guard-2026-05-19.md)).

The plan-row-6 letter assumed a fresh kg-loop-live CI run against the patched branch HEAD. Empirical reality: `kg-loop-live.yml` is not on `origin/main` (PR #38 — the KG-loop SAFETY-CRITICAL — is still OPEN). Importing the workflow + live test from the KG-loop branch to this plan's branch would violate WI-2 + WI-3. Task 6 was therefore adapted to a structural-orthogonality argument anchored to three empirical facts:

1. **Task 1 grep audit (Surface 2)**: `_PortableLtree` has exactly one production consumer (`PlaybookModel.path` via alembic baseline import).
2. **Task 2 substrate diff**: `+25 / −2` confined to `_PortableLtree.load_dialect_impl`'s Postgres branch — physically cannot affect any other code path.
3. **KG-loop live test source** (`packages/agents/cloud-posture/tests/integration/test_kg_loop_live_postgres.py` on the KG-loop branch): calls `Base.metadata.create_all(tables=[EntityModel.__table__, RelationshipModel.__table__])` — never materializes `playbooks` — therefore `_PortableLtree.load_dialect_impl` is never invoked by any KG-loop code path.

**Two structurally-disjoint surfaces.** No shared state, no shared invocation chain, no shared DDL emission. A regression of the KG-loop loop by the LTREE fix is structurally impossible given the empirical diff — not "unlikely to happen," structurally impossible.

**Empirical baseline cited**: KG-loop keystone CI run [`26055249482`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26055249482) — 3 passed in 2.46s on `edae2b9` (2026-05-18). This baseline pre-dates the LTREE fix; the fix did not alter `EntityModel`, `RelationshipModel`, `SemanticStore`, or any code these three tests invoke.

**Future empirical confirmation pathway (predicted)**: when PR #38 merges to main, any subsequent PR touching `packages/charter/src/charter/memory/**` will fire kg-loop-live automatically. Predicted result per the structural argument: 3 green tests in ~2.46s, identical pattern to the keystone baseline. A future deviation = real regression signal warranting investigation. The prediction is recorded explicitly so it cannot be silently ignored.

---

## §9. Breaking-change note

**None.** The substrate fix is byte-equivalent at the SQL-emission layer:

| Surface                                       | Pre-fix (intended)                                       | Pre-fix (actual)       | Post-fix                                |
| --------------------------------------------- | -------------------------------------------------------- | ---------------------- | --------------------------------------- |
| `playbooks.path` column DDL against Postgres  | `LTREE`                                                  | Crash (AttributeError) | `LTREE` (identical to intended pre-fix) |
| `playbooks.path` column DDL against aiosqlite | `VARCHAR(512)`                                           | `VARCHAR(512)`         | `VARCHAR(512)` (unchanged)              |
| `PlaybookModel.path` Python annotation        | `str`                                                    | `str`                  | `str` (unchanged)                       |
| `_PortableLtree` class shape                  | `impl=String, cache_ok=True, load_dialect_impl(dialect)` | Same                   | Same (unchanged)                        |
| Public API exports                            | (none — `_PortableLtree` is private)                     | Same                   | Same (unchanged)                        |

The DDL the substrate emits is now what the substrate _intended_ to emit. The fix restores the contract; it does not change it.

---

## §10. Hard-scope-boundary preserved

The plan's hard scope boundary, stated up-front:

> _"This plan fixes the LTREE column-type defect in `_PortableLtree.load_dialect_impl` ONLY."_

End-state verification:

- ✅ **No other charter source file changed.** WI-1 held.
- ✅ **No agent change.** WI-2 held across all 10 agents.
- ✅ **No other `_Portable*` type touched.** `_PortableJSONB`, `_PortableVector` etc. all unchanged.
- ✅ **No SQLAlchemy version bump.** Workspace pin remains at 2.0.49.
- ✅ **No KG-loop §13.1 fix.** Cross-run AFFECTS-edge dedup remains a separately-tracked debt.
- ✅ **No KG-loop §13.3 retro-point.** Cloud-posture live test still uses `Base.metadata.create_all(tables=...)`; retro-point to `alembic upgrade head` is a separately-tracked future follow-up.
- ✅ **No SET LOCAL `$1` fix.** Newly surfaced; out of scope; separately tracked.

**Three knobs locked, exactly as the plan specified.** One substrate file, one column-type fix, one permanent CI workflow.

---

## §11. Carry-forward debts (verbatim per operator directive 2026-05-20)

Three named, tracked follow-ups. Each is recorded with a named owner so a future reader can act on it without re-deriving the context.

### §11.1 SET LOCAL `$1` tenant-RLS substrate bug — NEWLY SURFACED

**Status**: KNOWN, NAMED, TRACKED, out of scope for this plan.

**The bug**: `packages/charter/src/charter/memory/` (exact location TBD by the successor plan) issues SQL of the form:

```
SET LOCAL app.tenant_id = $1::VARCHAR
```

Postgres' `SET LOCAL` does NOT accept parameter placeholders — the value must be inlined or quoted. The result: `PostgresSyntaxError: syntax error at or near "$1"` on every code path that tries to set the tenant context for RLS. This is a separate substrate bug in charter's F.4/F.5 tenant-RLS code, distinct from the LTREE bug this plan resolved.

**Why it lived undetected until 2026-05-20**: it was masked by the LTREE bug. The LTREE `AttributeError` fired at fixture setup, blocking every F.5 live-lane test from reaching the body that would have hit SET LOCAL. With LTREE fixed, the masked bug becomes visible for the first time. **The permanent `charter-f5-live.yml` workflow surfaced it within hours of Task 4 going live** — exactly what Task 4 was designed to do.

**Empirical evidence**: 5 of the 6 F.5 live tests fail with this SQL in [CI run `26088948053`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26088948053): `test_crud_round_trip_on_all_four_tables`, `test_pgvector_ann_returns_top_k_by_cosine_distance`, `test_rls_isolates_tenants_on_episodes`, `test_rls_isolates_tenants_on_playbooks`, `test_rls_isolates_tenants_on_entities`.

**Why this plan did NOT fix it (per operator directive 2026-05-20, verbatim)**:

> _"Park the SET LOCAL tenant-RLS bug. Close this LTREE plan honestly with what's proven. The SET LOCAL bug is a separately-surfaced finding affecting tenant-isolation, not blocking single-tenant agent development. Treating it as a separately-tracked debt — same pattern as how LTREE itself was tracked after the KG-loop plan before its own fix plan. Do NOT extend this plan to fix SET LOCAL. Do NOT bundle."_

**Named owner**: future "tenant-RLS substrate-fix" plan. That plan will:

1. Locate the offending code paths (likely in `charter.memory.service.MemoryService.session(tenant_id=...)` or wherever `SET LOCAL` is constructed).
2. Replace parameterized `SET LOCAL` with either string-inlined `SET LOCAL` (quoted + escaped) or a `SELECT set_config('app.tenant_id', :tid, true)` equivalent that DOES accept parameters.
3. Re-run the `charter-f5-live.yml` workflow against the patched substrate; expect **6 PASS** (the keystone proof of the future plan).
4. Update this verification record (or its successor) to mark §11.1 RESOLVED.

**Real defect status**: KNOWN, NAMED, TRACKED, NOT SILENTLY FORGOTTEN.

### §11.2 Cross-run AFFECTS-edge dedup — CARRY-FORWARD FROM KG-LOOP §13.1

**Status**: KNOWN, NAMED, TRACKED. Carried unchanged from the KG-loop closure verification record [§13.1](kg-loop-closure-verification-2026-05-18.md#131-cross-run-affects-edge-dedup-is-out-of-scope-for-v01).

**Original operator wording (verbatim, from the KG-loop Task 3 approval, 2026-05-18)**:

> _"Cross-run AFFECTS-edge dedup is out of scope for v0.1; the graph will accumulate duplicate edges across repeated Cloud Posture runs until a future substrate-level uniqueness guarantee addresses it. This is known, accepted, and must not be silently forgotten."_

**Scope of the v0.1 dedup that IS implemented** (proven against real Postgres by KG-loop Task 6's CI run `26055249482`):

- Per `KnowledgeGraphWriter` instance (= per `agent.run(...)` call).
- Per `(finding_id, asset_external_id)` pair.
- Asserted by `tests/test_kg_writer.py` (4 dedup tests) and proven against real Postgres by `tests/integration/test_kg_loop_live_postgres.py::test_repeated_write_within_one_writer_yields_exactly_one_AFFECTS_edge`.

**What v0.1 does NOT cover**: cross-run duplicates. If `agent.run(...)` fires twice against the same SemanticStore, the second run's `KnowledgeGraphWriter` instance starts with an empty dedup table and will re-emit `add_relationship` for arns the prior run already related. **The graph accumulates duplicate AFFECTS rows across runs.**

**Why this plan does NOT fix it**: this plan was scoped to the LTREE substrate bug only. The cross-run dedup fix is a substrate-uniqueness change (likely a UNIQUE constraint on `(tenant_id, src_entity_id, dst_entity_id, relationship_type)` at the `RelationshipModel` layer + migration + backfill) — a different substrate work item with its own scope, watch-items, and SAFETY-CRITICAL discipline.

**Named owner**: future "substrate-uniqueness-for-relationships" plan. Logical sequencing: the tenant-RLS fix at §11.1 likely lands first (it's in the active substrate-fix-plan queue and unblocks more tests); the cross-run dedup work can land in parallel or after.

### §11.3 KG-loop §13.3 letter-vs-spirit deviation — NEWLY UNBLOCKED, NOT RETRO-POINTED

**Status**: KNOWN, NAMED, TRACKED. **Newly UNBLOCKED by Task 2 of this plan.** NOT retro-pointed here.

**Background (from the KG-loop closure verification record [§13.3](kg-loop-closure-verification-2026-05-18.md#133-plan-row-6-letter-vs-spirit-deviation-alembic--basemetadatacreate_all))**: the KG-loop closure plan's row 6 letter said the cloud-posture live test should use `alembic upgrade head` against real Postgres. The actual implementation in [`packages/agents/cloud-posture/tests/integration/test_kg_loop_live_postgres.py`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/blob/feat/kg-loop-task-6-live-postgres-proof/packages/agents/cloud-posture/tests/integration/test_kg_loop_live_postgres.py) uses `Base.metadata.create_all(tables=[EntityModel.__table__, RelationshipModel.__table__])` — **because the F.5 LTREE substrate bug made `alembic upgrade head` against real Postgres impossible**. The deviation was honestly disclosed.

**Status as of this plan close**: Task 2's LTREE fix removes that blocker. `alembic upgrade head` against real Postgres now works for the first time in F.5's history — proven empirically by Task 5's `test_alembic_upgrade_head_creates_all_tables_and_extensions` PASS in CI run `26088948053`. **The §13.3 deviation is newly unblocked.** A future plan CAN retro-point the cloud-posture live test from `Base.metadata.create_all(tables=...)` back to `alembic upgrade head`.

**Why this plan does NOT execute that retro-point** (per the plan's hard scope boundary, verbatim):

> _"NOT the KG-loop §13.3 letter-vs-spirit deviation. This plan resolves §13.2 which §13.3 depends on, but does NOT retro-point the KG-loop test at `alembic upgrade head`. Task 6 of this plan **notes** that §13.3 becomes newly-unblocked for a future follow-up plan; it does **not** execute that follow-up."_

**Caveat**: the retro-point is only fully safe once the SET LOCAL `$1` bug at §11.1 is also fixed. The full F.5 alembic baseline includes the RLS migration `0002_memory_rls`, which exercises the tenant-RLS code path. Retro-pointing the KG-loop test today (before §11.1 is fixed) might cause the test to surface the SET LOCAL bug — which would be a regression for the cloud-posture live test. The right sequencing: §11.1 lands first; then §11.3 retro-point can proceed.

**Named owner**: future "cloud-posture-test-restore" follow-up plan. Sequencing constraint: blocks on §11.1 closure. Until then, the deviation stays in place as honestly disclosed.

### §11.4 (process-discovery, not a debt) — CI as keystone-proof pattern

Recorded for posterity; this is not a debt that needs fixing, but a pattern that recurs:

**Pattern**: CI workflow surfaces a latent substrate bug within hours of going live, blocking the original plan-row's letter and forcing an honest rescope.

**Observed twice now**:

1. KG-loop plan: Task 6/6a's `kg-loop-live.yml` first runs were RED. Three CI iterations surfaced three real bugs (path off-by-one, missing psycopg2, **LTREE substrate bug**) — none in loop logic. The LTREE bug was the one that survived as a debt for THIS plan to fix.
2. F.5 LTREE plan: Task 4's `charter-f5-live.yml` first run surfaced the SET LOCAL `$1` bug. Now carried forward to §11.1.

**Implication**: permanent CI workflows targeting real infrastructure are extraordinarily effective at surfacing latent substrate bugs. Every future "substrate-fix" plan should ship its own permanent CI workflow as part of the fix, AND expect that workflow's first run to surface NEW bugs that would otherwise stay latent. **The rescope-honestly discipline is the right response, not a sign of plan failure.**

---

## §12. Forward references / next-plan gate

The F.5 LTREE substrate fix is one of several substrate-maintenance items the platform owes. v0.1 here is intentionally narrow (LTREE only); the path forward depends on later plans.

| Future plan                                          | Purpose                                                                                                                                                                                                | Trigger / gate                                                                                                                                               |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Tenant-RLS substrate fix** (§11.1)                 | Resolve the `SET LOCAL $1` syntax error in charter's tenant-RLS code paths. Unblock charter F.5 live lane to full 6 PASS.                                                                              | **Most-likely-next.** Surfaced 2026-05-20 by this plan's Task 4 workflow. Unblocks §11.3 (KG-loop test retro-point).                                         |
| **Substrate-uniqueness for relationships** (§11.2)   | Resolve KG-loop §13.1. Stop the KG graph from accumulating duplicate AFFECTS rows across repeated agent runs.                                                                                          | After §11.1 (no logical dependency, but the substrate-fix-plan queue is sequenced one at a time per the operator's "do not bundle" discipline).              |
| **Cloud-posture-test-restore** (§11.3)               | Retro-point `test_kg_loop_live_postgres.py` from `Base.metadata.create_all(tables=...)` to `alembic upgrade head`. Honor the original KG-loop plan-row-6 letter once the substrate fully supports it.  | Blocks on §11.1 closure (so the RLS migration `0002_memory_rls` runs cleanly).                                                                               |
| **Other `_Portable*` type review** (no plan yet)     | Check whether `_PortableJSONB`, `_PortableVector`, `_PortableArray` etc. have analogous latent bugs that would only surface against real Postgres.                                                     | Opportunistic. The `charter-f5-live.yml` workflow will catch any of these automatically the next time a PR touches `packages/charter/src/charter/memory/**`. |
| **SQLAlchemy version bump** (no plan yet)            | If/when a later SA 2.0.x release ships `postgresql.LTREE` natively, optionally swap `_LtreeColumn` back to the stock attribute.                                                                        | Optional. The current fix is permanent and correct; a version-bump plan would be a one-line swap. Not urgent.                                                |
| **Agent build-out** (per operator directive, "NEXT") | Resume the agent track per the operator's 2026-05-20 directive: _"After this LTREE plan closes: HOLD. Do NOT start the SET LOCAL fix. The next plan is the agent build-out, not more substrate work."_ | After plan close. Wait for operator direction.                                                                                                               |

**Next-plan gate enforced by this verification record**: per operator directive 2026-05-20, do NOT auto-start the SET LOCAL fix. Hold after plan close. Await operator direction on the agent build-out.

---

## §13. Conclusion

v0.1 of the F.5 LTREE substrate fix is **complete and verified**. The keystone live proof is GREEN on the LTREE-fix-dependent test (CI run `26088948053`, `test_alembic_upgrade_head_creates_all_tables_and_extensions` PASSED). The first F.5 alembic-against-real-Postgres success ever, against a clean reproducible CI environment.

The discipline patterns (verification records, watch-items, ADR-011 PR flow, named carry-forward debts, CI-as-keystone-proof, honest rescope when CI surfaces unrelated bugs) are mature and demonstrably working. Tasks 5 and 6 both gracefully adapted to empirical realities the plan-row letters couldn't have anticipated — without violating watch-items, without bundling scope, without silent corner-cutting. The permanent `charter-f5-live.yml` workflow's value is already proven within hours of going live.

Three follow-ups are named, tracked, recorded verbatim per the operator directive, with explicit owners. **None are silently forgotten.**

The plan is closed. **HOLD per operator directive 2026-05-20.** Do NOT auto-start the tenant-RLS fix or any other substrate work. The next plan is the agent build-out, awaiting operator direction.

---

## §14. Cross-references

- Plan: [`docs/superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md`](../superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md)
- ADR-009 (memory architecture): [`docs/_meta/decisions/ADR-009-memory-architecture.md`](decisions/ADR-009-memory-architecture.md)
- ADR-010 (within-agent extension template, substrate-adapted here): [`docs/_meta/decisions/ADR-010-within-agent-version-extension-template.md`](decisions/ADR-010-within-agent-version-extension-template.md)
- ADR-011 (PR-flow + branch-protection discipline): [`docs/_meta/decisions/ADR-011-pr-flow-discipline.md`](decisions/ADR-011-pr-flow-discipline.md)
- KG-loop closure verification record (the source-of-record for §13.2 LTREE, §13.1 cross-run dedup, §13.3 deviation): [`kg-loop-closure-verification-2026-05-18.md`](kg-loop-closure-verification-2026-05-18.md)
- Task 1 grep audit: [`f5-ltree-fix-task-1-grep-audit-2026-05-19.md`](f5-ltree-fix-task-1-grep-audit-2026-05-19.md)
- Task 5 live proof: [`f5-ltree-fix-task-5-live-proof-2026-05-19.md`](f5-ltree-fix-task-5-live-proof-2026-05-19.md)
- Task 6 KG-loop regression guard: [`f5-ltree-fix-task-6-kg-loop-regression-guard-2026-05-19.md`](f5-ltree-fix-task-6-kg-loop-regression-guard-2026-05-19.md)
- Task 7 diagnostic cleanup: [`f5-ltree-fix-task-7-diagnostic-cleanup-2026-05-20.md`](f5-ltree-fix-task-7-diagnostic-cleanup-2026-05-20.md)
- Substrate file (the one modified): [`packages/charter/src/charter/memory/models.py`](../../packages/charter/src/charter/memory/models.py) (Task 2 changed lines 92-130)
- Mocked unit tests: [`packages/charter/tests/test_portable_ltree.py`](../../packages/charter/tests/test_portable_ltree.py)
- Permanent CI workflow: [`.github/workflows/charter-f5-live.yml`](../../.github/workflows/charter-f5-live.yml)
- Pre-fix red-signal CI run: <https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26082292289> (immutable; preserved after diagnostic cleanup)
- Post-fix keystone CI run: <https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26088948053>
