# F.5 LTREE substrate fix — Task 5 load-bearing live proof (rescoped)

**Plan-row-5 evidence-of-record for the F.5 LTREE substrate-fix plan** ([`docs/superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md`](../superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md)). This document captures the load-bearing proof that Task 2's substrate fix actually works against real Postgres — **the first time charter's F.5 baseline migration has materialized against a real Postgres instance in this project's history.**

The proof is **honestly rescoped** from the plan-row-5 letter ("F.5 live lane (all 6 tests) goes GREEN") to what the CI run empirically demonstrates: **1 PASS + 5 separately-tracked FAILs that are not the LTREE bug.** The rescope decision is recorded explicitly in §"Why this proof is rescoped" below; the SET LOCAL `$1` finding that surfaced behind the LTREE fix is named as a separately-tracked debt for a future tenant-RLS substrate-fix plan.

## Proof-of-record

### A.1-§8-style evidence block

Per the discipline established by [`a1-safety-verification-2026-05-16.md`](a1-safety-verification-2026-05-16.md) §8.

```
DATE:                       2026-05-19 (CI run); this record landed 2026-05-20
CI RUN URL:                 https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26088948053
CI RUN STATUS:              completed / failure (overall)
CI RUN DURATION:            ~37s (test phase), ~80s (full job incl. service-container spin-up)
HEAD AT RUN:                d8bc969 (the Task 4 permanent-CI-workflow branch tip after row-4 hash-pin)
WORKFLOW:                   .github/workflows/charter-f5-live.yml (committed at 32897b8 in Task 4)
RUNNER IMAGE:               ubuntu-24.04
POSTGRES SERVICE IMAGE:     pgvector/pgvector:pg16 (Postgres 16 + pgvector + ltree preinstalled)
POSTGRES PROVISIONING:      POSTGRES_USER=nexus / POSTGRES_PASSWORD=nexus_dev / POSTGRES_DB=nexus
                            (matches docker/docker-compose.dev.yml exactly; nexus is created as
                             a superuser by initdb so the test's admin DSN reaches the default
                             `postgres` admin DB without per-env overrides)
HEALTHCHECK:                pg_isready -U nexus (5s interval, 10 retries) — job-start gated on healthy
SYNC DRIVER:                psycopg2-binary installed at job-step (CI-only need for alembic's sync env)
SCHEMA INSTALLATION:        Real alembic upgrade head against the migrated DB (the F.5 baseline
                            migration `0001_memory_baseline` runs to completion for the first
                            time ever against real Postgres)
TESTS RUN:                  6 (charter F.5 live lane, packages/charter/tests/integration/test_memory_live_postgres.py)
TESTS PASSED:               test_alembic_upgrade_head_creates_all_tables_and_extensions
TESTS FAILED (NOT LTREE):   test_crud_round_trip_on_all_four_tables
                            test_pgvector_ann_returns_top_k_by_cosine_distance
                            test_rls_isolates_tenants_on_episodes
                            test_rls_isolates_tenants_on_playbooks
                            test_rls_isolates_tenants_on_entities
RESULT (RESCOPED):          1 passed / 5 failed (separately tracked); LTREE bug PROVEN FIXED;
                            SET LOCAL $1 bug PROVEN NEWLY-VISIBLE
OPERATOR (CI):              github-actions[bot] under PR-checks identity
COMPARISON (CONTROL):       Diagnostic CI run 26082292289 (2026-05-19, pre-fix, branch
                            diagnostic/f5-ltree-bug-repro): 6 ERRORS at fixture setup, every one
                            blocked by AttributeError at models.py:106 (`postgresql.LTREE`). The
                            F.5 baseline migration never completed.
```

### Verified-against-HEAD

All evidence above derives from CI run `26088948053`, which ran against branch HEAD `d8bc969` (the Task 4 permanent-CI-workflow branch tip after the row-4 hash-pin commit). The branch SHA is verifiable via `gh run view 26088948053 --json headSha`. This document's claims do not derive from any local-machine state or editor working tree — they derive exclusively from CI evidence at a named branch commit.

---

## What this proof DOES prove

### 1. Task 2's LTREE fix works against real Postgres — first ever F.5 alembic-against-real-Postgres success

**The keystone single passing test is `test_alembic_upgrade_head_creates_all_tables_and_extensions`.** This test:

1. Drops + creates a fresh Postgres test database (`nexus_memory_test`) via the `fresh_database` fixture.
2. Runs `alembic upgrade head` against that database using `_run_migrations()` — drives the full F.5 baseline migration `0001_memory_baseline` + the F.5 RLS migration `0002_memory_rls`.
3. Asserts the resulting schema contains the four F.5 tables (`episodes`, `playbooks`, `entities`, `relationships`) AND the two required Postgres extensions (`vector`, `ltree`) AND the LTREE-using GiST index on `playbooks.path` (`ix_playbooks_path_gist`).

Before Task 2's substrate fix (commit `acfc830`), this test errored at fixture setup with:

```
AttributeError: module 'sqlalchemy.dialects.postgresql' has no attribute 'LTREE'
packages/charter/src/charter/memory/models.py:106
```

— captured empirically by diagnostic CI run [`26082292289`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26082292289) on the same provisioning shape (`pgvector/pgvector:pg16`, `POSTGRES_USER=nexus`, etc.). All 6 F.5 live tests errored at fixture setup; none reached the test body.

After Task 2's substrate fix, this test **PASSES**. The `playbooks.path` LTREE column materializes correctly against real Postgres. The `_LtreeColumn` `UserDefinedType` (private to `models.py`) emits the correct `LTREE` DDL on the Postgres dialect path. **For the first time in F.5's history (since 2026-05-12), charter's F.5 baseline migration completes end-to-end against a real Postgres instance in a clean reproducible environment.**

This is the load-bearing claim of the LTREE substrate-fix plan. **It is proven by execution.**

### 2. The keystone CI lane itself is now real, permanent, and exercising real Postgres

Task 4's `charter-f5-live.yml` workflow is now live. The root cause that allowed the LTREE bug to live latent for ~11 days — _"nothing in CI ever exercised the substrate's Postgres-dialect path"_ — is structurally closed. Every future PR that touches `packages/charter/src/charter/memory/**`, `packages/charter/alembic/**`, `packages/charter/tests/integration/test_memory_live_postgres.py`, or the workflow file itself fires this workflow and runs the F.5 live lane against real Postgres. Substrate regressions of this class will be caught at PR-review time going forward.

### 3. The fix is minimal and reversible

The substrate diff is `+25 / −2` in one file (`packages/charter/src/charter/memory/models.py`). No other charter file changed. No agent file changed. Both invariants verifiable across the plan's commit history:

- `git diff --stat <plan-base>..HEAD packages/charter/` → only `models.py` and the new `tests/test_portable_ltree.py`.
- `git diff --stat <plan-base>..HEAD packages/agents/` → empty across all 10 agents.

---

## What this proof does NOT prove (and the rescope rationale)

### Why this proof is rescoped from "6 GREEN" to "1 PASS + 5 separately-tracked FAIL"

Plan row 5 said: _"the same provisioning shape that produced the red diagnostic CI run [`26082292289`] now produces a green run on this branch."_

The post-Task-2 CI run on the same provisioning shape **does NOT produce a fully green run.** It produces:

- **1 PASS**: `test_alembic_upgrade_head_creates_all_tables_and_extensions` — the LTREE-dependent migration test. This is **the test that was specifically blocked by the LTREE bug**. Its PASS is the empirical proof of the LTREE fix.

- **5 FAIL**: every one with the same root cause:

  ```
  sqlalchemy.exc.ProgrammingError: ... PostgresSyntaxError: syntax error at or near "$1"
  [SQL: SET LOCAL app.tenant_id = $1::VARCHAR]
  ```

These 5 failures are **NOT LTREE failures**. They originate in charter's tenant-RLS code path (the F.4/F.5 row-level-security wiring) — a separate substrate bug that was always present but was **masked** by the LTREE crash. The LTREE crash fired at fixture setup, blocking every test from reaching the body that would have hit the `SET LOCAL $1` issue. With LTREE fixed, the masked bug becomes visible for the first time.

This finding is **out of scope for the F.5 LTREE substrate-fix plan**. The plan's hard scope boundary, stated explicitly up-front, is _"ONE bug, ONE fix, the minimal surface required."_ Extending the plan to fix the second bug would violate that boundary. Per the operator's 2026-05-20 directive: **the SET LOCAL bug is parked as a separately-tracked debt** (see Task 8 verification record for the §13-style entry).

The rescope is therefore honest, not a deferral of a failure: **what this plan committed to fixing is empirically fixed; what surfaced behind it is documented and assigned to a future plan.**

### The cross-check that confirms the rescope is honest

Compare the diagnostic CI run `26082292289` (pre-fix) and this CI run `26088948053` (post-fix), with the same provisioning shape and the same six tests:

| Test                                                          | Pre-fix (run 26082292289)      | Post-fix (run 26088948053) | What this confirms                                                                |
| ------------------------------------------------------------- | ------------------------------ | -------------------------- | --------------------------------------------------------------------------------- |
| `test_alembic_upgrade_head_creates_all_tables_and_extensions` | ERROR (LTREE at fixture setup) | ✅ **PASSED**              | LTREE bug FIXED                                                                   |
| `test_crud_round_trip_on_all_four_tables`                     | ERROR (LTREE at fixture setup) | FAIL (`SET LOCAL $1`)      | Reached test body — confirms LTREE no longer blocks; SET LOCAL is the new ceiling |
| `test_pgvector_ann_returns_top_k_by_cosine_distance`          | ERROR (LTREE at fixture setup) | FAIL (`SET LOCAL $1`)      | Same                                                                              |
| `test_rls_isolates_tenants_on_episodes`                       | ERROR (LTREE at fixture setup) | FAIL (`SET LOCAL $1`)      | Same                                                                              |
| `test_rls_isolates_tenants_on_playbooks`                      | ERROR (LTREE at fixture setup) | FAIL (`SET LOCAL $1`)      | Same                                                                              |
| `test_rls_isolates_tenants_on_entities`                       | ERROR (LTREE at fixture setup) | FAIL (`SET LOCAL $1`)      | Same                                                                              |

Six pre-fix errors of the same root cause → 1 post-fix PASS + 5 post-fix fails of a DIFFERENT root cause. **The change in failure mode is itself the proof that one bug went away** and a different, previously-masked bug is now visible.

### What still needs proving for full F.5 lane green (out of scope here)

- **The `SET LOCAL $1` tenant-RLS substrate bug must be fixed.** That work belongs to a future "tenant-RLS substrate-fix" plan with its own scope, its own watch-items, its own SAFETY-CRITICAL discipline. Named explicitly in Task 8's verification record.
- After that fix lands, charter's F.5 live lane (the same six tests) should run **6 PASS** in the permanent `charter-f5-live.yml` workflow. That will be the future plan's load-bearing proof.

### What this proof EXPLICITLY does not claim

- ❌ "F.5's live lane is green." (Honest: 1 of 6 passes; 5 are blocked by a separately-tracked bug.)
- ❌ "All F.5 substrate bugs are fixed." (Honest: LTREE is fixed; SET LOCAL is parked.)
- ❌ "The tenant-RLS code path works against real Postgres." (Honest: not exercised; blocked by the new finding.)
- ❌ "Charter F.5 is production-ready against real Postgres." (Honest: single-tenant alembic schema-installation works; tenant-isolation queries do not.)

These claims would only become true after the future tenant-RLS substrate-fix plan completes.

---

## Watch-items at this proof

| #    | Item                                                                               | Verification                                                                                                                                              |
| ---- | ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WI-1 | charter UNTOUCHED EXCEPT `models.py` lines 92-130 + `tests/test_portable_ltree.py` | `git diff --stat <plan-base>..HEAD packages/charter/` shows exactly those two files. ✅                                                                   |
| WI-2 | NO AGENT MODIFIED (all 10 agents incl. cloud-posture)                              | Per-agent diff empty across the entire plan branch sequence. ✅                                                                                           |
| WI-3 | Other carry-forwards remain separately sequenced                                   | No KG-loop test or agent code touched. The SET LOCAL bug **adds** a third carry-forward (alongside KG-loop §13.1 cross-run dedup) — see Task 8 record. ✅ |
| WI-4 | Diagnostic preserved until Task 7                                                  | Branch `diagnostic/f5-ltree-bug-repro` + draft PR #42 + workflow file `f5-ltree-diagnostic.yml` all still alive at this commit. Task 7 cleans them up. ✅ |

---

## Cross-references

- [Plan](../superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md) — the F.5 LTREE substrate-fix plan; this document is row 5's evidence-of-record.
- [KG-loop closure verification](kg-loop-closure-verification-2026-05-18.md) §13.2 — the source-of-record for the LTREE bug. This plan resolves §13.2's claim.
- [Task 1 grep audit](f5-ltree-fix-task-1-grep-audit-2026-05-19.md) — empirically confirmed `postgresql.LTREE` was referenced only at `models.py:106`.
- [`packages/charter/src/charter/memory/models.py`](../../packages/charter/src/charter/memory/models.py) — the file Task 2 modified (`+25 / −2`); the new private `_LtreeColumn(UserDefinedType[str])` lives at lines 92-113.
- [`packages/charter/tests/test_portable_ltree.py`](../../packages/charter/tests/test_portable_ltree.py) — Task 3's mocked unit tests; 6 pass; the unit-layer regression net.
- [`.github/workflows/charter-f5-live.yml`](../../.github/workflows/charter-f5-live.yml) — Task 4's permanent CI workflow; this proof's source-of-truth runner.
- [CI run 26088948053](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26088948053) — this proof's evidence-source URL.
- [CI run 26082292289](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26082292289) — the pre-fix control run (diagnostic workflow) that establishes the LTREE-blocking baseline.

---

**This is the rescoped Task 5 evidence-of-record. Agent does NOT merge — bringing the full report to the operator per the SAFETY-CRITICAL discipline.**
