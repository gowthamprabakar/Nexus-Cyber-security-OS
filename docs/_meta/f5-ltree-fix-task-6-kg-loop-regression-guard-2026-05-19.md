# F.5 LTREE substrate fix — Task 6 KG-loop keystone regression guard

**Plan-row-6 evidence-of-record for the F.5 LTREE substrate-fix plan** ([`docs/superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md`](../superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md)). The plan-row goal: confirm that Task 2's LTREE substrate fix does not regress the KG-loop closure plan's keystone proof (CI run [`26055249482`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26055249482), which closed the KG read/write loop against real Postgres on 2026-05-18).

This Task 6 also **notes** that the KG-loop §13.3 letter-vs-spirit deviation becomes newly-unblocked by Task 2's fix, but explicitly **does NOT execute the retro-point** — that is a separate follow-up plan per the F.5 LTREE plan's hard scope boundary.

## State of the empirical situation

The plan-row-6 letter assumes a fresh CI run of `.github/workflows/kg-loop-live.yml` against the patched branch HEAD. The empirical situation at this commit is:

| Fact                                                                                                                                                                         | Verification                                                                                                                                          |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/kg-loop-live.yml` does NOT exist on `origin/main`                                                                                                         | `git ls-tree origin/main -- .github/workflows/` returns only `ci.yml` + `lint.yml`                                                                    |
| PR #38 (KG-loop Task 6 SAFETY-CRITICAL containing the kg-loop-live workflow + the live test) is still OPEN                                                                   | `gh pr view 38 --json state,mergedAt` returns `{"mergedAt":null,"state":"OPEN"}`                                                                      |
| The kg-loop-live workflow file lives on branch `feat/kg-loop-task-6-live-postgres-proof` (commits `e50e7c2` → `edae2b9`) — a parallel pending stack, NOT this plan's lineage | `git log --all --oneline -- .github/workflows/kg-loop-live.yml` returns only those KG-loop-branch commits                                             |
| Task 6 of this plan cannot trigger a fresh kg-loop-live run on this branch because the workflow file isn't here                                                              | A `workflow_dispatch` requires the workflow to be on the default branch; a `pull_request` trigger requires the workflow file to exist on the head ref |

**The plan-row-6 letter cannot be executed today as written.** Instead, this record uses the same honest-rescope discipline as Task 5: do what CAN be empirically demonstrated, name what cannot, and assign the future verification to a tracked follow-up.

## What CAN be empirically demonstrated — structural orthogonality

The LTREE fix at Task 2 (`acfc830`) and the KG-loop keystone proof (CI run `26055249482`) operate on **structurally disjoint code paths**. The argument is precise, not hand-wavy:

### The LTREE fix's blast radius

Per [`docs/_meta/f5-ltree-fix-task-1-grep-audit-2026-05-19.md`](f5-ltree-fix-task-1-grep-audit-2026-05-19.md) (Task 1's empirical grep audit) and [`docs/_meta/f5-ltree-fix-task-5-live-proof-2026-05-19.md`](f5-ltree-fix-task-5-live-proof-2026-05-19.md) (Task 5's live proof), Task 2's substrate change is **confined to the function body of `_PortableLtree.load_dialect_impl` at `packages/charter/src/charter/memory/models.py:104-108`**:

- New private class `_LtreeColumn(UserDefinedType[str])` added (private; not exported).
- Line 106 swap: `postgresql.LTREE()` → `_LtreeColumn()`.
- `# type: ignore[attr-defined]` comment removed.

**That is the entire substrate diff: `+25 / −2` in one file.** The fix is invoked ONLY when SQLAlchemy needs to emit DDL for a column of type `_PortableLtree` against the Postgres dialect.

### Which production paths use `_PortableLtree`

Per Task 1's grep audit (Surface 2): the ONLY consumer of `_PortableLtree` in the entire codebase is the ORM declaration of `PlaybookModel.path` (verified via `from charter.memory.models import _PortableJSONB, _PortableLtree, _PortableVector` at `packages/charter/alembic/versions/0001_memory_baseline.py:39`). No other ORM model, no other table, no other code path references `_PortableLtree`.

Therefore: **the LTREE fix is invoked if and only if the `playbooks` table is materialized against the Postgres dialect**.

### What KG-loop's live test materializes

The KG-loop live test at [`packages/agents/cloud-posture/tests/integration/test_kg_loop_live_postgres.py`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/blob/feat/kg-loop-task-6-live-postgres-proof/packages/agents/cloud-posture/tests/integration/test_kg_loop_live_postgres.py) — the file whose CI runs produced the keystone proof — calls `Base.metadata.create_all(tables=[EntityModel.__table__, RelationshipModel.__table__])`. **It materializes only `entities` and `relationships`.** Per the KG-loop closure verification record §13.3, this was a deliberate workaround precisely because the F.5 baseline alembic migration could not materialize against real Postgres (the LTREE bug).

`PlaybookModel.path` is **never materialized** by the KG-loop test. The LTREE column DDL is **never emitted** by the KG-loop test's setup. Therefore `_PortableLtree.load_dialect_impl` is **never invoked** by any code path the KG-loop test exercises.

### The conclusion

| Surface                                            | LTREE fix exercises it?                                                                             | KG-loop test exercises it?                               |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `_PortableLtree.load_dialect_impl` Postgres branch | ✅ YES (the fix is here)                                                                            | ❌ NO (playbooks never materialized)                     |
| `_LtreeColumn.get_col_spec()`                      | ✅ YES (the new emitter)                                                                            | ❌ NO (never invoked)                                    |
| `playbooks` table                                  | ✅ YES (the only table using `_PortableLtree`)                                                      | ❌ NO (test only materializes entities + relationships)  |
| `entities` + `relationships` tables                | ❌ NO (LTREE fix doesn't touch these tables' DDL — they use `_PortableJSONB`, not `_PortableLtree`) | ✅ YES (the KG-loop test's full materialization surface) |

**The two surfaces are structurally disjoint.** No production code path is exercised by both. Therefore the LTREE fix cannot regress the KG-loop loop path: there is no shared state, no shared invocation chain, no shared DDL emission.

This is not a probabilistic argument ("it's unlikely to regress"); it is a structural argument ("the code paths do not intersect"). A regression would require the LTREE fix to somehow modify code that runs against `entities` or `relationships` materialization — and the empirical diff of Task 2 (`+25 / −2` in one file's `_PortableLtree.load_dialect_impl` region) makes that physically impossible.

## What CANNOT be empirically demonstrated today

A **fresh CI run** of `kg-loop-live.yml` against a branch HEAD that includes Task 2's LTREE substrate fix. Not because the regression risk is meaningful — the structural argument above rules it out — but because the workflow file isn't on main yet, and bringing it onto this Task 6 branch would require either (a) pulling in `kg_writer.py` + `agent.py` rewires + `test_kg_loop_live_postgres.py` + `kg-loop-live.yml` from a parallel still-open PR (out of scope; WI-2/WI-3 violation) or (b) coordinating a stacked PR through the KG-loop Task 6 PR's merge (out of scope for this plan).

The **future** empirical confirmation pathway, once PR #38 merges to main:

1. Any subsequent PR that touches `packages/charter/src/charter/memory/**` (which the LTREE fix did) will fire `kg-loop-live.yml` automatically via its paths-filter.
2. That run will exercise the KG-loop loop against the LTREE-patched substrate.
3. The expected result, per the structural argument above: **3 green tests in ~2.46s, identical pattern to keystone run `26055249482`.**

This Task 6 evidence-of-record predicts that result. If a future run contradicts the prediction, that is a real regression signal that this record's structural argument missed something; it would warrant immediate investigation. The prediction is recorded here precisely so a future deviation is impossible to silently ignore.

### Baseline citation

The empirical baseline against which any future regression check is compared: **CI run [`26055249482`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26055249482) — 3 passed in 2.46s on branch `feat/kg-loop-task-6-live-postgres-proof` HEAD `edae2b9` (2026-05-18).** All three tests:

1. `test_loop_closes_via_memory_neighbors_walk_against_real_postgres` — the keystone read/write loop closes.
2. `test_repeated_write_within_one_writer_yields_exactly_one_affects_edge` — the within-run REPEATED-WRITE dedup proven.
3. `test_skip_kg_path_does_not_touch_substrate` — semantic_store=None leaves substrate untouched.

This baseline existed BEFORE the LTREE substrate fix landed. The fix did not alter `EntityModel`, `RelationshipModel`, `SemanticStore`, or any code these three tests invoke.

## KG-loop §13.3 is newly-unblocked — but NOT addressed here

The KG-loop closure verification record [`kg-loop-closure-verification-2026-05-18.md`](kg-loop-closure-verification-2026-05-18.md) §13.3 documented a deliberate deviation from plan-row-6's letter: the cloud-posture live test used `Base.metadata.create_all(tables=[EntityModel.__table__, RelationshipModel.__table__])` instead of `alembic upgrade head` **because the F.5 LTREE substrate bug made the full F.5 alembic baseline impossible to materialize against real Postgres**.

That blocker is now lifted. With Task 2's LTREE fix, `alembic upgrade head` against real Postgres completes for the first time in F.5's history (empirically proven by Task 5's `test_alembic_upgrade_head_creates_all_tables_and_extensions` PASS). **A future plan can therefore retro-point the cloud-posture live test from `Base.metadata.create_all(tables=...)` back to `alembic upgrade head` if desired.**

**This Task 6 explicitly does NOT execute that retro-point.** Per the F.5 LTREE plan's hard scope boundary: _"NOT the KG-loop §13.3 letter-vs-spirit deviation. This plan resolves §13.2 which §13.3 depends on, but does NOT retro-point the KG-loop test at `alembic upgrade head`. Task 6 of this plan **notes** that §13.3 becomes newly-unblocked for a future follow-up plan; it does **not** execute that follow-up."_

This evidence-of-record is the **notation**. Task 8's plan-closer verification record will carry §13.3 forward as **newly-unblocked but unaddressed**, joined by the SET LOCAL `$1` finding and the cross-run AFFECTS dedup carry-forward from KG-loop §13.1.

## Watch-items at this proof

| #    | Item                                                                                   | Verification                                                                                                                              |
| ---- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| WI-1 | charter UNTOUCHED EXCEPT `models.py` lines 92-130 + `tests/test_portable_ltree.py`     | Doc-only PR. ✅                                                                                                                           |
| WI-2 | NO AGENT MODIFIED (all 10 agents incl. cloud-posture)                                  | Doc-only PR. ✅                                                                                                                           |
| WI-3 | Other carry-forwards separately sequenced; KG-loop §13.3 retro-point NOT executed here | This record **notes** §13.3 newly-unblocked; does NOT execute the retro-point. Carry-forward to Task 8 and to a future follow-up plan. ✅ |
| WI-4 | Diagnostic preserved until Task 7                                                      | No workflow file touched. Diagnostic branch + PR #42 + workflow file all still alive at this commit. ✅                                   |

## Cross-references

- [Plan](../superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md) — the F.5 LTREE substrate-fix plan; this document is row 6's evidence-of-record.
- [Task 1 grep audit](f5-ltree-fix-task-1-grep-audit-2026-05-19.md) — empirical confirmation that `_PortableLtree` has exactly one consumer (the `playbooks.path` ORM column).
- [Task 5 live proof](f5-ltree-fix-task-5-live-proof-2026-05-19.md) — empirical confirmation that the LTREE fix is invoked correctly when `playbooks` IS materialized against real Postgres.
- [KG-loop closure verification](kg-loop-closure-verification-2026-05-18.md) §13.3 — the letter-vs-spirit deviation this record marks as newly-unblocked.
- [KG-loop keystone CI run `26055249482`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26055249482) — the empirical baseline against which any future regression check is compared.
- KG-loop Task 6 SAFETY-CRITICAL PR #38 (still OPEN) — the parallel pending PR containing `kg-loop-live.yml`. Future merge of this PR enables the post-LTREE-fix empirical regression check via the paths-filter.

---

**This is Task 6's evidence-of-record.** No fresh CI run; structural-orthogonality argument with empirical baseline citation, honestly disclosed. No charter touch, no agent touch, no §13.3 retro-point.
