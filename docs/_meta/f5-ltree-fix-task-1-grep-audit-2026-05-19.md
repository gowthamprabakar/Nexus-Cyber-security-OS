# F.5 LTREE substrate fix — Task 1 empirical grep audit (2026-05-19)

**Audit-of-record for Task 1 of the F.5 LTREE substrate-fix plan.** Confirms empirically that **the broken `postgresql.LTREE` reference at `packages/charter/src/charter/memory/models.py:106` is the one and only such reference in the entire codebase.** Task 8 (the plan-closer verification record) pulls this audit into its full record verbatim.

The plan's §"Settled context" asserts the single-line invariant as text: _"Nothing outside `_PortableLtree` references `postgresql.LTREE` directly."_ Task 1 makes the assertion empirical at execution-time so a future drift is caught at audit-time rather than at migration-time — same discipline as the KG-loop Task 2 grep audit.

## Audit parameters

| Field        | Value                                                                                                                      |
| ------------ | -------------------------------------------------------------------------------------------------------------------------- |
| Audit date   | 2026-05-19                                                                                                                 |
| Branch       | `feat/f5-ltree-task-1-grep-audit` (stacked on `plan/f5-ltree-substrate-fix`)                                               |
| Plan         | [`docs/superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md`](../superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md) |
| Plan row     | Row 1 — "grep audit confirming no other `postgresql.LTREE` references in `packages/`"                                      |
| Search scope | `packages/` (entire monorepo source tree — agents, charter, shared, eval-framework, control-plane, content-packs, edge)    |
| Operator     | gowthamprabakar                                                                                                            |

## Five search surfaces

The audit covers five independent surfaces. A broken-LTREE reference anywhere in the codebase would surface in at least one of them; the empirical result is that the only code-level match is the single line being fixed.

### Surface 1 — `postgresql.LTREE` (the broken attribute reference itself)

```
$ grep -rn "postgresql\.LTREE" packages/
packages/charter/src/charter/memory/models.py:106:            return dialect.type_descriptor(postgresql.LTREE())  # type: ignore[attr-defined]
```

**Result: ONE match — exactly the line Task 2 of this plan modifies.** No other file in `packages/` references `postgresql.LTREE`. This is the empirical confirmation of the plan's single-line invariant: the bug is contained to one expression in one function in one file.

### Surface 2 — `ltree` imports (case-insensitive)

```
$ grep -rn -E "^(import|from).*[Ll]tree" packages/
packages/charter/alembic/versions/0001_memory_baseline.py:39:from charter.memory.models import _PortableJSONB, _PortableLtree, _PortableVector
```

**Result: ONE match — and it's the charter substrate's own private type, not a third-party LTREE source.** The alembic baseline migration imports `_PortableLtree` from `charter.memory.models` (the same file Task 2 modifies). After Task 2 lands, this import continues to work bit-for-bit identically because `_PortableLtree`'s class shape, name, and module path do not change. **Zero third-party LTREE imports anywhere in the codebase** — confirming that the plan's chosen fix (an inline private `UserDefinedType`) does not need to displace any existing import.

### Surface 3 — `LtreeType` (sqlalchemy-utils-style usage)

```
$ grep -rn "LtreeType" packages/
(no matches)
```

**Result: ZERO matches across `packages/`.** Confirms that no part of the codebase uses (or has ever used) `sqlalchemy-utils.LtreeType` or any analogous third-party LTREE type wrapper. The plan's "Alternatives considered" Option B (adding `sqlalchemy-utils`) would have introduced a new dependency surface; this audit confirms there is no existing surface that the option could have aligned with.

### Surface 4 — `LTREE()` invocation shape

```
$ grep -rnE "LTREE\(\)" packages/
packages/charter/src/charter/memory/models.py:106:            return dialect.type_descriptor(postgresql.LTREE())  # type: ignore[attr-defined]
```

**Result: ONE match — same line as Surface 1.** Confirms there is no other `LTREE()` constructor call anywhere in `packages/`. The fix's one-line swap (`postgresql.LTREE()` → `_LtreeColumn()` at line 106) is the only call-site that needs to change.

### Surface 5 (sanity) — bare `LTREE` token anywhere in Python source code

```
$ grep -rn "LTREE" packages/ --include="*.py"
packages/agents/audit/src/audit/schemas.py:81:    # filesystem paths can be long. 512 matches the LTREE column ceiling
packages/charter/tests/test_procedural_store.py:13:   LTREE path is a descendant of `prefix` (and `prefix` itself).
packages/charter/tests/test_procedural_store.py:14:   On aiosqlite, the LTREE column is `String(512)`; the store falls
packages/charter/tests/test_procedural_store.py:125:# ---------------------------- list_subtree (LTREE) -----------------------
packages/charter/tests/integration/test_memory_live_postgres.py:23:  Postgres-native column types (JSONB, VECTOR, LTREE).
packages/charter/alembic/versions/0001_memory_baseline.py:19:- `ix_playbooks_path_gist` — GiST over LTREE for the `<@` / `@>`
packages/charter/alembic/versions/0001_memory_baseline.py:38:# the JSONB / pgvector / LTREE fallbacks.
packages/charter/src/charter/memory/procedural.py:5:are addressed by an LTREE-shaped hierarchical path
packages/charter/src/charter/memory/procedural.py:18:LTREE subtree containment (`<@`) is Postgres-only. On aiosqlite the
packages/charter/src/charter/memory/procedural.py:22:`path` is a descendant of `a.b` under the LTREE dot-separated taxonomy.
packages/charter/src/charter/memory/procedural.py:183:        OR `path LIKE prefix || '.%'` — same semantics for the LTREE
packages/charter/src/charter/memory/models.py:27:column types (JSONB native, pgvector VECTOR, LTREE) appear in the
packages/charter/src/charter/memory/models.py:93:    """Dialect-portable LTREE — Postgres-native LTREE, String fallback elsewhere.
packages/charter/src/charter/memory/models.py:98:    LTREE-specific operators behind a dialect check.
packages/charter/src/charter/memory/models.py:106:            return dialect.type_descriptor(postgresql.LTREE())  # type: ignore[attr-defined]
```

**Result: 15 matches across `packages/`. Of these, exactly 1 is code (line 106 — the bug being fixed). All other 14 are docstrings, comments, or test docstrings.**

Breakdown by category (zero scope creep for the fix):

| Category                                             | Count             | Match locations                                                                                                                 | Significance for Task 2's fix                                                                   |
| ---------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Code-level `postgresql.LTREE()` call**             | 1                 | `models.py:106`                                                                                                                 | **THE ONLY LINE TASK 2 CHANGES.**                                                               |
| Docstring text mentioning "LTREE" as a concept       | 8                 | `procedural.py` × 4, `models.py` × 3, `test_procedural_store.py` × 1                                                            | Documentation, not code. Task 2's banner comment may update some; the rest stay. No fix needed. |
| Comment text mentioning "LTREE" as a concept         | 5                 | `audit/schemas.py:81`, `test_procedural_store.py` × 1, `test_memory_live_postgres.py:23`, `alembic/0001_memory_baseline.py` × 2 | Comments only, not code references.                                                             |
| `_PortableLtree` class name (in import or test file) | 0 in this surface | (counted in Surface 2 instead)                                                                                                  | Class name preserved by Task 2; no rename.                                                      |

**No category requires Task 2 to touch any file other than `models.py`.** The fix is genuinely confined to the single broken line, plus the new `_LtreeColumn` class added in the same file. No collateral edit is needed in `procedural.py`, `alembic/0001_memory_baseline.py`, `test_procedural_store.py`, `test_memory_live_postgres.py`, or `audit/schemas.py` — their LTREE references are descriptive, not behavioural.

## Summary table

| Surface                                                                        | Invocation                                          | Code-level matches outside `models.py:106`                  | Code-level matches at `models.py:106` | Total matches |
| ------------------------------------------------------------------------------ | --------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------- | ------------- |
| 1 — `postgresql.LTREE`                                                         | `grep -rn "postgresql\.LTREE" packages/`            | **0**                                                       | 1                                     | 1             |
| 2 — ltree imports                                                              | `grep -rn -E "^(import\|from).*[Ll]tree" packages/` | 1 (own `_PortableLtree` import in alembic; not third-party) | 0                                     | 1             |
| 3 — `LtreeType` (third-party shape)                                            | `grep -rn "LtreeType" packages/`                    | **0**                                                       | 0                                     | **0**         |
| 4 — `LTREE()` invocation                                                       | `grep -rnE "LTREE\(\)" packages/`                   | **0**                                                       | 1                                     | 1             |
| 5 — bare `LTREE` token (sanity)                                                | `grep -rn "LTREE" packages/ --include="*.py"`       | 14 (all in docstrings / comments)                           | 1                                     | 15            |
| **TOTAL code-level `postgresql.LTREE` references outside the one being fixed** |                                                     | **0**                                                       |                                       |               |
| **TOTAL third-party LTREE library usage anywhere**                             |                                                     | **0**                                                       |                                       |               |

## Conclusion

**Empirically confirmed: `postgresql.LTREE` is referenced in exactly one place in the entire codebase — the line being fixed by Task 2 at `packages/charter/src/charter/memory/models.py:106`.** No other file in `packages/` calls `postgresql.LTREE()`, imports anything related to LTREE from `sqlalchemy.dialects.postgresql`, or uses a third-party LTREE type. The plan's chosen fix (inline `_LtreeColumn` `UserDefinedType` private to `models.py`) genuinely confines the change to the one expression on the one line.

This audit closes Task 1 of the plan and locks in the plan's §"Settled context" claim:

> _"Nothing outside `_PortableLtree` references `postgresql.LTREE` directly."_

The audit makes that claim empirical, not assumed.

## Watch-items (this PR)

| #    | Watch-item                                                                                             | Verification                                                                                                                                                              |
| ---- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WI-1 | `packages/charter/` UNTOUCHED EXCEPT lines 92-110 of `models.py` + new `tests/test_portable_ltree.py`  | This PR's diff is `docs/_meta/f5-ltree-fix-task-1-grep-audit-2026-05-19.md` + the plan-row-1 hash-pin. `git diff --stat <base>..HEAD packages/charter/` returns empty. ✅ |
| WI-2 | NO AGENT MODIFIED (all 10 agents incl. cloud-posture)                                                  | This PR adds a single docs file under `docs/_meta/` + the plan-row-1 hash-pin. Zero `packages/` changes. ✅                                                               |
| WI-3 | Other carry-forwards (cross-run dedup, KG-loop §13.3 retro-point) remain separately sequenced          | This PR does not touch `packages/agents/cloud-posture/tests/integration/test_kg_loop_live_postgres.py` or any agent code. ✅                                              |
| WI-4 | Diagnostic at `.github/workflows/f5-ltree-diagnostic.yml` + PR #42 + branch stay in place until Task 7 | This PR does not touch any workflow file. ✅                                                                                                                              |

## Re-run instructions

The audit is reproducible. From the repo root:

```bash
# Surface 1
grep -rn "postgresql\.LTREE" packages/

# Surface 2
grep -rn -E "^(import|from).*[Ll]tree" packages/

# Surface 3
grep -rn "LtreeType" packages/

# Surface 4
grep -rnE "LTREE\(\)" packages/

# Surface 5 (sanity)
grep -rn "LTREE" packages/ --include="*.py"
```

Outputs should match the §"Five search surfaces" blocks above byte-for-byte at the audit-time HEAD. After Task 2 lands, the expected drift in subsequent re-runs:

- **Surface 1** will return **zero matches** (the broken line is gone).
- **Surface 2** result unchanged (the own-import in alembic stays).
- **Surface 3** still zero (no third-party LTREE library introduced).
- **Surface 4** will return **zero matches** (the `postgresql.LTREE()` call is replaced by `_LtreeColumn()`).
- **Surface 5** (bare LTREE token) gains 1–2 new matches inside `models.py` for the new `_LtreeColumn.get_col_spec` return value (`"LTREE"` as a string) and possibly its docstring. Net result: still confined to `models.py`.

Any re-run that surfaces a `postgresql.LTREE` match in any file other than `models.py:106` (pre-Task-2) or anywhere (post-Task-2) is a scope-creep regression and the corresponding PR is rejected.

## Cross-references

- [`docs/superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md`](../superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md) — the plan that owns Task 1; row 1 of its execution-status table is hash-pinned to this PR's HEAD by a paired doc-only commit.
- [`docs/_meta/kg-loop-closure-verification-2026-05-18.md`](kg-loop-closure-verification-2026-05-18.md) §13.2 — the source-of-record for the substrate bug being fixed; cross-checked against the audit results here.
- [`packages/charter/src/charter/memory/models.py:106`](../../packages/charter/src/charter/memory/models.py#L106) — the single code-level `postgresql.LTREE` reference in the codebase; Task 2 modifies this line.
- Task 8 verification record (forthcoming at plan close) — will quote this audit's summary table verbatim under its scope-boundary audit section.
