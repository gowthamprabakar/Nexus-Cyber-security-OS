# KG-loop Task 2 — empirical grep audit (2026-05-18)

**Audit-of-record for Task 2 of the KG-loop-closure plan.** Confirms empirically that **no agent other than `cloud-posture` has a Neo4j writer** at the time the reroute starts. Task 8 (the KG-loop closure verification record) pulls this audit into its full record verbatim.

The plan's §"Settled context" asserts the single-agent invariant as text. Task 2 makes the assertion empirical at execution-time so a future drift is caught at audit-time rather than at migration-time — same discipline as the F.7 v0.2 verification record's per-task watch-item evidence blocks.

## Audit parameters

| Field              | Value                                                                                                                                                                      |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Audit date         | 2026-05-18                                                                                                                                                                 |
| Branch             | `feat/kg-loop-task-2-grep-audit`                                                                                                                                           |
| HEAD at audit time | `3f5c5c9` (= `origin/main` after PR #33 merge)                                                                                                                             |
| Plan               | [`docs/superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md`](../superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md) |
| Plan row           | Row 2 — "audit-of-record: empirical grep audit to confirm no agent other than Cloud Posture has a Neo4j writer"                                                            |
| Search scope       | `packages/` (entire monorepo source tree — agents, shared, charter, infra)                                                                                                 |
| Operator           | gowthamprabakar                                                                                                                                                            |

## Six search invocations

The audit covers six independent surfaces. A Neo4j writer in some other agent would surface in at least one of them; absence across all six is the evidence the single-agent invariant holds.

### Invocation 1 — `from neo4j …` import surface

```
$ grep -rn "from neo4j" packages/
(no matches)
```

**Result: zero matches across `packages/`.** No code anywhere in the monorepo imports a symbol from the `neo4j` package. (The cloud-posture `neo4j_kg.py` deliberately uses `Any` instead of the `AsyncDriver` type — see Invocation 3 — so this returns empty even for the dormant writer.)

### Invocation 2 — `import neo4j` / `from neo4j ` import surface

```
$ grep -rn "^import neo4j\b\|^from neo4j " packages/
(no matches)
```

**Result: zero matches across `packages/`.** Confirms there is no bare `import neo4j` either. The runtime dependency exists (Invocation 5) but no Python source consumes it via direct import.

### Invocation 3 — `AsyncDriver` type-usage surface

```
$ grep -rn "AsyncDriver" packages/
packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py:4:(`neo4j.AsyncDriver`). Per the per-tenant isolation requirement (ADR-004,
```

**Result: one match — inside a docstring in the dormant `neo4j_kg.py` (cloud-posture only).** Spot-checked via `Read` against [`packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py`](../../packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py) lines 1–15: the dormant module's module docstring references `neo4j.AsyncDriver` as the protocol it consumes, but the actual code (lines 11–15) deliberately types the driver as `Any` so the writer stays decoupled from upstream driver-shape churn across minor versions. The type-annotation surface for `AsyncDriver` in production code is **zero across the whole monorepo, including inside the dormant writer.**

### Invocation 4 — `KnowledgeGraphWriter` class-shape surface

```
$ grep -rn "KnowledgeGraphWriter" packages/
packages/agents/cloud-posture/src/cloud_posture/agent.py:51:from cloud_posture.tools.neo4j_kg import KnowledgeGraphWriter
packages/agents/cloud-posture/src/cloud_posture/agent.py:117:        kg = KnowledgeGraphWriter(driver=neo4j_driver, customer_id=customer_id)
packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py:36:class KnowledgeGraphWriter:
packages/agents/cloud-posture/tests/test_neo4j_kg.py:6:from cloud_posture.tools.neo4j_kg import KnowledgeGraphWriter
packages/agents/cloud-posture/tests/test_neo4j_kg.py:27:    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")
packages/agents/cloud-posture/tests/test_neo4j_kg.py:49:    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")
packages/agents/cloud-posture/tests/test_neo4j_kg.py:60:    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")
packages/agents/cloud-posture/tests/test_neo4j_kg.py:82:    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")
packages/agents/cloud-posture/tests/test_neo4j_kg.py:108:    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")
```

**Result: 9 matches — all confined to `packages/agents/cloud-posture/`.** Breakdown:

- 1 × class definition (the dormant writer at `tools/neo4j_kg.py:36`).
- 2 × cloud-posture agent.py references (line 51 import + line 117 usage). These get rewired by Task 3 to import `kg_writer.KnowledgeGraphWriter` (new) and consume `semantic_store` instead of `neo4j_driver`. The dormant `tools/neo4j_kg.py` class continues to exist — same class name lives in both files, Python's module-prefix import path disambiguates them. Task 7 verifies the dormant file's preservation.
- 1 × import in the existing test file `tests/test_neo4j_kg.py:6`. Retained per Task 7's dormancy verification — the dormant writer's tests stay green, proving the writer's surface is still functionally intact for the Phase-2 swap path.
- 5 × test-method-local instantiations in `tests/test_neo4j_kg.py` (lines 27 / 49 / 60 / 82 / 108).

**Zero matches in any other agent's `src/` or `tests/`.** Confirms the single-agent invariant for the writer-class surface.

### Invocation 5 — `neo4j` dependency surface (pyproject.toml)

```
$ grep -rn "^[[:space:]]*[\"']neo4j[\"><=~]\|^[[:space:]]*neo4j[[:space:]]*[=><~]" packages/*/pyproject.toml packages/agents/*/pyproject.toml
packages/agents/cloud-posture/pyproject.toml:16:    "neo4j>=5.24.0",
```

**Result: one match — `cloud-posture/pyproject.toml` only.** No other agent or shared package declares a `neo4j` runtime dependency. The cloud-posture dependency stays per Task 7 (the dormant `neo4j_kg.py` imports nothing from `neo4j` directly, but the dep is retained against the Phase-2 swap so the dormant writer remains functional if the registry is ever re-pointed at it).

### Invocation 6 — Cypher pattern surface (`MERGE (n:…)` / `MATCH (n:…)` / `CREATE (n:…)`)

```
$ grep -rn -E "MERGE \([a-z]:|MATCH \([a-z]:|CREATE \([a-z]:" packages/agents/*/src/
packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py:18:    "MERGE (a:Asset {customer_id: $customer_id, kind: $kind, "
packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py:24:    "MERGE (f:Finding {customer_id: $customer_id, finding_id: $finding_id}) "
packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py:29:    "MATCH (f:Finding {customer_id: $customer_id, finding_id: $finding_id}) "
packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py:31:    "MERGE (a:Asset {customer_id: $customer_id, external_id: arn}) "
```

**Result: 4 matches — all in the dormant `cloud_posture/tools/neo4j_kg.py`.** The three Cypher templates (`_UPSERT_ASSET_CYPHER` / `_UPSERT_FINDING_CYPHER` / `_RELATE_FINDING_CYPHER`). No other agent constructs Cypher queries.

## Summary table

| Surface                                          | Invocation | Match count outside `cloud-posture` | Match count inside `cloud-posture`       |
| ------------------------------------------------ | ---------- | ----------------------------------- | ---------------------------------------- |
| Import (`from neo4j …`)                          | 1          | **0**                               | 0 (writer types driver as `Any`)         |
| Import (`import neo4j` / `from neo4j `)          | 2          | **0**                               | 0                                        |
| Type usage (`AsyncDriver`)                       | 3          | **0**                               | 1 (docstring only)                       |
| Writer class (`KnowledgeGraphWriter`)            | 4          | **0**                               | 9 (class + agent.py × 2 + test file × 6) |
| Runtime dependency (`neo4j` in `pyproject.toml`) | 5          | **0**                               | 1 (`cloud-posture/pyproject.toml`)       |
| Cypher patterns                                  | 6          | **0**                               | 4 (three templates in dormant module)    |
| **TOTAL**                                        |            | **0**                               | **15 (all expected)**                    |

## Conclusion

**Empirically confirmed: no agent other than `cloud-posture` has a Neo4j writer.** All 15 within-monorepo matches are confined to `packages/agents/cloud-posture/` and accounted for:

- The dormant `tools/neo4j_kg.py` (preserved per Task 7).
- Its existing tests `tests/test_neo4j_kg.py` (retained per Task 7).
- The current agent.py wire-up at lines 51 + 117 (rewired by Task 3 to point at the new `kg_writer.py`; `neo4j_kg.py` is NOT touched in Task 3, preserved dormant).
- The runtime dep declaration in cloud-posture's `pyproject.toml` (retained per Task 7).

The plan's hard scope boundary ("Cloud Posture write-path only; no other agent touched") is therefore not just a stated invariant — it matches the codebase's actual state at the start of execution. Any future PR that adds a `from neo4j` import, a `KnowledgeGraphWriter` class, or a Cypher template in any agent other than `cloud-posture` is a scope-creep regression detectable by re-running this audit.

## Watch-items (this PR)

| #    | Watch-item                                                                 | Verification                                                                                                                                                                                                                                                                                     |
| ---- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| WI-1 | `packages/charter/` UNTOUCHED                                              | This PR's diff is `docs/_meta/kg-loop-task-2-grep-audit-2026-05-18.md` + the plan-row hash-pin. `git diff --stat main..HEAD packages/charter/` returns empty. ✅                                                                                                                                 |
| WI-2 | No other agent `src/` modified                                             | This PR adds a single docs file under `docs/_meta/` + the plan-row hash-pin under `docs/superpowers/plans/`. Zero `packages/` changes. ✅                                                                                                                                                        |
| WI-3 | Neo4j escape-hatch door labelled; `neo4j_kg.py` stays DORMANT, no deletion | This PR does not touch the dormant module. The labelling is at the ADR layer (Task 1) + the file's docstring banner (Task 7, not this PR). The audit above confirms the dormant module exists today and contains the writer surface intact — which is what Task 7 will then docstring-banner. ✅ |

## Re-run instructions

The audit is reproducible. From the repo root:

```bash
# Invocation 1
grep -rn "from neo4j" packages/

# Invocation 2
grep -rn "^import neo4j\b\|^from neo4j " packages/

# Invocation 3
grep -rn "AsyncDriver" packages/

# Invocation 4
grep -rn "KnowledgeGraphWriter" packages/

# Invocation 5
grep -rn "^[[:space:]]*[\"']neo4j[\"><=~]\|^[[:space:]]*neo4j[[:space:]]*[=><~]" packages/*/pyproject.toml packages/agents/*/pyproject.toml

# Invocation 6
grep -rn -E "MERGE \([a-z]:|MATCH \([a-z]:|CREATE \([a-z]:" packages/agents/*/src/
```

Outputs should match the §"Six search invocations" blocks above byte-for-byte at HEAD `3f5c5c9`. After Tasks 3, 4, and 7 land, the expected drift in subsequent re-runs:

- Invocation 4 will gain matches under `cloud_posture/tools/kg_writer.py` (Task 3 — the new `KnowledgeGraphWriter` class) and under `cloud_posture/tests/test_kg_writer.py` (Task 4 — the mocked unit tests).
- All other invocations' result sets should remain identical (the dormant module + its dep + its tests stay; nothing new touches the `neo4j` package).

Any re-run that surfaces a `neo4j`-related match in any agent other than `cloud-posture` is a regression and that PR is rejected per the plan's hard scope boundary.

## Cross-references

- [`docs/superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md`](../superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md) — the plan that owns Task 2; row 2 of its execution-status table is hash-pinned to this PR's HEAD by a paired doc-only commit.
- [`docs/_meta/decisions/ADR-009-memory-architecture.md`](decisions/ADR-009-memory-architecture.md) — the ADR amended by Task 1 (PR #33, merged at `3f5c5c9`). This audit empirically confirms the rule named in the amendment ("Every agent writes to the graph ONLY through `MemoryService.semantic` — no direct database drivers, ever") is **currently held** across the monorepo, with the one disclosed exception (the dormant `cloud_posture/tools/neo4j_kg.py`).
- Task 8 verification record (forthcoming at plan close) — will quote this audit's summary table verbatim under its "dormancy audit + scope-boundary audit" section.
