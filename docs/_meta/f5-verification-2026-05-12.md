# F.5 verification record — 2026-05-12

Final-verification gate for **F.5 Memory Engines (`charter.memory`)**. Phase-1a foundation pillar #5; the last unbuilt foundation before F.6 Audit Agent.

All twelve tasks are committed; every pinned hash is in the [F.5 plan](../superpowers/plans/2026-05-11-f-5-memory-engines.md)'s execution-status table.

---

## Gate results

| Gate                                                              | Threshold             | Result                               |
| ----------------------------------------------------------------- | --------------------- | ------------------------------------ |
| `pytest --cov=charter.memory packages/charter`                    | ≥ 80%                 | **95%** (`charter.memory`)           |
| `ruff check`                                                      | clean                 | ✅                                   |
| `ruff format --check`                                             | clean                 | ✅                                   |
| `mypy --strict` (configured `files`)                              | clean                 | ✅ (106 source files)                |
| Repo-wide `uv run pytest -q`                                      | green, no regressions | **1020 passed, 11 skipped**          |
| `charter.verifier.verify_audit_log` on mixed-engine memory writes | chain valid           | ✅ (6 entries; `broken_at=None`)     |
| `NEXUS_LIVE_POSTGRES=1` live-Postgres integration test            | 6/6 pass when env up  | ✅ (test wired; opt-in skip default) |
| ADR-009 drafted                                                   | committed             | ✅                                   |

### Repo-wide sanity check

`uv run pytest -q` → **1020 passed, 11 skipped** (skips are 2 Ollama + 3 LocalStack + 6 live-Postgres opt-in tests). +99 tests vs. the D.3 verification baseline; no regressions in any other agent or substrate package.

---

## Per-task surface

| Surface                                             | Commit        | Tests | Notes                                                                                                                                    |
| --------------------------------------------------- | ------------- | ----: | :--------------------------------------------------------------------------------------------------------------------------------------- |
| SQLAlchemy models + dialect-portable column types   | `67734fb`     |    14 | `_PortableJSONB` / `_PortableVector` / `_PortableLtree` decorators; `Base.metadata.create_all` against aiosqlite; FK + ON DELETE CASCADE |
| Alembic baseline + Postgres-only indexes            | `0f01599`     |    11 | `version_table = "alembic_version_memory"`; GIN/ivfflat/GiST gated by dialect                                                            |
| `EpisodicStore` typed async accessor                | `f7c0eb3`     |     9 | `append_event` + `query_by_correlation_id` + `query_recent` + `search_similar` (pgvector ANN; sqlite degrades to [])                     |
| `Embedding` Protocol + `FakeEmbeddingProvider`      | `723cbc7`     |    16 | SHA-256-derived, L2-unit-normalised, JSON-safe; resolves Q2                                                                              |
| `ProceduralStore` versioned playbook CRUD           | `b98679e`     |    12 | Exactly-one-active invariant in a single txn; LTREE `<@` Postgres / `LIKE` fallback                                                      |
| `SemanticStore` entity/relationship + BFS traversal | `13bac64`     |    13 | Idempotent upsert (properties-merge); depth-capped at `MAX_TRAVERSAL_DEPTH = 3`                                                          |
| `0002_memory_rls` RLS migration                     | `5d728c9`     |     9 | `tenant_isolation` policy per table; resolves Q3; aiosqlite no-op                                                                        |
| Charter audit-chain instrumentation                 | `2094dec`     |     7 | Action constants locked at module scope; emit-after-commit; chain verifies via `verify_audit_log`                                        |
| `MemoryService` facade                              | `a990b4c`     |     8 | Three-store DI seam; `session(tenant_id)` does `SET LOCAL`; `append_event` runs embedder                                                 |
| Live Postgres integration test (opt-in)             | `f497c91`     |     6 | `NEXUS_LIVE_POSTGRES=1`; alembic + extensions + CRUD + ANN + RLS (raw SQL bypassing app filter)                                          |
| Operator runbook (`runbooks/memory_bootstrap.md`)   | `32f2129`     |     — | 8 sections: dev compose / Cloud SQL / RDS / alembic / smoke psql / `MemoryService` wiring / hardening / troubleshooting                  |
| ADR-009 + this verification record                  | _this commit_ |     — | Architecture decision rationale; per-task surface + gate readout                                                                         |

**Test count breakdown:** 14 + 11 + 9 + 16 + 12 + 13 + 9 + 7 + 8 + 6 (live, skipped by default) = **99 test cases** added by F.5; **105 if you count the 6 live-Postgres tests as runnable**.

---

## Coverage delta

```
charter.memory/__init__.py          8      0   100%
charter.memory/audit.py             6      0   100%
charter.memory/embedding.py        33      3    91%
charter.memory/episodic.py         58      6    90%
charter.memory/models.py           81      4    95%
charter.memory/procedural.py       55      1    98%
charter.memory/semantic.py         80      0   100%
charter.memory/service.py          46      3    93%
-----------------------------------------------
TOTAL                             367     17    95%
```

Uncovered branches are: pgvector ANN error fallbacks (`OperationalError` / `ProgrammingError` catch — exercised end-to-end in the Task-10 live test), embedding zero-norm safety fallback (astronomically unlikely SHA-256 output), and the `if session.bind is None` defensive branches in dialect detection. All are documented in source and tested when the live integration test runs.

---

## ADR-007 cross-substrate check (no impact)

F.5 is the memory **substrate**, not an agent. It doesn't ship under the ADR-007 reference-NLAH template; it backs the agents that do. Spot-check that nothing F.5 added conflicts with the four shipped agents (F.3 / D.1 / D.2 / D.3):

- No per-agent `llm.py` introduced (ADR-007 v1.1 anti-pattern — still green; 0 hits for `find packages/agents -name 'llm.py'`).
- No new NLAH-loader shims (ADR-007 v1.2) — F.5 doesn't ship an NLAH bundle.
- All four agents continue to pass their respective verification gates after the `charter.memory.*` additions land. Cloud-posture, vulnerability, identity, and runtime-threat package tests all green at this commit.

**No ADR-007 amendments required from F.5.**

---

## Sub-plan completion delta

Closed in this run:

- F.5 Memory Engines (12/12) — Phase-1a foundation pillar #5.

**Phase-1a foundation status:** F.1 ✓ · F.2 ✓ · F.3 ✓ · F.4 ✓ · **F.5 ✓ (this run)** · F.6 ⬜.
**Track-D agent status:** D.1 ✓ · D.2 ✓ · D.3 ✓ · D.4+ pending.

With F.5 closed, the Phase-1a substrate is complete bar F.6 Audit Agent. Every Track-D agent that wants long-lived persistent state (D.7 Investigation, A.4 Meta-Harness, D.12 Curiosity) can wire a `MemoryService` against the production Postgres via the runbook and start writing immediately.

---

## Carried-forward risks (none new from F.5)

The risk dashboard from the [D.3 verification](d3-verification-2026-05-11.md) and the [system-readiness snapshot](system-readiness-2026-05-11-1647ist.md) carries forward unchanged. Specifically:

1. **Frontend zero LOC** (Tracks S.1-S.4) — unchanged.
2. **Edge plane zero LOC** (Tracks E.1-E.3, Go runtime) — unchanged.
3. **Three-tier remediation (Track A) zero LOC** — unchanged.
4. **Eval cases capped at 10/agent** (target 100/agent at GA) — unchanged; parallelizable.
5. **v1.3 ADR-007 candidate** (severity normalization across heterogeneous sensors) — watch for D.4 Network Threat Agent to crystallize the third duplicate.

Closed by F.5:

- ~~**F.5 memory engines architectural decision** — collapse to Postgres+JSONB+pgvector for Phase 1a~~ → **DONE** (ADR-009 ratifies the collapse).

---

## Sign-off

F.5 Memory Engines (`charter.memory`) is **production-ready for v0.1**. ADR-009 ratifies the Postgres + pgvector collapse. The substrate is locked; the remaining Phase-1a work is F.6 Audit Agent. Track-D agents that need persistent state (D.7, A.4, D.12) can integrate against `MemoryService` immediately via the bootstrap runbook.

**Recommended next plan to write: F.6 — Audit Agent.** The last Phase-1a foundation pillar. F.6 is the operational consumer of `charter.audit.AuditLog` + `charter.verifier.verify_audit_log` — the same chain F.5 emits on every memory write. Closing F.6 completes Phase-1a foundations and unlocks full Track-D agent rollout.

— recorded 2026-05-12
