# ADR-009 — Memory Architecture (`charter.memory` v0.1)

- **Status:** accepted
- **Date:** 2026-05-12
- **Authors:** F.5
- **Stakeholders:** AI/Agent Eng, D.7 Investigation Agent author, A.4 Meta-Harness author, D.12 Curiosity Agent author, control-plane on-call, security review

## Context

[F.5](../../superpowers/plans/2026-05-11-f-5-memory-engines.md) ships `charter.memory`, the substrate that gives Nexus agents long-lived persistent state across three orthogonal access patterns:

- **Episodic** — append-only event history. Agent runs leave a per-event trail (finding emitted, action taken, escalation triggered) that the [D.7 Investigation Agent](../../superpowers/plans/) chains together into incidents and the [A.4 Meta-Harness Agent] reads to score whether last week's NLAH rewrite actually improved behaviour.
- **Procedural** — versioned playbooks and action policies addressed by a hierarchical taxonomy (e.g. `remediation.s3.public_bucket`). The [D.12 Curiosity Agent] picks which idle-time queries to run by walking this tree.
- **Semantic** — entity-relationship knowledge graph (hosts, principals, findings) joined by directed typed edges. Cross-agent enrichment lives here.

The original Phase-1 plan (pre-resolution) called for three separate engines: TimescaleDB for episodic, vanilla Postgres for procedural, Neo4j Aura for semantic. Each was optimised for one access pattern. By the time F.5 began, the [F.4 Q1 resolution](../../superpowers/plans/2026-05-11-f-4-auth-tenant-manager.md) and the [system-readiness snapshot](../system-readiness-2026-05-11-1647ist.md#41-strategy--business-documents-layer-0) had pulled control-plane fully onto Postgres + SQLAlchemy. Operating three databases for memory alongside one for control-plane would have tripled the substrate ops surface — backups, IAM, monitoring, schema migration tooling — for ~80% of access patterns that a single well-indexed Postgres covers.

This ADR locks the resulting architecture decisions.

## Decision

The substrate is structured around six load-bearing decisions.

### D1 — One Postgres + pgvector for all three engines in Phase 1a

Phase 1a collapses TimescaleDB + Postgres + Neo4j into **a single Postgres 16 + pgvector + LTREE instance**. The four memory tables (`episodes`, `playbooks`, `entities`, `relationships`) live in one database with one alembic head.

| Original engine | Original choice                                                       | Phase 1a coverage in vanilla pg16 + pgvector                                                                                                                 |
| --------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Episodic        | TimescaleDB (hypertables, automatic partitioning, retention policies) | `episodes (BRIN-indexed emitted_at, JSONB GIN, pgvector ivfflat)`. TimescaleDB defers to Phase 1b once write volume exceeds ~1M events/day/tenant.           |
| Procedural      | Vanilla Postgres                                                      | `playbooks (LTREE path + GiST index, JSONB body)` — same shape, same dialect. No change.                                                                     |
| Semantic        | Neo4j Aura (Cypher, native graph traversal)                           | `entities + relationships (recursive CTE for traversal, JSONB properties)`. Neo4j defers to Phase 2 if recursive-CTE graph traversal becomes the bottleneck. |

The substrate is not coupled to this collapse — `EpisodicStore`, `ProceduralStore`, and `SemanticStore` each take an `async_sessionmaker[AsyncSession]` and route every query through it. Splitting back out to dedicated engines later is a per-store session-factory swap, not a rewrite.

### D2 — Dialect-portable column types via SQLAlchemy `TypeDecorator`

The Postgres-native column types (`JSONB`, `pgvector.VECTOR(1536)`, `ltree.LTREE`) ship behind three `TypeDecorator`s in `charter.memory.models`: `_PortableJSONB`, `_PortableVector`, `_PortableLtree`. Each falls back to a portable substitute (`JSON`, `JSON`, `String(512)`) when the dialect is anything other than postgresql.

Reasons:

- Unit tests run against in-memory aiosqlite for speed and isolation. The full memory schema materialises via `Base.metadata.create_all` on aiosqlite, so a developer can verify column shape + FK + ON DELETE CASCADE + indexes without standing up Postgres.
- Production runs on Postgres where the native types are used.
- The two paths share one schema definition. No drift.

Dialect-specific operators (`pgvector` cosine distance, `LTREE <@`) live behind dialect checks at query sites, not in the column types. `EpisodicStore.search_similar` returns `[]` on aiosqlite rather than crashing; `ProceduralStore.list_subtree` falls back to `LIKE prefix || '.%'`. Same observable semantics; the live integration test (Task 10) verifies the Postgres path.

### D3 — One alembic head per logical substrate, distinct `version_table`

F.5's alembic config writes to `version_table = "alembic_version_memory"`, not the default `alembic_version`. F.4's control-plane alembic head keeps `alembic_version`. Both can live on the same Postgres instance without colliding.

Reasons:

- Each substrate evolves on its own cadence (memory schema changes are independent from auth schema changes). Sharing one head would couple their release schedules.
- A single `alembic upgrade head` invocation per substrate is easier to reason about than coordinated migrations across heads.
- Recovery is per-substrate: rolling memory back to revision N doesn't require rolling control-plane back.

Per-substrate alembic heads is a general pattern Phase 1b will reuse for the audit substrate (F.6).

### D4 — Row-Level Security as primary tenant isolation; application filter as secondary

Every memory table carries `tenant_id` as a leading column. The `0002_memory_rls` migration enables RLS on all four tables and installs a `tenant_isolation` policy that reads `current_setting('app.tenant_id', true)`. `MemoryService.session(tenant_id=...)` runs `SET LOCAL app.tenant_id = '<tid>'` inside the same transaction the session uses.

Application code still passes `tenant_id` to every store method (which still issues `WHERE tenant_id = ?`). This is intentional: the application-level filter is the secondary defence in case a connection somehow bypasses RLS (BYPASSRLS role, statement-mode pooling, etc.). The operator runbook calls out both gotchas explicitly.

Reasons RLS is the primary defence rather than application-only filtering:

- RLS holds even when a caller forgets the `WHERE` clause. A bug in store code that drops the filter is still safe.
- Cross-tenant data leakage is a P0 security incident. Defence in depth costs essentially nothing here (RLS is a Postgres feature; we pay zero infra cost) and buys real safety.
- Live integration test (`test_rls_isolates_tenants_on_*` in Task 10) issues _raw SQL_ under a tenant-B session and verifies tenant-A rows are not returned — proving RLS itself, not the application filter, excludes them.

### D5 — `Embedding` Protocol with deterministic `FakeEmbeddingProvider` for v0.1

`charter.memory.embedding.Embedding` is a `runtime_checkable` `Protocol` with one method: `embed(text: str) -> list[float]`. `FakeEmbeddingProvider` derives unit-normalised, JSON-safe vectors from SHA-256 of the input.

Reasons:

- Drop-in DI seam. The MemoryService takes an `Embedding`-conforming object; OpenAI / Anthropic providers slot in for Phase 1b without rewriting the substrate.
- Air-gapped pilots can run end-to-end without external embedding API calls.
- Deterministic vectors mean the live integration test can predict the top-K ranking exactly (insert 100 deterministic embeddings, search by the seed of payload #7, expect #7 first).
- Unit-normalised so pgvector's `cosine_distance = 1 − dot product` — the property the ivfflat index assumes.

This is the same Protocol pattern ADR-003 / ADR-006 used for `LLMProvider`. One pattern, multiple substrates.

### D6 — `MemoryService` facade as the single DI seam

Every agent talks to memory through `charter.memory.MemoryService`, not the three stores directly. The facade bundles:

- The three stores constructed once at service init.
- The embedder, run automatically inside `MemoryService.append_event` so agents don't have to remember.
- The optional `AuditLog`, threaded into every store so each write emits a hash-chained audit entry verifiable via `charter.verifier.verify_audit_log`.
- The tenant-scoped `session(tenant_id=...)` async context manager that runs `SET LOCAL app.tenant_id` for RLS.

Agent code is:

```python
async with memory.session(tenant_id=ctx.tenant_id):
    episode_id = await memory.append_event(
        tenant_id=ctx.tenant_id,
        correlation_id=ctx.correlation_id,
        agent_id="cloud_posture",
        action="finding.created",
        payload={"text": finding.title, "severity": finding.severity},
    )
```

No agent constructs a `SQLAlchemy` engine, a session factory, or a per-store object. The facade is the contract; the stores are implementation detail.

## Consequences

**Positive:**

- One Postgres instance instead of three. One backup pipeline, one IAM role policy, one set of dashboards, one set of alerts.
- Schema evolution is unified for memory (one alembic head, one CI gate).
- Per-tenant isolation has two defences (RLS + application filter); a bug in one doesn't open a data-leak hole.
- Unit tests run in ~1.5s against in-memory aiosqlite (no docker compose dependency for the main test suite).
- The Phase-1b path to TimescaleDB / Neo4j is a per-store engine swap — `EpisodicStore(session_factory=timescale_factory, audit_log=...)` — not a rewrite.

**Negative / accepted trade-offs:**

- Recursive-CTE graph traversal on Postgres is O(N × depth) per traversal where N is the per-tenant `relationships` row count. Capped at depth 3 (`MAX_TRAVERSAL_DEPTH`) to keep this predictable. If a future agent (D.7 Investigation) needs depth ≥ 4 against a graph with > 1M edges per tenant, that triggers the Phase-2 Neo4j swap.
- Episodic writes at scale (≥ 1M events/day/tenant) will exceed vanilla Postgres's autovacuum + index-maintenance budget. Phase 1b adds TimescaleDB hypertables to absorb that load. v0.1 customers are well below that threshold.
- pgvector ivfflat lists is fixed at 100 in the baseline migration. The runbook documents the post-30-day re-tune: `floor(sqrt(N))`. Until then, recall vs. speed defaults to "good enough".
- LTREE subtree queries use the dialect-portable `LIKE prefix || '.%'` fallback on non-Postgres dialects. This is fine for unit tests; production runs on Postgres where the GiST + `<@` operator path is used.

## Implementation

The architecture lands in 12 tasks across F.5 ([plan](../../superpowers/plans/2026-05-11-f-5-memory-engines.md)). Highlights:

| Component                                | Lives in                                                 | Tests                                      |
| ---------------------------------------- | -------------------------------------------------------- | ------------------------------------------ |
| Models + dialect-portable column types   | `charter.memory.models`                                  | `test_memory_models.py` (14)               |
| Alembic baseline + Postgres-only indexes | `charter/alembic/versions/0001_memory_baseline.py`       | `test_memory_alembic.py` (11)              |
| Episodic store + pgvector ANN            | `charter.memory.episodic`                                | `test_episodic_store.py` (9)               |
| Embedding Protocol + deterministic fake  | `charter.memory.embedding`                               | `test_embedding.py` (16)                   |
| Procedural store + LTREE / LIKE fallback | `charter.memory.procedural`                              | `test_procedural_store.py` (12)            |
| Semantic store + BFS traversal           | `charter.memory.semantic`                                | `test_semantic_store.py` (13)              |
| RLS migration                            | `charter/alembic/versions/0002_memory_rls.py`            | `test_memory_rls_migration.py` (9)         |
| Charter audit instrumentation            | `charter.memory.{episodic,procedural,semantic}`          | `test_memory_audit_instrumentation.py` (7) |
| `MemoryService` facade                   | `charter.memory.service`                                 | `test_memory_service.py` (8)               |
| Live Postgres integration test           | `charter/tests/integration/test_memory_live_postgres.py` | 6 (opt-in via `NEXUS_LIVE_POSTGRES=1`)     |
| Operator runbook                         | `charter/runbooks/memory_bootstrap.md`                   | —                                          |

**Coverage:** 95% across the eight-module `charter.memory` package (target ≥ 80%). Mypy `--strict` clean across the 106 source files in the configured set. Ruff + ruff-format clean. Repo-wide pytest 1020 passed / 11 skipped.

## Cross-references

- F.5 plan: [`docs/superpowers/plans/2026-05-11-f-5-memory-engines.md`](../../superpowers/plans/2026-05-11-f-5-memory-engines.md)
- Bootstrap runbook: [`packages/charter/runbooks/memory_bootstrap.md`](../../../packages/charter/runbooks/memory_bootstrap.md)
- F.4 (auth + tenant manager) — same Postgres-collapse decision: [F.4 plan](../../superpowers/plans/2026-05-11-f-4-auth-tenant-manager.md)
- ADR-002 — charter as context manager (the audit-chain `AuditLog` instrumentation hooks F.5 inherits): [ADR-002](ADR-002-charter-as-context-manager.md)
- ADR-004 — fabric layer (the `tenant_id` propagation strategy F.5's RLS plugs into): [ADR-004](ADR-004-fabric-layer.md)
