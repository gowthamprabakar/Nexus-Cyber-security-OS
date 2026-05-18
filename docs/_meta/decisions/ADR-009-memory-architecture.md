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

## Amendment 2026-05-18 — Cloud Posture rerouted to SemanticStore; Neo4j writer preserved dormant

### Why this amendment exists

ADR-009 (2026-05-12) recorded the decision to collapse the three planned memory engines (TimescaleDB + Postgres + Neo4j) onto a single Postgres 16 + pgvector + LTREE instance for Phase 1a. The decision was correct and remains in force. **What ADR-009 did not do was sweep the codebase for pre-decision writers that targeted the abandoned engines.**

Cloud Posture's `packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py` (F.3 Task 6, committed 2026-05-08 at `bee67ad`) was one such writer — a Phase-1a-era `KnowledgeGraphWriter` against `neo4j.AsyncDriver`. After the F.5 pivot it became unreachable: nothing in the platform reads the Neo4j Aura instance it writes to. **For ~6 days the keystone of ADR-009's collapse was load-bearing but unloaded** — D.7 Investigation's `memory_neighbors_walk` consumes the Postgres `SemanticStore`; no agent populated it.

The structural gap that allowed the drift is **the absence of this amendment between 2026-05-12 and 2026-05-18.** No ADR mentioned the writer; the F.5 plan didn't sweep for old writers; the writer kept compiling and shipping. **Writing this amendment closes that gap by recording the decision and the rule below — so the next such drift is caught at amendment-time, not at migration-time.**

Timeline:

| Date       | Event                                                                                                                                                                            |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-05-08 | F.3 Task 6 ships `cloud_posture/tools/neo4j_kg.py` against the original three-engine architecture (Neo4j Aura for semantic). Worked as designed at the time.                     |
| 2026-05-11 | F.4 + F.5 pivot collapses control-plane + memory onto Postgres. The three-engine plan is abandoned; the existing Neo4j writer becomes unreachable from the platform graph.       |
| 2026-05-12 | This ADR (ADR-009) records the Postgres-collapse decision but does not sweep pre-existing writers. Cloud Posture's `neo4j_kg.py` continues to exist alongside the new direction. |
| 2026-05-18 | KG-loop-closure plan reroutes Cloud Posture's KG write path to the Postgres `SemanticStore`. This amendment records the decision + the rule + the dormancy choice.               |

### The reroute decision (verbatim)

**Cloud Posture rerouted to the Postgres SemanticStore; loop closed via Postgres. Neo4j writer PRESERVED DORMANT in the codebase, intentionally NOT deleted — retained for the future scale-driven migration to Neo4j (ADR-009 escape hatch). Postgres is the Phase-1 graph; Neo4j is the deliberate future engine when scale requires it.**

Operationally:

- `cloud_posture/tools/kg_writer.py` (new) implements the same `KnowledgeGraphWriter` class shape — `upsert_asset(kind, external_id, properties)` and `upsert_finding(finding_id, rule_id, severity, affected_arns)` — backed by `SemanticStore.upsert_entity` (entity_type `"asset"` or `"finding"`) and `SemanticStore.add_relationship` (relationship_type `"AFFECTS"`).
- `cloud_posture/agent.py`'s tool registry re-points the two `kg_upsert_*` registrations from `neo4j_kg.KnowledgeGraphWriter` to `kg_writer.KnowledgeGraphWriter`. F.6 audit-chain action names (`kg_upsert_asset`, `kg_upsert_finding`) are preserved — only the backend changes.
- `cloud_posture/tools/neo4j_kg.py` stays in the codebase, **DORMANT**: disconnected from the agent's tool registry, unimported by production code, retained as functionally intact for the future Phase-2 Neo4j swap. The file carries a module-level docstring banner stating the dormancy decision and cross-referencing this amendment + the new `kg_writer.py`.
- The `neo4j>=5.24.0` dependency stays in `packages/agents/cloud-posture/pyproject.toml` — required by the dormant module's import surface.

### Data-model mapping (Cypher → SemanticStore)

| Pre-reroute (Cypher; `neo4j_kg.py`)                                                                       | Post-reroute (SemanticStore; `kg_writer.py`)                                                                                                                 |
| --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `MERGE (a:Asset {customer_id, kind, external_id}) SET a += $properties`                                   | `await semantic_store.upsert_entity(tenant_id, entity_type="asset", external_id, properties={"kind": kind, **properties})` (kind moves from key to property) |
| `MERGE (f:Finding {customer_id, finding_id}) SET f.rule_id, f.severity`                                   | `await semantic_store.upsert_entity(tenant_id, entity_type="finding", external_id=finding_id, properties={"rule_id", "severity"})`                           |
| `MATCH (f) UNWIND $arns AS arn MERGE (a:Asset {customer_id, external_id: arn}) MERGE (f)-[:AFFECTS]->(a)` | per-arn: `dst = upsert_entity(entity_type="asset", external_id=arn, properties={})` ; `add_relationship(src=finding_entity_id, dst=dst, type="AFFECTS")`     |

**One translation issue, resolved agent-side: SemanticStore.add_relationship is INSERT-only (no upsert-by-tuple).** Repeated calls on the same `(src, dst, type)` produce duplicate rows. The new `KnowledgeGraphWriter` maintains an in-process per-finding `set[str]` of already-related arns; `upsert_finding` only emits `add_relationship` calls for arns it hasn't yet related within the current scan run. **Substrate is unmodified — `SemanticStore`'s API is consumed exactly as it ships today.** The agent-side dedup is verified by the KG-loop-closure plan's Task 6 live proof, which writes the same finding + same arn twice against real Postgres and asserts exactly one AFFECTS row exists.

### Rule (new): every agent writes to the graph ONLY through `MemoryService.semantic`

> **Every agent writes to the graph ONLY through `MemoryService.semantic` — no direct database drivers, ever. This is what keeps the future Neo4j migration a one-layer swap instead of a per-agent rebuild.**

This rule **existed implicitly** in the F.5 / ADR-009 design intent — the graph-portability claim in ADR-009 §"Decision" (_"The substrate is not coupled to this collapse — `EpisodicStore`, `ProceduralStore`, and `SemanticStore` each take an `async_sessionmaker[AsyncSession]` and route every query through it. Splitting back out to dedicated engines later is a per-store session-factory swap, not a rewrite."_) only works if every consumer reaches the graph through the same DI seam. The rule was **never written down**, which is what allowed Cloud Posture's `neo4j_kg.py` to ship with a `neo4j.AsyncDriver` directly held inside the agent's source — a violation no reviewer flagged because no rule said "don't."

This amendment writes the rule down. From 2026-05-18 forward:

- Any new KG-writing code (D.5, D.6, future detect agents, future supervisor primitives, future probability / attack-path consumers) **must** reach the graph through `MemoryService.semantic` (or one of the stores it exposes — `SemanticStore`, `EpisodicStore`, `ProceduralStore`).
- **No agent may hold a database driver instance directly** — neither `neo4j.AsyncDriver` nor `sqlalchemy.AsyncEngine` nor any other backend-specific handle. The driver lives at the substrate layer (`charter.memory`) and behind the `MemoryService` facade; agents take a typed store reference.
- The Phase-2 Neo4j swap (per the escape-hatch trigger below) then stays a **one-layer change** — swap `SemanticStore`'s session-factory wiring at the substrate, and every agent picks up the new backend without source modification.

Code review should reject any new agent-side import of `neo4j`, raw `sqlalchemy.AsyncEngine`, or equivalent backend driver. The dormant `cloud_posture/tools/neo4j_kg.py` is the **one and only** exception, and only because it is structurally retired (not in the tool registry, not exercised by tests except as a dormant module, retained as a marker for the Phase-2 swap path — see the file's docstring banner).

### Phase-2 Neo4j escape hatch — reaffirmed, not triggered

ADR-009's §"Consequences" already names the trigger condition for the Phase-2 Neo4j swap:

> _"Recursive-CTE graph traversal on Postgres is O(N × depth) per traversal where N is the per-tenant `relationships` row count. Capped at depth 3 (`MAX_TRAVERSAL_DEPTH`) to keep this predictable. If a future agent (D.7 Investigation) needs depth ≥ 4 against a graph with > 1M edges per tenant, that triggers the Phase-2 Neo4j swap."_

This amendment **reaffirms but does not trigger** that condition. Today's graph is empty in production (no agent populates it); the 2026-05-18 reroute makes it non-empty by routing Cloud Posture's writes to it. Throughput against the trigger condition is a future-monitoring concern, not an immediate one.

What this amendment adds to the escape-hatch story:

- **The dormant `neo4j_kg.py` is the labelled door.** When the trigger fires, the Phase-2 swap is "re-route Cloud Posture's KG-tool registrations back to `neo4j_kg.KnowledgeGraphWriter`" (plus a parallel `SemanticStore`-backend swap to Neo4j at the substrate layer) — not "rebuild a Neo4j writer from scratch." The agent-side code path stays at parity with the dormant module's existing surface.
- **The MemoryService.semantic-only rule above is what keeps the swap a one-layer change.** If new agents (D.5, D.6, ...) had each grown their own `neo4j.AsyncDriver` writers in the meantime, the Phase-2 swap would be a per-agent rebuild. The rule prevents that compounding.

Probability-weighted multi-hop paths / attack-path enumeration / cure-recommendation engines are deferred consumers; whether any of them triggers the swap (because Postgres recursive-CTE can't express the traversal) is a per-plan judgment at the time. The trigger condition above is the structural floor.

### Cross-references for this amendment

- KG-loop-closure plan: [`docs/superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md`](../../superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md) — the plan that executes this amendment's decision across Tasks 2-8.
- The dormant module: [`packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py`](../../../packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py) — retained, DORMANT-bannered (Task 7), exists as the Phase-2 swap target.
- The new writer: `packages/agents/cloud-posture/src/cloud_posture/tools/kg_writer.py` (Task 3 of the KG-loop-closure plan) — `SemanticStore`-backed; same `KnowledgeGraphWriter` class shape as the dormant module.
- ADR-007 (Cloud Posture as reference agent) — the dormant writer was F.3 Task 6 of the original reference-agent surface: [ADR-007](ADR-007-cloud-posture-as-reference-agent.md).

## Cross-references

- F.5 plan: [`docs/superpowers/plans/2026-05-11-f-5-memory-engines.md`](../../superpowers/plans/2026-05-11-f-5-memory-engines.md)
- Bootstrap runbook: [`packages/charter/runbooks/memory_bootstrap.md`](../../../packages/charter/runbooks/memory_bootstrap.md)
- F.4 (auth + tenant manager) — same Postgres-collapse decision: [F.4 plan](../../superpowers/plans/2026-05-11-f-4-auth-tenant-manager.md)
- ADR-002 — charter as context manager (the audit-chain `AuditLog` instrumentation hooks F.5 inherits): [ADR-002](ADR-002-charter-as-context-manager.md)
- ADR-004 — fabric layer (the `tenant_id` propagation strategy F.5's RLS plugs into): [ADR-004](ADR-004-fabric-layer.md)
