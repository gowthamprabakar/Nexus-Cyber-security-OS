# F.5 — Memory Engines Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Memory engines** substrate (Phase 1a foundation pillar #5) — typed, async-accessed Postgres-backed persistent state for **episodic memory** (agent run history + decisions), **procedural memory** (learned playbooks + policies), and **semantic memory** (entity-relationship knowledge graph). Lives at `packages/charter/src/charter/memory/` (substrate stays in the Apache 2.0 charter; per-agent tables are agent-package code under BSL 1.1).

**Strategic role.** F.5 is the **last unbuilt Phase-1a foundation pillar** (F.1 ✓ · F.2 ✓ · F.3 ✓ · F.4 ✓ · **F.5** · F.6 ⬜). It unblocks:

- **D.7 Investigation Agent** — needs the semantic-memory knowledge graph to chain cross-agent findings into incidents.
- **A.4 Meta-Harness Agent** — needs the episodic-memory event store to read agent traces for self-evolution.
- **D.12 Curiosity Agent** — needs the procedural-memory playbook store to know which idle-time queries are worth running.
- **The four shipped agents** (F.3 / D.1 / D.2 / D.3) — currently write only to per-run workspaces. F.5 gives them a long-lived "this finding existed last week, here's how it was triaged" lookup. **Not required for v0.1 deterministic flow** but unlocks production deployment.

**Q1 resolved up-front.** Per the [system-readiness recommendation](../../_meta/system-readiness-2026-05-11-1647ist.md#41-strategy--business-documents-layer-0) and the [F.4 Q1 resolution](2026-05-11-f-4-auth-tenant-manager.md): **Phase 1a collapses to PostgreSQL + JSONB + pgvector** instead of the original three-engine plan (TimescaleDB episodic + PostgreSQL procedural + Neo4j Aura semantic). The original three engines were the right Phase 1 plan when each had distinct query patterns; today's `pgvector` + `JSONB GIN indexes` + `LTREE` + `recursive CTEs` cover ~80% of the read patterns the three-engine plan was solving for, at one-third the operational surface. **TimescaleDB defers to Phase 1b** if episodic write volume forces it; **Neo4j defers to Phase 2** if cross-tenant graph queries cross the recursive-CTE break-even.

**Architecture:**

```
charter.Charter (per F.1 / ADR-002)
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ charter.memory                                              │
│   - EpisodicStore   (agent run events; pgvector embeddings) │
│   - ProceduralStore (NLAH versions, playbooks, action       │
│                       policies; LTREE for hierarchical tags)│
│   - SemanticStore   (entity-relationship triples;           │
│                       recursive CTE for graph traversal)    │
│   All three are typed async SQLAlchemy 2.0 accessors over   │
│   Postgres 16+ schemas. Per-tenant row-level security per   │
│   ADR-004's tenant_id propagation.                          │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Postgres 16 (alembic migration `0001_memory_baseline`,      │
│   separate head from control-plane's `alembic_version`)     │
│                                                             │
│   - episodes        (run events, JSONB payload, pgvector    │
│                      embedding, BRIN index on time)         │
│   - playbooks       (NLAH versions, hierarchical LTREE      │
│                      path, jsonb_path_ops index)            │
│   - entities        (nodes in the semantic graph: assets,   │
│                      principals, findings, etc.)            │
│   - relationships   (edges between entities; src + dst +    │
│                      type + properties JSONB)               │
└─────────────────────────────────────────────────────────────┘
```

**Tech stack:** Python 3.12 · Apache 2.0 (charter substrate) · SQLAlchemy 2.0 (async) · asyncpg · alembic · pgvector (Postgres extension) · pydantic 2.9. dev: pytest + pytest-asyncio + aiosqlite (fast unit-test DB) + a real postgres instance for integration tests via Docker Compose (opt-in via `NEXUS_LIVE_POSTGRES=1`, mirrors the existing `NEXUS_LIVE_*` pattern).

**Depends on:**

- F.1 (charter) — memory stores accept a `Charter` context for audit-chain emission on every write.
- F.4 (auth + tenant manager) — `control-plane.tenants.models.Base` provides the SQLAlchemy declarative base; F.5 extends the same schema. The alembic config from F.4 inherits.

**Defers (Phase 1b / Phase 2):**

- **TimescaleDB hypertables** for episodic — Phase 1b if write volume forces it (target: ≥ 1M events/day per tenant).
- **Neo4j Aura** for semantic — Phase 2 if recursive-CTE graph traversal becomes the bottleneck.
- **Cross-tenant memory queries** — Phase 2; v0.1 is single-tenant-per-query by row-level-security.
- **Memory garbage collection** (TTL on episodes) — Phase 1c; v0.1 stores everything indefinitely.
- **Multi-region read replicas** — Phase 2 GA hardening.

**Reference template:** F.4's `control-plane.tenants` substrate work — same alembic baseline, same async SQLAlchemy 2.0 patterns, same aiosqlite-for-unit-tests + opt-in Postgres-for-integration approach. **F.5 is structurally F.4 with three more tables and a couple of indexes.**

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12
```

| Task | Status     | Commit    | Notes                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---- | ---------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ✅ done    | `67734fb` | Production SQLAlchemy models — `charter.memory.models` ships `Base` + `EpisodeModel` + `PlaybookModel` + `EntityModel` + `RelationshipModel` with every production index; tests assert structure + FK + ON DELETE CASCADE via `Base.metadata.create_all` against aiosqlite. Runtime/dev deps land here (pgvector, asyncpg, aiosqlite). 14 tests; mypy strict clean (21 source files); repo-wide 935 passed / 5 skipped. |
| 2    | ⬜ pending | —         | Alembic config + `0001_memory_baseline` migration that drives the Task 1 models; tests execute the migration end-to-end (offline-mode SQL emit + online `upgrade head` against aiosqlite); `version_table = "alembic_version_memory"` so it coexists with control-plane's alembic head when sharing a Postgres                                                                                                          |
| 3    | ⬜ pending | —         | `EpisodicStore` — typed async accessor; `append_event(charter, *, agent_id, action, payload, embedding=None)`; `query_by_correlation_id` etc.                                                                                                                                                                                                                                                                           |
| 4    | ⬜ pending | —         | pgvector embedding helper — `embed_for_episode(payload, *, dim=1536)`; deterministic fake provider for tests; OpenAI / Anthropic providers Phase 1b                                                                                                                                                                                                                                                                     |
| 5    | ⬜ pending | —         | `ProceduralStore` — playbook CRUD with LTREE-shaped hierarchical path; `publish_version` + `get_active(path)`                                                                                                                                                                                                                                                                                                           |
| 6    | ⬜ pending | —         | `SemanticStore` — typed entity/relationship CRUD; `neighbors(entity_id, depth, *, edge_types)` via recursive CTE                                                                                                                                                                                                                                                                                                        |
| 7    | ⬜ pending | —         | Per-tenant row-level security (RLS) policies wired into the alembic migration; integration test that an off-tenant query returns empty                                                                                                                                                                                                                                                                                  |
| 8    | ⬜ pending | —         | Charter-instrumentation adapter — every memory write emits a hash-chained audit entry; tested against `charter.verifier`                                                                                                                                                                                                                                                                                                |
| 9    | ⬜ pending | —         | `MemoryService` facade — single async DI seam that the four shipped agents (F.3 / D.1 / D.2 / D.3) can wire into without each agent owning a session                                                                                                                                                                                                                                                                    |
| 10   | ⬜ pending | —         | Integration test against a live Postgres (Docker Compose) — opt-in via `NEXUS_LIVE_POSTGRES=1`; CRUD round-trip on all four tables; pgvector ANN                                                                                                                                                                                                                                                                        |
| 11   | ⬜ pending | —         | Operator runbook (`runbooks/memory_bootstrap.md`) — Docker Compose Postgres + pgvector + alembic upgrade + smoke read/write                                                                                                                                                                                                                                                                                             |
| 12   | ⬜ pending | —         | Final verification (≥ 80% coverage; ruff/mypy clean; chain verifies; live integration test); ADR-009 (memory architecture) drafted                                                                                                                                                                                                                                                                                      |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-002](../../_meta/decisions/ADR-002-charter-as-context-manager.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [**ADR-009 (memory architecture)**](../../_meta/decisions/ADR-009-memory-architecture.md) — drafted alongside Task 12.

---

## Key design questions

### Q1 — Single-engine Postgres vs. original three-engine plan

**Resolved before this plan was written.** The 2026-05-08 build-roadmap named TimescaleDB + Postgres + Neo4j Aura. The [system-readiness recommendation](../../_meta/system-readiness-2026-05-11-1647ist.md) and the F.4 Q1 resolution collapse to **PostgreSQL + JSONB + pgvector for Phase 1a**.

Rationale:

- **Operational surface.** One engine, one auth surface, one backup/restore story, one upgrade pipeline. The three-engine plan was 3× the operational complexity for Phase 1a.
- **Query coverage.** `pgvector` covers approximate-nearest-neighbor for embeddings (the main TimescaleDB-not-needed signal). `JSONB GIN` covers semi-structured payloads. `LTREE` covers hierarchical taxonomy. Recursive CTE covers graph traversal up to ~3 hops at sub-millisecond per-tenant. Together they cover ~80% of the original three-engine reads.
- **Cost.** Single Postgres-with-extensions on AWS RDS is < $200/mo at Phase 1 customer scale. Neo4j Aura + TimescaleDB Cloud would be $1500+/mo combined.
- **Escape hatch.** If episodic write volume forces TimescaleDB or graph queries force Neo4j, the data shape is preserved — both engines can ingest the existing Postgres schema as a one-shot ETL.

**Verdict:** Postgres-only for Phase 1a. Re-evaluate at first 100k events/day per tenant OR first 3-hop graph query exceeding 100ms.

### Q2 — Embedding provider for episodic memory

`EpisodicStore.append_event` accepts an optional `embedding: list[float] | None`. Two design choices:

- **Eager embed on write** (the store calls an embedding API for every event). Pro: queries are immediately ANN-searchable. Con: ties write latency to an external API; cost scales with event volume.
- **Lazy embed on first query** (events store raw payload; embedding job materializes vectors asynchronously). Pro: write path stays fast. Con: most-recent events are not in the ANN index for a few minutes.

**Resolve in Task 4.** Recommendation: **eager-embed-with-fake-provider in v0.1.** A `FakeEmbeddingProvider(dim=1536)` returns deterministic vectors derived from a hash of the payload; tests are reproducible; production callers thread in OpenAI / Anthropic providers in Phase 1b. The write path stays sub-millisecond because the fake provider doesn't make API calls.

### Q3 — Per-tenant isolation: RLS policies vs. application-side `WHERE tenant_id = ?`

- **PostgreSQL Row-Level Security (RLS)** — set `tenant_id` per session; every query is automatically filtered. Pro: impossible to accidentally leak across tenants. Con: requires `SET LOCAL tenant_id = ?` on every connection; adds latency to short queries.
- **Application-side filtering** — every SQLAlchemy query includes `.where(table.c.tenant_id == ?)`. Pro: simpler operationally. Con: one missing `.where` clause is a P0 incident.

**Resolve in Task 7.** Recommendation: **RLS policies in the alembic migration** with `current_setting('app.tenant_id')` populated by the `MemoryService` facade (Task 9). The facade sets the session variable inside the same SQLAlchemy session it hands to callers, so no caller can forget. An integration test (Task 10) verifies off-tenant queries return empty.

---

## File Structure

```
packages/charter/src/charter/memory/
├── __init__.py                                  # re-exports the three stores + MemoryService
├── episodic.py                                  # Task 3
├── procedural.py                                # Task 5
├── semantic.py                                  # Task 6
├── embedding.py                                 # Task 4 (Protocol + FakeEmbeddingProvider)
├── service.py                                   # Task 9 (MemoryService facade)
└── audit.py                                     # Task 8 (charter-instrumentation adapter)

packages/charter/alembic/
├── alembic.ini                                  # Task 2
├── env.py                                       # Task 2 (sync + async migration support)
├── script.py.mako                               # Task 2
└── versions/
    └── 0001_memory_baseline.py                  # Task 2 (autogenerated from models.py, then hand-tweaked for pgvector ivfflat + JSONB GIN)

packages/charter/tests/
├── test_memory_episodic.py
├── test_memory_procedural.py
├── test_memory_semantic.py
├── test_memory_service.py
├── test_memory_audit.py
└── integration/
    └── test_memory_live_postgres.py             # opt-in via NEXUS_LIVE_POSTGRES=1

packages/charter/runbooks/
└── memory_bootstrap.md                          # Task 11
```

---

## Task 1: SQLAlchemy memory models + runtime deps

**Production-grade discipline:** the first F.5 commit lands real working models that a customer's `Base.metadata.create_all` can materialize end-to-end. Nothing in this commit is a placeholder.

Files:

- `packages/charter/pyproject.toml` — add `pgvector>=0.3.0`, `asyncpg>=0.29.0`, `sqlalchemy>=2.0.30`, `greenlet>=3.1.0` to runtime deps; add `aiosqlite>=0.20.0` to dev deps. None of these were previously in charter; they ship here because charter now owns persistent state.
- `packages/charter/src/charter/memory/__init__.py` — re-exports the `Base` and the four model classes that exist in `models.py`. Nothing forward-declared; nothing re-exported that doesn't have a real implementation in this commit.
- `packages/charter/src/charter/memory/models.py` — `Base` (DeclarativeBase) + `EpisodeModel` + `PlaybookModel` + `EntityModel` + `RelationshipModel`. Every column has its production type (ULID lengths, JSONB, vector dim 1536, TIMESTAMPTZ, LTREE). FKs + ON DELETE CASCADE on the relationships table. Indexes declared on the model so they materialize regardless of which dialect creates the schema. Bi-directional `to_pydantic()` / `to_dict()` shapes deferred to the stores in Tasks 3 / 5 / 6 (those tasks land typed accessor classes; the models here are the wire format).
- `packages/charter/tests/test_memory_models.py` — exercises real behavior: `Base.metadata.create_all` against aiosqlite, schema introspection (every table + every column + every FK), insertion + commit round-trip through an `AsyncSession`. No "import works" placeholder tests.

- [ ] **Step 1: Write failing tests** — table-count assertion, per-table column assertions, FK on `relationships.{src,dst}_entity_id → entities.entity_id` with ON DELETE CASCADE, index existence (where dialect-independent), insertion round-trip through a real AsyncSession. ≥ 12 tests.
- [ ] **Step 2: Implement** the four models with production columns + indexes.
- [ ] **Step 3: Tests pass** against aiosqlite (the dialect that backs the unit tests).
- [ ] **Step 4: Commit** — `feat(f5): sqlalchemy memory models + runtime deps (F.5 task 1)`.

---

## Task 2: Alembic config + baseline migration

Land the alembic config under `packages/charter/alembic/` with `version_table = "alembic_version_memory"` so it coexists with control-plane's alembic head when the two packages share a Postgres instance. The baseline migration `0001_memory_baseline.py` is autogenerated from Task 1's models, then hand-tweaked to include the Postgres-only indexes (GIN on JSONB, ivfflat on vector) that the dialect-portable model definitions can't declare.

Mirror F.4's [`0001_initial_tenant_user_tables.py`](../../../packages/control-plane/alembic/versions/0001_initial_tenant_user_tables.py) shape. Tables (mirroring the Task 1 models):

```sql
-- episodes: every charter audit entry that warrants long-term storage
CREATE TABLE episodes (
  episode_id     BIGSERIAL PRIMARY KEY,
  tenant_id      VARCHAR(26)   NOT NULL,
  correlation_id VARCHAR(32)   NOT NULL,
  agent_id       VARCHAR(64)   NOT NULL,
  action         VARCHAR(128)  NOT NULL,
  payload        JSONB         NOT NULL,
  embedding      VECTOR(1536),
  emitted_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_episodes_tenant_emitted ON episodes (tenant_id, emitted_at DESC);
CREATE INDEX ix_episodes_correlation    ON episodes (correlation_id);
CREATE INDEX ix_episodes_payload_gin    ON episodes USING GIN (payload jsonb_path_ops);
CREATE INDEX ix_episodes_embedding_ivf  ON episodes USING ivfflat (embedding vector_cosine_ops);

-- playbooks: versioned NLAH / action policies with hierarchical taxonomy
CREATE TABLE playbooks (
  playbook_id  BIGSERIAL    PRIMARY KEY,
  tenant_id    VARCHAR(26)  NOT NULL,
  path         LTREE        NOT NULL,                -- e.g. "remediation.s3.public_bucket"
  version      INT          NOT NULL,
  active       BOOL         NOT NULL DEFAULT FALSE,
  body         JSONB        NOT NULL,
  published_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, path, version)
);
CREATE INDEX ix_playbooks_path_gist ON playbooks USING GIST (path);

-- entities: nodes in the semantic graph
CREATE TABLE entities (
  entity_id    VARCHAR(26)  PRIMARY KEY,   -- ULID
  tenant_id    VARCHAR(26)  NOT NULL,
  entity_type  VARCHAR(64)  NOT NULL,      -- e.g. "host", "principal", "finding"
  external_id  VARCHAR(255) NOT NULL,
  properties   JSONB        NOT NULL DEFAULT '{}'::jsonb,
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, entity_type, external_id)
);
CREATE INDEX ix_entities_tenant_type ON entities (tenant_id, entity_type);

-- relationships: edges
CREATE TABLE relationships (
  relationship_id BIGSERIAL    PRIMARY KEY,
  tenant_id       VARCHAR(26)  NOT NULL,
  src_entity_id   VARCHAR(26)  NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
  dst_entity_id   VARCHAR(26)  NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
  relationship    VARCHAR(64)  NOT NULL,
  properties      JSONB        NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_relationships_src_type ON relationships (src_entity_id, relationship);
CREATE INDEX ix_relationships_dst_type ON relationships (dst_entity_id, relationship);
```

- [ ] **Step 1: Write failing tests** — alembic config has `version_table = "alembic_version_memory"`; offline-SQL emits the four tables; `upgrade head` against aiosqlite succeeds and leaves `Base.metadata.tables` reachable; indexes + FK + ON DELETE CASCADE all present. ≥ 8 tests.
- [ ] **Step 2: Implement** the alembic config + the migration.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(f5): alembic config + baseline migration for memory engines (F.5 task 2)`.

---

## Task 3: `EpisodicStore`

Typed async accessor over the `episodes` table. Signature:

```python
class EpisodicStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None: ...

    async def append_event(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        agent_id: str,
        action: str,
        payload: dict[str, Any],
        embedding: list[float] | None = None,
    ) -> int: ...  # returns episode_id

    async def query_by_correlation_id(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
    ) -> list[EpisodeRow]: ...

    async def search_similar(
        self,
        *,
        tenant_id: str,
        embedding: list[float],
        top_k: int = 10,
    ) -> list[EpisodeRow]: ...   # pgvector ANN; falls back to no-op when no pgvector
```

- [ ] **Step 1: Write failing tests** — append + query round-trip; correlation grouping; similar-search returns ranked rows; tenant isolation; ≥ 8 tests via aiosqlite (pgvector pieces gated behind the live test in Task 10).
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(f5): episodicstore typed async accessor (F.5 task 3)`.

---

## Task 4: Embedding helper + Fake provider

`charter.memory.embedding.Embedding` Protocol with `embed(text: str) -> list[float]`. `FakeEmbeddingProvider(dim=1536)` returns deterministic vectors derived from a SHA-256 of the input — reproducible across runs, ANN-correct (similar inputs yield similar vectors via shared SHA-256 prefix patterns).

Production providers (OpenAI / Anthropic) defer to Phase 1b.

**Resolves Q2.** Eager-embed-on-write with the fake provider in v0.1.

- [ ] **Step 1: Write failing tests** — fake provider returns vectors of the configured dim; same input always gives same output; vectors are unit-normalized; ≥ 5 tests.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(f5): embedding protocol + fakeembeddingprovider (F.5 task 4)`.

---

## Task 5: `ProceduralStore`

Versioned playbook CRUD with hierarchical paths.

```python
class ProceduralStore:
    async def publish_version(
        self,
        *,
        tenant_id: str,
        path: str,                   # e.g. "remediation.s3.public_bucket"
        body: dict[str, Any],
    ) -> int: ...                    # auto-increments version; sets active=True; deactivates prior

    async def get_active(
        self,
        *,
        tenant_id: str,
        path: str,
    ) -> PlaybookRow | None: ...

    async def list_subtree(
        self,
        *,
        tenant_id: str,
        prefix: str,                  # e.g. "remediation.s3" returns all s3.* playbooks
    ) -> list[PlaybookRow]: ...
```

- [ ] **Step 1: Write failing tests** — publish + get_active round-trip; version auto-increments; only one active per path; subtree query via LTREE; tenant isolation; ≥ 8 tests.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(f5): proceduralstore versioned playbook crud (F.5 task 5)`.

---

## Task 6: `SemanticStore`

Entity-relationship CRUD with recursive-CTE traversal.

```python
class SemanticStore:
    async def upsert_entity(
        self,
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str: ...                     # returns entity_id (ULID)

    async def add_relationship(
        self,
        *,
        tenant_id: str,
        src_entity_id: str,
        dst_entity_id: str,
        relationship: str,
        properties: dict[str, Any] | None = None,
    ) -> int: ...

    async def neighbors(
        self,
        *,
        tenant_id: str,
        entity_id: str,
        depth: int = 1,                # ≤ 3 in v0.1 — recursive CTE cost cap
        edge_types: tuple[str, ...] | None = None,
    ) -> list[EntityRow]: ...
```

- [ ] **Step 1: Write failing tests** — entity upsert idempotent on (tenant_id, type, external_id); relationship add; neighbors at depth 1 / 2 / 3; tenant isolation; max-depth enforcement; ≥ 10 tests.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(f5): semanticstore entity-relationship crud + traversal (F.5 task 6)`.

---

## Task 7: Per-tenant Row-Level Security

Alembic migration `0003_memory_rls` adds RLS policies to all four memory tables. Pattern:

```sql
ALTER TABLE episodes ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON episodes
  USING (tenant_id = current_setting('app.tenant_id', true));
```

**Resolves Q3.** RLS in the migration; `MemoryService` (Task 9) sets `app.tenant_id` per session.

- [ ] **Step 1: Write failing tests** (integration-only via Task 10's Postgres) — session A with `tenant=cust_a` cannot read `cust_b` rows; ≥ 4 tests.
- [ ] **Step 2: Implement** migration `0003_memory_rls`.
- [ ] **Step 3: Tests pass** when `NEXUS_LIVE_POSTGRES=1`.
- [ ] **Step 4: Commit** — `feat(f5): per-tenant rls policies on memory tables (F.5 task 7)`.

---

## Task 8: Charter audit-chain instrumentation

Every memory write emits a hash-chained audit entry via the existing `charter.audit.AuditLog`. The store's `append_event` / `publish_version` / `upsert_entity` / `add_relationship` each call `charter.audit.append(...)` with action names: `episode_appended`, `playbook_published`, `entity_upserted`, `relationship_added`.

- [ ] **Step 1: Write failing tests** — chain verifies via `charter.verifier.verify_audit_log` after every write; action names match the canon; ≥ 6 tests.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(f5): charter audit instrumentation on every memory write (F.5 task 8)`.

---

## Task 9: `MemoryService` facade

Single async DI seam that bundles the three stores + audit + RLS session-variable management.

```python
class MemoryService:
    def __init__(self, session_factory: ..., embedder: Embedding) -> None: ...

    @asynccontextmanager
    async def session(self, *, tenant_id: str) -> AsyncIterator[AsyncSession]:
        """Yield a session with `app.tenant_id` set so RLS is enforced."""

    @property
    def episodic(self) -> EpisodicStore: ...

    @property
    def procedural(self) -> ProceduralStore: ...

    @property
    def semantic(self) -> SemanticStore: ...
```

Callers (the four shipped agents + future agents) do:

```python
async with memory.session(tenant_id="cust_acme"):
    episode_id = await memory.episodic.append_event(...)
```

- [ ] **Step 1: Write failing tests** — session sets the RLS variable; multi-tenant agent flows don't leak; embedder is wired into `append_event`; ≥ 6 tests.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(f5): memoryservice facade (F.5 task 9)`.

---

## Task 10: Live Postgres integration test

Docker Compose runs `pgvector/pgvector:pg16` on port 5432. Test gates behind `NEXUS_LIVE_POSTGRES=1` (mirrors `NEXUS_LIVE_LOCALSTACK=1`, `NEXUS_LIVE_OLLAMA=1`).

Tests:

- alembic upgrade head against the live DB.
- CRUD round-trip on each of the four tables.
- pgvector ANN — insert 100 episodes, embed-search, top-K is correct.
- RLS — session A's tenant cannot read session B's rows.

- [ ] **Step 1: Add `docker/docker-compose.dev.yml` Postgres service** (mirror the existing LocalStack service config).
- [ ] **Step 2: Write the integration test** at `packages/charter/tests/integration/test_memory_live_postgres.py`.
- [ ] **Step 3: Verify locally** — `docker compose up -d postgres && NEXUS_LIVE_POSTGRES=1 uv run pytest packages/charter/tests/integration/test_memory_live_postgres.py -v`.
- [ ] **Step 4: Commit** — `test(f5): live postgres integration test for memory engines (F.5 task 10)`.

---

## Task 11: Operator runbook

`packages/charter/runbooks/memory_bootstrap.md` walks an operator through:

1. Bring up Postgres + pgvector via Docker Compose.
2. Run `alembic upgrade head` against the running DB.
3. Confirm pgvector extension is loaded (`CREATE EXTENSION IF NOT EXISTS vector;`).
4. Smoke read/write through the `MemoryService` Python API.
5. Common failures — `pgvector extension not found`, `LTREE column type unknown`, RLS-locked-out-by-missing-session-variable.

- [ ] **Step 1: Write the runbook** — 5 sections + common-failures table.
- [ ] **Step 2: Commit** — `docs(f5): memory bootstrap operator runbook (F.5 task 11)`.

---

## Task 12: Final verification + ADR-009

Mirror F.4's gate set:

1. `uv run pytest packages/charter/ --cov=charter.memory --cov-fail-under=80` — ≥ 80%.
2. `uv run ruff check + format --check + mypy strict` — all clean.
3. `NEXUS_LIVE_POSTGRES=1 uv run pytest packages/charter/tests/integration/test_memory_live_postgres.py` — passes.
4. Chain verifies via `charter.verifier.verify_audit_log` against a workspace populated by multiple memory writes.

**ADR-009 — Memory architecture.** Draft alongside Task 12. Records:

- Q1 resolution: Postgres-only for Phase 1a (vs original three-engine plan).
- Q2 resolution: eager-embed-on-write with `FakeEmbeddingProvider` in v0.1.
- Q3 resolution: RLS policies + `MemoryService`-managed session variable.
- Trigger conditions for escape hatches (TimescaleDB at 1M events/day, Neo4j at 3-hop > 100ms).
- The four canonical tables + their indexes.

Capture `docs/_meta/f5-verification-<date>.md`.

- [ ] **Step 1: Run all gates.**
- [ ] **Step 2: Write verification record.**
- [ ] **Step 3: Draft ADR-009.**
- [ ] **Step 4: Commit** — `docs(f5): final verification + adr-009 memory architecture`.

**Acceptance:** Memory engines runs end-to-end against a live Postgres. Three stores cover episodic / procedural / semantic read patterns. RLS enforces tenant isolation. Audit chain verifies. ADR-009 records the architectural decision and its escape-hatch triggers. **Phase 1a foundation now at 5/6** (F.6 Audit Agent remains).

---

## Self-Review

**Spec coverage** (build-roadmap F.5 entry "Memory engines integration — TimescaleDB (episodic) + PostgreSQL (procedural) + Neo4j Aura (semantic). Per-tenant workspace pattern enforced"):

- ✓ Episodic memory — Task 3 (`EpisodicStore`).
- ✓ Procedural memory — Task 5 (`ProceduralStore`).
- ✓ Semantic memory — Task 6 (`SemanticStore`).
- ✓ Per-tenant isolation — Task 7 (RLS).
- ⚠️ Original three-engine plan (TimescaleDB + Neo4j) **deliberately deferred** — see Q1 resolution.

**Phase-1a / Phase 1b / Phase 2 caps (deferred):**

- ✓ TimescaleDB hypertables (Phase 1b if write volume forces it).
- ✓ Neo4j Aura (Phase 2 if recursive CTE becomes bottleneck).
- ✓ Cross-tenant memory queries (Phase 2).
- ✓ Memory garbage collection / TTL (Phase 1c).
- ✓ Multi-region replicas (Phase 2 GA).

**Pattern parity vs D.1 / D.2 / D.3 / F.4:**

- ✓ 12-task structure (vs 16-task for agent plans — F.4 was 12 tasks, F.5 follows that shape).
- ✓ Three Q-decisions resolved in code or pre-resolved in the plan opener.
- ✓ Reference template names F.4 — F.5 is structurally F.4 with three more tables.
- ✓ aiosqlite-for-unit-tests + Postgres-for-integration pattern carries from F.4.
- ✓ Opt-in `NEXUS_LIVE_*` integration test pattern carries from charter / cloud-posture.

**What's different from F.4:**

- **New ADR** (ADR-009) drafted alongside Task 12 — the Q1 resolution (collapse three engines to one) is a substantive architectural decision worth recording separately from F.4's incremental decisions.
- **First Postgres extension dependency** (pgvector) in the substrate. The operator runbook explicitly walks through `CREATE EXTENSION`.
- **Row-Level Security is mandatory**, not optional. F.4's tenant_id was application-side; F.5's tenant_id is engine-enforced.

**Acceptance gates (carry-forward from F.4):**

- ≥ 80% coverage on `charter.memory` at Task 12.
- ruff + format + mypy strict clean across the new module.
- Live Postgres integration test passes when `NEXUS_LIVE_POSTGRES=1`.
- Charter audit chain verifies after every memory write.
- ADR-009 records the architecture + escape-hatch triggers.

---

## Why F.5 before D.4

D.7 Investigation Agent **requires** the semantic-memory knowledge graph. A.4 Meta-Harness **requires** the episodic-memory event store. Building three more detection agents (D.4 / D.5 / D.6) without F.5 means those agents emit findings but downstream consumers can't cross-reference them. F.5 is the leverage point that unblocks the second half of Track-D, not just the foundation track.

**Recommended next plan after F.5: F.6 Audit Agent.** F.6 wraps the existing `charter.audit` + `control_plane.auth.audit` machinery as a queryable agent surface for compliance teams. Once F.5 + F.6 land, **Phase 1a foundation is complete** and Track-D parallelization can begin in earnest.
