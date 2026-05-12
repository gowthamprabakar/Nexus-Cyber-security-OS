# F.6 — Audit Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Audit Agent** (`packages/agents/audit/`), the **last Phase-1a foundation pillar** and **Agent #14** per the glossary ("append-only hash-chained log writer; the only agent the others cannot disable"). Wraps the existing per-invocation audit primitives (`charter.audit.AuditLog`, `charter.verifier.verify_audit_log`, and the F.5 memory-engine emissions) as a **queryable agent surface for compliance teams**.

**Strategic role.** F.6 closes Phase-1a foundations (F.1 ✓ · F.2 ✓ · F.3 ✓ · F.4 ✓ · F.5 ✓ · **F.6**). It unblocks:

- **Compliance exports** — SOC 2 Type 2 evidence, ISO 27001 logs, GDPR Article 30 records-of-processing — without the platform team writing custom one-off scripts per audit.
- **A.4 Meta-Harness Agent** — reads audit traces to score "did last week's NLAH rewrite improve agent behaviour?". F.6 turns the raw `audit.jsonl` files into a query-shaped dataset Meta-Harness can `JOIN` against.
- **D.7 Investigation Agent** — chains audit events across agents into incidents; needs a corpus, not raw files.
- **Customer self-service audit log** — surfaced via the operator console (S.\* tracks, Phase 1b).

**Q1 to resolve up-front.** Audit Agent is positioned in Track-F (foundation), not Track-D (detection agent), but glossary explicitly calls it Agent #14. ADR-007 (reference NLAH) governs every Track-D agent. **Q1: does F.6 ship under ADR-007's reference-NLAH template, or as a substrate-only consumer like F.5?**

**Resolution: ADR-007 template, with the always-on amendment.** F.6 has a queryable runtime surface (CLI + eval-runner + NLAH for natural-language audit queries) so the template applies. The one deviation from D.1/D.2/D.3: **F.6 has no budget envelope** — it must not be stoppable by a misconfigured caller. Captured as an ADR-007 v1.3 candidate at Task 16 (final verification) and locked into the agent driver at Task 11.

**Architecture:**

```
F.5 audit emissions ──┐
charter.audit.jsonl ──┼──→ AuditAgent.ingest ──→ Postgres `audit_events` table
control_plane.auth ──┘                                │
                                                      ▼
compliance team ──→ CLI / Markdown report ──→ AuditAgent.query (tenant / time / action / agent_id)
                                                      │
A.4 Meta-Harness ──→ AuditAgent.query_traces ─────────┘
                                                      │
                                              chain integrity verified
                                              via charter.verifier on every read
```

**Tech stack:** Python 3.12 · BSL 1.1 (per-agent licensing per ADR-001) · OCSF v1.3 Detection Finding (`class_uid 2007` Audit Activity) · pydantic 2.9 · click 8 · charter.llm_adapter (LLM adapter per ADR-007 v1.1) · charter.nlah_loader (NLAH per ADR-007 v1.2) · charter.memory (F.5 substrate — Audit Agent persists into the `episodes` table under its own `agent_id`, plus a dedicated `audit_events` table for fast tenant + time + action queries).

**Depends on:**

- F.1 charter — `AuditLog` + `verify_audit_log` are the primitives Audit Agent wraps.
- F.4 control-plane — `tenants` table for tenant lookup; `users` for the requesting principal on a query.
- F.5 memory engines — every memory write already emits an audit entry; Audit Agent is the read-side consumer. The `audit_events` table lives in the same Postgres + alembic head as the F.5 memory tables (one substrate, two pillars sharing a database).
- ADR-007 v1.1 + v1.2 — reference NLAH template; F.6 is the fifth agent to ship under it.

**Defers (Phase 1b / Phase 2):**

- **Real-time streaming ingest** (Kafka / NATS) — Phase 1b. v0.1 ingests from filesystem `audit.jsonl` paths + the `episodes` table on demand.
- **Long-term cold-storage archival** (S3 + Glacier) — Phase 1c. v0.1 keeps everything in Postgres.
- **Cross-tenant compliance queries** (e.g. "show me every action across all tenants in the last hour") — Phase 2; v0.1 is single-tenant per query, enforced by F.5 RLS.
- **External SIEM integration** (Splunk, Sumo, Elastic) — Phase 1b. v0.1 emits CSV + JSON; SIEM connectors come later.
- **Tamper alerting via PagerDuty / Slack** — Phase 1c. v0.1 surfaces chain breaks in the CLI report and the Meta-Harness eval signal; routing to external alerting tools is a separate track.

**Reference template:** D.3 Runtime Threat Agent shape (most-recent ADR-007 conformant agent). F.6 is structurally D.3 with: (a) different OCSF class_uid (2007 Audit Activity vs 2004 Detection); (b) one additional always-on bit on the driver; (c) one extra table in the alembic head; (d) read-side LLM use (natural-language audit queries) rather than write-side classification.

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status     | Commit    | Notes                                                                                                                                                                                                                                                                                                                                            |
| ---- | ---------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | ✅ done    | `338087e` | Bootstrap shipped — pyproject (BSL 1.1, eval-runner entry-point, `audit-agent` CLI script), `py.typed`, README. 6-test smoke gate covers ADR-007 v1.1/v1.2 hoists + F.5 MemoryService dep + anti-pattern guard. Repo-wide 1026 passed / 11 skipped.                                                                                              |
| 2    | ✅ done    | `90ead6f` | `AuditEventModel` extends `charter.memory.models.Base` with `audit_events` table. `(tenant_id, entry_hash)` UNIQUE → idempotent re-ingest. Three indexes match F.6 query paths. 8 tests. Repo-wide 1034 passed / 11 skipped.                                                                                                                     |
| 3    | ✅ done    | `a846885` | Alembic `0003_audit_events` migration. Chains from `0002_memory_rls`. Postgres-gated: payload GIN + RLS `tenant_isolation` policy. Dialect-portable indexes present on aiosqlite. 11 tests. Repo-wide 1045 passed / 11 skipped.                                                                                                                  |
| 4    | ✅ done    | `659bc47` | OCSF v1.3 API Activity (`class_uid 6003`, **plan-corrected from 2007**) pydantic schemas. `AuditEvent` / `AuditQueryResult` / `ChainIntegrityReport`, all frozen + JSON-round-tripping. Chain-specific fields ride in the OCSF `unmapped` slot. 22 tests. Repo-wide 1067 passed / 11 skipped.                                                    |
| 5    | ✅ done    | `f0d00e1` | `AuditStore` typed async accessor. Idempotent `ingest` via dialect-specific `INSERT ... ON CONFLICT DO NOTHING` (Postgres + sqlite). `query` with five filter axes; `count_by_action` window aggregation. 13 tests. Repo-wide 1080 passed / 11 skipped.                                                                                          |
| 6    | ✅ done    | `a6f7b3e` | `audit_jsonl_read(*, path, tenant_id)` async tool wrapper. `asyncio.to_thread` for filesystem read. Maps `AuditEntry.run_id` → `correlation_id`; stamps `source = jsonl:<path>`. Forgiving: malformed lines dropped silently. Schema correction: `source` max_length 64 → 512 (paths can be long). 10 tests. Repo-wide 1090 passed / 11 skipped. |
| 7    | ✅ done    | `fabe178` | `episode_audit_read(*, session_factory, tenant_id, since, until)` async tool. Reads F.5 `episodes` rows; roots each at `GENESIS_HASH` (table isn't chain-structured); computes `entry_hash` via `charter.audit._hash_entry`. Stamps `source = memory:<tenant>`. Deterministic across reads. 8 tests. Repo-wide 1098 passed / 11 skipped.         |
| 8    | ✅ done    | `cb24750` | `verify_audit_chain(events, *, sequential)`. Two modes: `sequential=True` enforces both chain-link + per-entry hash (jsonl chains); `sequential=False` per-entry hash only (memory:\* events). Stops at first break; returns `ChainIntegrityReport`. 8 tests. Repo-wide 1106 passed / 11 skipped.                                                |
| 9    | ✅ done    | `813d63a` | `render_markdown(*, tenant_id, since, until, result, chain)`. Header → Chain integrity → Volume by action (desc) → Volume by agent (desc) → Tamper alerts pinned (only on break, above per-action sections) → Per-action sections. Empty input degrades to "No audit events in this window." 10 tests. Repo-wide 1116 passed / 11 skipped.       |
| 10   | ⬜ pending | —         | NLAH bundle + 25-line `nlah_loader.py` shim per ADR-007 v1.2. NLAH text covers natural-language audit query phrasing.                                                                                                                                                                                                                            |
| 11   | ⬜ pending | —         | Charter `llm_adapter` consumption per ADR-007 v1.1 (no per-agent `llm.py`; anti-pattern guard test stays green). LLM use: convert NL audit query → typed `AuditStore.query` params.                                                                                                                                                              |
| 12   | ⬜ pending | —         | Agent driver `run(contract, *, llm_provider, memory, sources, since, until, ...)`. **Critical**: budget envelope's `wall_clock_sec` is honoured but every other budget axis is **always-on** (ignored cap → log a warning, never raise). Q1's deviation locked into code here.                                                                   |
| 13   | ⬜ pending | —         | 10 representative YAML eval cases: empty corpus; chain-clean ingest; chain-tamper detected; per-action query; per-tenant query; cross-source merge (file + memory); time-range filter; agent_id filter; correlation_id walk; LLM natural-language query → parsed params.                                                                         |
| 14   | ⬜ pending | —         | `AuditEvalRunner` + entry-point + 10/10 acceptance via `eval-framework run --runner audit`.                                                                                                                                                                                                                                                      |
| 15   | ⬜ pending | —         | CLI (`audit-agent eval` / `audit-agent run` / `audit-agent query`). The `query` subcommand exposes the operator-facing path: `audit-agent query --tenant T1 --action episode_appended --since 2026-05-01`.                                                                                                                                       |
| 16   | ⬜ pending | —         | README + operator runbook (`runbooks/audit_query_operator.md`) + ADR-007 v1.3 amendment (always-on agent class). Final verification record `docs/_meta/f6-verification-<date>.md`.                                                                                                                                                               |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-002](../../_meta/decisions/ADR-002-charter-as-context-manager.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md) · [ADR-009](../../_meta/decisions/ADR-009-memory-architecture.md) · [**ADR-007 v1.3**](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) — amendment drafted alongside Task 16.

---

## Resolved questions

| #   | Question                                                                     | Resolution                                                                                                                                                                                                                                             | Task    |
| --- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- |
| Q1  | Does F.6 ship under ADR-007's reference NLAH template?                       | **Yes**, with the always-on amendment locked at Task 12 + ratified as ADR-007 v1.3 at Task 16.                                                                                                                                                         | Task 16 |
| Q2  | Where does the `audit_events` table live?                                    | Same Postgres + alembic head as F.5 memory tables. F.5 already runs `version_table = "alembic_version_memory"`; F.6's migration extends that chain.                                                                                                    | Task 3  |
| Q3  | How does Audit Agent get told what to ingest?                                | Explicit `sources: list[Path]` for filesystem `audit.jsonl` files + an optional `memory: MemoryService` for the F.5-table consumer. No autodiscovery in v0.1 — operators pin the sources.                                                              | Task 12 |
| Q4  | Natural-language query path uses LLM — what happens when LLM is unavailable? | The CLI falls back to structured-flag-only queries (`--action`, `--since`, `--agent-id`). NL query is a UX nicety, not a load-bearing path.                                                                                                            | Task 11 |
| Q5  | "The only agent others cannot disable" — what does that mean operationally?  | Budget envelope is honoured only for `wall_clock_sec` (a runaway query is killed); every other axis (token, llm_calls, cloud_api_calls, mb_written) **logs a warning and proceeds**. Captured in code at Task 12, ratified in ADR-007 v1.3 at Task 16. | Task 12 |

---

## File map (target)

```
packages/agents/audit/
├── pyproject.toml                                # Task 1
├── README.md                                     # Tasks 1, 16
├── runbooks/
│   └── audit_query_operator.md                   # Task 16
├── src/audit/
│   ├── __init__.py                               # Task 1
│   ├── py.typed                                  # Task 1
│   ├── schemas.py                                # Task 4 (pydantic, OCSF 2007)
│   ├── store.py                                  # Task 5 (AuditStore async)
│   ├── chain.py                                  # Task 8 (verify_audit_chain)
│   ├── summarizer.py                             # Task 9
│   ├── nlah_loader.py                            # Task 10 (25-line shim)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── jsonl_reader.py                       # Task 6
│   │   └── episode_reader.py                     # Task 7
│   ├── agent.py                                  # Tasks 11, 12 (driver)
│   ├── eval_runner.py                            # Task 14
│   └── cli.py                                    # Task 15
├── nlah/
│   ├── README.md                                 # Task 10
│   ├── tools.md                                  # Task 10
│   └── examples/                                 # Task 10
├── eval/
│   └── cases/                                    # Task 13 (10 YAML cases)
└── tests/
    ├── test_pyproject.py                         # Task 1
    ├── test_schemas.py                           # Task 4
    ├── test_store.py                             # Task 5
    ├── test_tools_jsonl.py                       # Task 6
    ├── test_tools_episode.py                     # Task 7
    ├── test_chain.py                             # Task 8
    ├── test_summarizer.py                        # Task 9
    ├── test_nlah_loader.py                       # Task 10
    ├── test_agent.py                             # Task 12
    ├── test_eval_runner.py                       # Task 14
    └── test_cli.py                               # Task 15
```

Plus, in shared substrates:

```
packages/charter/src/charter/memory/models.py     # Task 2: + AuditEventModel
packages/charter/alembic/versions/                # Task 3: + 0003_audit_events
docs/_meta/decisions/                             # Task 16: + ADR-007 v1.3 amendment
docs/_meta/                                       # Task 16: + f6-verification-<date>.md
```

---

## Task 1: Bootstrap

Mirrors D.3 Task 1 exactly. Ship the package skeleton with enough scaffolding-free structure that `uv sync` lights it up and the smoke gate passes.

- [ ] **Step 1: Write failing tests** — `test_pyproject.py` asserts `[project]` name `nexus-audit-agent`, BSL 1.1 license, py.typed marker, entry-point group registered. Smoke test imports `charter.nlah_loader` (v1.2 hoist gate) and `charter.memory.MemoryService` (F.5 dependency).
- [ ] **Step 2: Implement** — pyproject.toml + src tree + README stub.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): bootstrap (pyproject + py.typed + smoke gate) (F.6 task 1)`.

---

## Task 2: `AuditEventModel` SQLAlchemy table

Extends `charter.memory.models` with `AuditEventModel`. Same `Base` so a single alembic head still covers everything. Schema:

```sql
audit_events (
  audit_event_id   BIGSERIAL PRIMARY KEY,
  tenant_id        VARCHAR(26)  NOT NULL,
  correlation_id   VARCHAR(32)  NOT NULL,
  agent_id         VARCHAR(64)  NOT NULL,
  action           VARCHAR(128) NOT NULL,
  payload          JSONB        NOT NULL,
  previous_hash    CHAR(64)     NOT NULL,
  entry_hash       CHAR(64)     NOT NULL,
  emitted_at       TIMESTAMPTZ  NOT NULL,
  ingested_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  source           VARCHAR(64)  NOT NULL  -- "jsonl:<path>" or "memory:<tenant>"
)
```

- [ ] **Step 1: Write failing tests** — `AuditEventModel` in `charter.memory.models` `__all__`; column shape + indexes via `Base.metadata.create_all` aiosqlite; ≥ 6 tests.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): auditeventmodel sqlalchemy table (F.6 task 2)`.

---

## Task 3: Alembic `0003_audit_events` migration

Chains from `0002_memory_rls`. Creates the `audit_events` table + Postgres-only RLS policy + GIN index on payload.

- [ ] **Step 1: Write failing tests** — structural (revision metadata, ENABLE ROW LEVEL SECURITY + CREATE POLICY tenant_isolation strings present) + end-to-end (`upgrade head` against aiosqlite leaves table reachable + downgrade clean). ≥ 6 tests.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): alembic 0003_audit_events migration (F.6 task 3)`.

---

## Task 4: OCSF v1.3 Audit Activity schemas

Pydantic `BaseModel` with `frozen=True`, `extra="forbid"`, JSON round-trip clean. Three models:

- `AuditEvent` — `class_uid: 2007`, `tenant_id`, `correlation_id`, `agent_id`, `action`, `payload`, `previous_hash`, `entry_hash`, `emitted_at`, `source`. Validation: `previous_hash` and `entry_hash` are 64-char hex.
- `AuditQueryResult` — `total: int`, `events: tuple[AuditEvent, ...]`, `count_by_action: dict[str, int]`, `count_by_agent: dict[str, int]`.
- `ChainIntegrityReport` — `valid: bool`, `entries_checked: int`, `broken_at_correlation_id: str | None`, `broken_at_action: str | None`.

- [ ] **Step 1: Write failing tests** — ≥ 12 tests covering field validation, hash-shape enforcement, JSON round-trip, equality.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): ocsf 2007 audit activity schemas (F.6 task 4)`.

---

## Task 5: `AuditStore`

Mirrors F.5 store pattern. Constructor takes `async_sessionmaker[AsyncSession]`. Surface:

```python
class AuditStore:
    async def ingest(self, *, tenant_id: str, events: Sequence[AuditEvent]) -> int: ...
    async def query(
        self, *, tenant_id: str,
        since: datetime | None = None,
        until: datetime | None = None,
        action: str | None = None,
        agent_id: str | None = None,
        correlation_id: str | None = None,
        limit: int = 1000,
    ) -> AuditQueryResult: ...
    async def count_by_action(
        self, *, tenant_id: str,
        since: datetime, until: datetime,
    ) -> dict[str, int]: ...
```

Ingestion is idempotent on `(tenant_id, entry_hash)`.

- [ ] **Step 1: Write failing tests** — ≥ 10 tests covering ingest idempotency, every filter combination, tenant isolation, sorted-by-emitted_at output.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): auditstore typed async accessor (F.6 task 5)`.

---

## Task 6: `audit_jsonl_read` filesystem tool

Async tool wrapper per ADR-005. Reads a `audit.jsonl` file produced by `charter.audit.AuditLog`, parses each line via `AuditEntry.from_json`, returns `tuple[AuditEvent, ...]`. Maps `AuditEntry.run_id` → `correlation_id`. Inherits the `source = "jsonl:<path>"` tag.

- [ ] **Step 1: Write failing tests** — ≥ 8 tests covering happy path, malformed line tolerance, empty file, missing file, source-tag stamping.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): audit_jsonl_read async tool wrapper (F.6 task 6)`.

---

## Task 7: `episode_audit_read` memory-table tool

Reads from F.5's `episodes` table where every memory-engine write emitted a chained audit entry (Task 8 of F.5 wired this). Converts `EpisodeModel` rows whose `action` is one of `episode_appended` / `playbook_published` / `entity_upserted` / `relationship_added` into the `AuditEvent` shape. Inherits the `source = "memory:<tenant_id>"` tag.

- [ ] **Step 1: Write failing tests** — ≥ 6 tests covering the four action types, tenant isolation, time-range filter, empty result.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): episode_audit_read memory-table tool (F.6 task 7)`.

---

## Task 8: Chain-integrity verifier

Wraps `charter.verifier.verify_audit_log` to work on an in-memory `tuple[AuditEvent, ...]`. Returns `ChainIntegrityReport`. Optional `sequential=True` parameter enforces that consecutive events' `previous_hash` chains; `sequential=False` only recomputes each entry's own hash.

- [ ] **Step 1: Write failing tests** — ≥ 8 tests: clean chain valid, single-tamper detected, genesis-hash chain start, sequential vs per-entry mode, empty input → valid+0.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): chain integrity verifier (F.6 task 8)`.

---

## Task 9: Markdown summarizer

Layout (top-down, mirrors D.3's critical-pin pattern):

```
# Audit summary — tenant <id>, <since> → <until>

## Chain integrity
<broken_at if any, else "Chain valid (<N> entries checked).">

## Volume by action
<sorted desc table>

## Volume by agent
<sorted desc table>

## Tamper alerts pinned
<chain breaks at top with full event context>

## Per-action sections
### action: <name>
<event list>
```

- [ ] **Step 1: Write failing tests** — ≥ 10 tests covering each section + chain-break pinning + empty-input edge case.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): markdown summarizer with tamper-alert pin (F.6 task 9)`.

---

## Task 10: NLAH bundle + 25-line shim

ADR-007 v1.2 conformance. NLAH text covers:

- Audit terminology (entry, chain, tenant, action).
- Natural-language query phrasing the LLM adapter translates to typed parameters.
- Severity policy for chain-break reports.

`nlah_loader.py` is the v1.2 shim — exactly 25 LOC delegating to `charter.nlah_loader`.

- [ ] **Step 1: Write failing tests** — ≥ 6 tests covering shim line count, delegation correctness, NLAH-bundle file presence.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): nlah bundle + 25-line shim (F.6 task 10)`.

---

## Task 11: Charter `llm_adapter` consumption

No per-agent `llm.py`. Audit Agent calls `charter.llm_adapter.complete_via_provider(...)` directly for the NL-query → typed-parameters translation.

- [ ] **Step 1: Write failing tests** — ≥ 6 tests: NL → typed params happy path, malformed LLM output → falls back to a structured-only query, anti-pattern guard (`find packages/agents/audit -name 'llm.py'` empty), LLM-unavailable graceful fallback.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): charter llm_adapter consumption (F.6 task 11)`.

---

## Task 12: Agent driver `run()`

The driver. Signature:

```python
async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,
    memory: MemoryService | None = None,
    sources: tuple[Path, ...] = (),
    since: datetime | None = None,
    until: datetime | None = None,
) -> AuditQueryResult: ...
```

Multi-source fan-out via `asyncio.TaskGroup` (mirrors D.3's three-feed pattern). **The always-on amendment**: enforces `wall_clock_sec` only; every other budget axis logs a structlog warning when exceeded and proceeds. The warning is itself an audit-emit so the Meta-Harness can observe it.

- [ ] **Step 1: Write failing tests** — ≥ 10 tests: empty sources, file-only, memory-only, file+memory merge, time-range filter, agent-id filter, budget warning (not raise) on overrun of every axis except wall_clock_sec, wall_clock_sec **does** raise.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): agent driver run() with always-on budget exception (F.6 task 12)`.

---

## Task 13: 10 representative YAML eval cases

Mirrors D.3 Task 12 (10 cases). Coverage:

1. Empty corpus (no sources).
2. Clean chain ingest (file only).
3. Tampered file (one entry's hash mutated) → chain break detected.
4. Per-action query.
5. Per-tenant query (tenant isolation).
6. Cross-source merge (file + memory).
7. Time-range filter.
8. Agent_id filter.
9. Correlation_id walk (every event with the same correlation_id).
10. NL-query path via LLM adapter → typed params.

- [ ] **Step 1: Author 10 YAML files** under `eval/cases/`.
- [ ] **Step 2: Run smoke against the cases** (`audit-agent eval eval/cases`).
- [ ] **Step 3: Commit** — `feat(audit): 10 representative eval cases (F.6 task 13)`.

---

## Task 14: `AuditEvalRunner` + entry-point + 10/10 acceptance

Registered via `[project.entry-points."nexus_eval_runners"]`. Verified through `eval-framework run --runner audit`.

- [ ] **Step 1: Write failing tests** — ≥ 12 tests covering the runner shape, entry-point resolution, 10/10 acceptance via the framework CLI, audit-log emission per run.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): eval-runner + entry-point + 10/10 (F.6 task 14)`.

---

## Task 15: CLI

Three subcommands. `audit-agent eval <cases_dir>` runs the eval suite (same shape as D.3). `audit-agent run` is the agent runner. `audit-agent query` is the operator-facing read path:

```bash
audit-agent query \
    --tenant 01HV0... \
    --since 2026-05-01 \
    --action episode_appended \
    --agent-id cloud_posture \
    --format markdown
```

Output formats: `markdown` (default), `csv`, `json`. Chain integrity verified on every read.

- [ ] **Step 1: Write failing tests** — ≥ 12 tests: --help, --version, eval happy/fail, run happy, query with each filter, three output formats, chain-break exit code 2.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(audit): cli (eval / run / query) (F.6 task 15)`.

---

## Task 16: README + runbook + ADR-007 v1.3 + final verification

ADR-007 v1.3 amendment: "**Always-on agent class**". An agent declared `always_on=True` (via a class-level flag or pyproject marker, TBD at implementation) honours only `wall_clock_sec` from its `BudgetSpec`; every other budget axis logs a structlog warning and continues. F.6 is the first member of the class. Future amendments to the budget envelope must explicitly preserve this exception.

Final verification record `docs/_meta/f6-verification-<date>.md` covers: gate readout (≥80% package coverage; ruff/mypy clean; eval framework 10/10; full ADR-007 v1.1+v1.2+v1.3 conformance), per-task surface table, Wiz-coverage delta (CSPM 8%, Vulnerability 3%, CIEM 3%, CWPP 5%, **Compliance/Audit ~3%**), sub-plan completion delta closing Phase-1a foundations.

- [ ] **Step 1: Write README + runbook**.
- [ ] **Step 2: Draft ADR-007 v1.3 amendment**.
- [ ] **Step 3: Final verification record**.
- [ ] **Step 4: Commit** — `docs(audit): readme + runbook + adr-007 v1.3 + verification (F.6 task 16)`.

---

## Risks

| Risk                                                                                                            | Mitigation                                                                                                                                                                                                                   |
| --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit_events` write volume swamps Postgres at production scale.                                                | F.5's ivfflat re-tune note already calls out the post-30-day re-tune. Same pattern applies here: re-evaluate after first 30 days; consider Phase 1b TimescaleDB hypertable for `audit_events` if write rate > 1M/day/tenant. |
| Always-on flag becomes a footgun (an agent ships with `always_on=True` accidentally and burns infinite tokens). | ADR-007 v1.3 amendment ratifies the flag at the class level + requires an explicit allowlist in `charter.audit`. Only `audit_agent` is on the list in v0.1.                                                                  |
| Cross-source merge produces duplicate events (jsonl + memory both have the same chain).                         | `AuditStore.ingest` is idempotent on `(tenant_id, entry_hash)`. Test in Task 5 pins the contract.                                                                                                                            |
| Tamper detection produces false positives during legitimate log rotation.                                       | F.6 verifies sequential chains within a single source; cross-source merges check per-entry hashes only. Documented in the runbook (Task 16).                                                                                 |
| LLM unavailable → NL-query path breaks.                                                                         | CLI falls back to structured-only flags when `--no-llm` or `charter.llm_adapter` returns provider-unavailable. Task 11 + Task 15 own this.                                                                                   |

---

## Done definition

F.6 is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- ≥ 80% test coverage on `packages/agents/audit` (gate same as D.3).
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- `eval-framework run --runner audit` returns 10/10.
- ADR-007 v1.1 + v1.2 + **v1.3** conformance verified end-to-end.
- README + runbook reviewed.
- F.6 verification record committed.

That closes Phase-1a foundations. Phase 1a exit gate is then **met**; Track-D D.4+ rollout is fully unblocked.
