# Live Correlation Run on a Persistent Graph — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `correlation_run` that runs data-security → identity (both writing one shared `SemanticStore`) → investigation/D.7, producing a real, persisted OCSF 2005 toxic-combination finding — proven in-memory (CI) and against real Postgres (gated `NEXUS_LIVE_POSTGRES`).

**Architecture:** A production session-factory builder provisions a Postgres-backed store (a verbatim lift of the existing live-Postgres test pattern). Identity gains a small expander that drives its dormant `_synthesize_admin_grants` into real `HAS_ACCESS_TO` edges against the tenant's resource nodes. A sequenced `correlation_run` orchestrator constructs three contracts, runs the agents in order against the shared store, and wires identity's findings into D.7 as a sibling workspace.

**Tech Stack:** Python 3.12, async, SQLAlchemy async (`async_sessionmaker`), alembic, `charter.memory` (`SemanticStore`, `AuditStore`), the three agents' `run()`, pytest + pytest-asyncio.

## Global Constraints

- **Real code only** — no supplied/faked grants. The `HAS_ACCESS_TO` edge is DERIVED by identity's real code from a (fixture) `IdentityListing`. Cloud _input_ is a fixture; the _derivation_ is real.
- **Additive / offline-inert.** Identity's new write is gated on `semantic_store is not None` (consistent with `record_listing`) → default behavior byte-identical. No existing signature changed except additive params.
- **HAS_ACCESS_TO = admin-grade only** (over-permissioned principal → every tenant `CLOUD_RESOURCE`). Mark the bound with a comment; fine-grained non-admin + the live `SimulatePrincipalPolicy` simulator are explicitly deferred.
- **Ordering:** data-security MUST run before identity (identity links to resource nodes data-security wrote). The orchestrator enforces this.
- **Typed vocabulary** (`NodeCategory`/`EdgeType`); **tenant-scoped** (`contract.customer_id`); **read/write separation** (`kg_query` read-only).
- **CI store does not enforce RLS** (SQLite) — DB-level RLS proven only by the gated Postgres test. State it in the test docstring.
- Commit lines ≤100 chars. Branch is `slice-live-correlation-run`.

---

## File Structure

| File                                                                       | Create/Modify            | Responsibility                                                                |
| -------------------------------------------------------------------------- | ------------------------ | ----------------------------------------------------------------------------- |
| `packages/charter/src/charter/memory/provisioning.py`                      | Create                   | `build_session_factory(dsn, *, run_migrations)` — production Postgres factory |
| `packages/charter/tests/integration/test_provisioning_live_postgres.py`    | Create                   | gated round-trip through the production factory                               |
| `packages/agents/identity/src/identity/agent.py`                           | Modify (~after line 228) | drive admin grants → `HAS_ACCESS_TO` against tenant resources                 |
| `packages/agents/identity/tests/test_kg_writer.py` (or test_agent_unit.py) | Modify                   | identity writes `HAS_ACCESS_TO` when resources exist                          |
| `packages/runtime/src/nexus_runtime/correlation.py`                        | Create                   | `correlation_run` orchestrator (sequenced)                                    |
| `packages/runtime/tests/test_correlation_run.py`                           | Create                   | CI orchestration e2e (in-memory) + negatives                                  |
| `packages/runtime/tests/integration/test_correlation_live_postgres.py`     | Create                   | gated real-Postgres orchestration + persistence                               |

---

### Task 1: production session-factory builder

**Files:**

- Create: `packages/charter/src/charter/memory/provisioning.py`
- Test: `packages/charter/tests/integration/test_provisioning_live_postgres.py`

**Interfaces:**

- Produces: `async def build_session_factory(dsn: str, *, run_migrations: bool = False) -> async_sessionmaker[AsyncSession]` and `def run_migrations(dsn: str) -> None`. The orchestrator builds `SemanticStore(factory)` + `AuditStore(factory)` from the returned factory.

- [ ] **Step 1: Read the proven pattern**

Read `packages/charter/tests/integration/test_memory_live_postgres.py` lines ~92-133 — it already does: alembic `command.upgrade(cfg, "head")` with `sqlalchemy.url` set to the sync (`+psycopg2`) form of the DSN, then `create_async_engine` + `async_sessionmaker(engine, expire_on_commit=False)`. Your factory lifts exactly this. Note the async→sync URL conversion helper (`_alembic_url_from`) and the `alembic.ini` path (`charter_root / "alembic.ini"`).

- [ ] **Step 2: Write the failing (gated) test**

```python
# packages/charter/tests/integration/test_provisioning_live_postgres.py
"""Gated (NEXUS_LIVE_POSTGRES=1): the production factory builds a working,
migrated, RLS-capable store against real Postgres. CI skips this."""
import os

import pytest
from charter.memory.provisioning import build_session_factory
from charter.memory.semantic import SemanticStore

_LIVE = os.environ.get("NEXUS_LIVE_POSTGRES") == "1"
# Reuse the same DSN/fresh-db setup as test_memory_live_postgres.py (import its helpers
# or replicate _TARGET_URL + fresh_database). Keep this test's DSN pointing at a throwaway DB.

pytestmark = pytest.mark.skipif(not _LIVE, reason="set NEXUS_LIVE_POSTGRES=1 + reachable Postgres")


@pytest.mark.asyncio
async def test_build_session_factory_round_trips(postgres_dsn: str) -> None:
    factory = await build_session_factory(postgres_dsn, run_migrations=True)
    store = SemanticStore(factory)
    eid = await store.upsert_entity(
        tenant_id="t1", entity_type="cloud_resource",
        external_id="arn:aws:s3:::b", properties={})
    rows = await store.list_entities_by_type(tenant_id="t1", entity_type="cloud_resource")
    assert any(r.entity_id == eid for r in rows)
```

(Use the `fresh_database`/migration fixtures from `test_memory_live_postgres.py` for `postgres_dsn` — replicate or import them.)

- [ ] **Step 3: Implement the factory**

```python
# packages/charter/src/charter/memory/provisioning.py
"""Production SemanticStore/AuditStore session-factory provisioning (Postgres).

Lifts the proven live-test pattern into a reusable production builder: run alembic
migrations (sync psycopg2 URL), then return an async session factory. The only store
factory previously in the repo was the in-memory test one — this is its production
counterpart. SemanticStore(factory) + AuditStore(factory) are built by the caller.
"""
from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_CHARTER_ROOT = Path(__file__).resolve().parents[3]  # packages/charter


def _alembic_url(dsn: str) -> str:
    """Alembic runs sync — swap the asyncpg driver for psycopg2."""
    return dsn.replace("+asyncpg", "+psycopg2")


def run_migrations(dsn: str) -> None:
    cfg = Config(str(_CHARTER_ROOT / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", _alembic_url(dsn))
    command.upgrade(cfg, "head")


async def build_session_factory(
    dsn: str, *, run_migrations: bool = False
) -> async_sessionmaker[AsyncSession]:
    """Build a production async session factory from a Postgres DSN.

    When ``run_migrations`` is True, applies ``alembic upgrade head`` first (use for a
    fresh DB / first boot; production normally migrates out-of-band and passes False).
    """
    if run_migrations:
        globals()["run_migrations"]  # noqa: B018 - see note
    return async_sessionmaker(create_async_engine(dsn), expire_on_commit=False)
```

> NOTE: do not shadow the module function with the param name. Rename the param to `migrate: bool = False` and call `run_migrations(dsn)` inside. Final form:
>
> ```python
> async def build_session_factory(dsn: str, *, migrate: bool = False) -> async_sessionmaker[AsyncSession]:
>     if migrate:
>         run_migrations(dsn)
>     return async_sessionmaker(create_async_engine(dsn), expire_on_commit=False)
> ```
>
> Verify `_CHARTER_ROOT` resolves to `packages/charter` (where `alembic.ini` lives) — adjust `parents[N]` if the file depth differs.

- [ ] **Step 4: Verify**

Run (gated): `NEXUS_LIVE_POSTGRES=1 uv run pytest packages/charter/tests/integration/test_provisioning_live_postgres.py -v` (requires `docker compose -f docker/docker-compose.dev.yml up -d postgres`).
Ungated CI: confirm it SKIPS cleanly: `uv run pytest packages/charter/tests/integration/test_provisioning_live_postgres.py -v` → 1 skipped.

- [ ] **Step 5: Commit**

```bash
git add packages/charter/src/charter/memory/provisioning.py \
        packages/charter/tests/integration/test_provisioning_live_postgres.py
git commit -m "feat(charter): production Postgres session-factory provisioning"
```

---

### Task 2: identity drives admin grants → real `HAS_ACCESS_TO`

**Files:**

- Modify: `packages/agents/identity/src/identity/agent.py` (add a helper + one call after grants are computed, ~line 228)
- Test: `packages/agents/identity/tests/test_kg_writer.py`

**Interfaces:**

- Consumes: `_synthesize_admin_grants(listing) -> list[EffectiveGrant]` (existing; `EffectiveGrant` has `principal_arn`, `is_admin`); `SemanticStore.list_entities_by_type`; `KnowledgeGraphWriter.record_access` (existing, uncalled).
- Produces: identity's `run()`, when `semantic_store` is present, writes `IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE` for each admin-grade principal × each tenant resource node.

- [ ] **Step 1: Write the failing test**

```python
# add to packages/agents/identity/tests/test_kg_writer.py
import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from identity.agent import _write_access_edges  # new helper
from identity.tools.permission_paths import EffectiveGrant


@pytest.mark.asyncio
async def test_write_access_edges_expands_admin_over_tenant_resources():
    async with in_memory_semantic_store() as store:
        # a resource node already in the tenant graph (as data-security would have written):
        bucket = await store.upsert_entity(
            tenant_id="t1", entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:aws:s3:::acme-pii", properties={})
        grants = [EffectiveGrant(
            principal_arn="arn:aws:iam::1:role/admin", action="*:*",
            resource_pattern="*", effect="Allow", source_policy_arns=(), is_admin=True)]

        await _write_access_edges(store, "t1", grants)

        role = await store.upsert_entity(
            tenant_id="t1", entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:aws:iam::1:role/admin", properties={})
        edges = await store.get_relationships_from(
            tenant_id="t1", src_entity_id=role, edge_types=(EdgeType.HAS_ACCESS_TO.value,))
        assert len(edges) == 1
        assert edges[0].dst_entity_id == bucket


@pytest.mark.asyncio
async def test_write_access_edges_noop_when_no_admin_or_no_resources():
    async with in_memory_semantic_store() as store:
        # non-admin grant → nothing
        non_admin = [EffectiveGrant(
            principal_arn="arn:aws:iam::1:role/x", action="s3:Get",
            resource_pattern="arn:aws:s3:::b", effect="Allow", source_policy_arns=(), is_admin=False)]
        await _write_access_edges(store, "t1", non_admin)
        assert await store.list_entities_by_type(
            tenant_id="t1", entity_type=NodeCategory.IDENTITY.value) == []
```

(Confirm `EffectiveGrant`'s exact constructor kwargs from `identity/tools/permission_paths.py` and adjust the fixture if a field differs.)

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest packages/agents/identity/tests/test_kg_writer.py -k write_access_edges -v`
Expected: FAIL — `ImportError: cannot import name '_write_access_edges'`.

- [ ] **Step 3: Implement the helper + wire it into run()**

Add the helper near the other private helpers in `agent.py`:

```python
async def _write_access_edges(
    semantic_store: SemanticStore,
    customer_id: str,
    grants: list[EffectiveGrant],
) -> None:
    """Write IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE for admin-grade principals.

    Drives the offline admin-grant synthesis: an admin (resource_pattern "*") can reach
    every resource, so we expand "*" against the tenant's concrete CLOUD_RESOURCE nodes
    (written by data-security/cloud-posture, keyed by ARN). record_access upserts
    idempotently → edges land on the existing resource nodes.

    # Bound (v1): admin-grade only. Fine-grained non-admin access needs concrete
    # per-statement Resource extraction (not implemented) + the live SimulatePrincipalPolicy
    # simulator (needs live AWS) — deferred to a later depth slice.
    """
    admins = [g for g in grants if g.is_admin]
    if not admins:
        return
    resources = await semantic_store.list_entities_by_type(
        tenant_id=customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
    )
    if not resources:
        return
    kg = KnowledgeGraphWriter(semantic_store, customer_id)
    await kg.record_access(
        [(g.principal_arn, r.external_id) for g in admins for r in resources]
    )
```

Then call it in `run()` immediately AFTER `grants` is computed (the `if assess_effective_perms / else` block, ~line 218) and the `semantic_store` is present. Insert after that block:

```python
        if semantic_store is not None:
            await _write_access_edges(semantic_store, contract.customer_id, grants)
```

Add imports if missing: `from charter.memory.graph_types import NodeCategory`, `from identity.tools.permission_paths import EffectiveGrant`, and ensure `SemanticStore`/`KnowledgeGraphWriter` are imported (KnowledgeGraphWriter already is for `record_listing`).

- [ ] **Step 4: Verify**

Run: `uv run pytest packages/agents/identity/tests/test_kg_writer.py -k write_access_edges -v` → PASS.
Run the full identity suite (no regression — additive, gated on store): `uv run pytest packages/agents/identity -q` → all pass.

- [ ] **Step 5: Commit**

```bash
git add packages/agents/identity/src/identity/agent.py \
        packages/agents/identity/tests/test_kg_writer.py
git commit -m "feat(identity): drive admin grants into HAS_ACCESS_TO over tenant resources"
```

---

### Task 3: `correlation_run` orchestrator + CI e2e

**Files:**

- Create: `packages/runtime/src/nexus_runtime/correlation.py`
- Test: `packages/runtime/tests/test_correlation_run.py`

**Interfaces:**

- Consumes: `data_security.agent.run`, `identity.agent.run`, `investigation.agent.run`; `SemanticStore`, `AuditStore`; `ExecutionContract`, `BudgetSpec`.
- Produces: `async def correlation_run(*, session_factory, tenant, ds_inventory_feed, workspace_root) -> IncidentReport`. Builds `SemanticStore(session_factory)` + `AuditStore(session_factory)`; runs data-security (with `ds_inventory_feed`) → identity → D.7 (`sibling_workspaces=(ds_ws, id_ws)`, `detect_toxic_combinations=True`); returns D.7's `IncidentReport`.

- [ ] **Step 1: Read the contract + agent-invocation patterns**

Read each agent's test contract helper for the exact `permitted_tools`/workspace each agent's `run()` needs (these are proven to work): data-security `_make_contract` (`packages/agents/data-security/tests/test_agent.py`), identity `_contract` (`packages/agents/identity/tests/test_agent_unit.py`), investigation `_contract` (`packages/agents/investigation/tests/test_agent.py`). Mirror their `permitted_tools` per agent — do not invent tool lists. Also read investigation's `session_factory`/`semantic_store`/`audit_store` fixtures (test_agent.py ~46-66) for the in-memory factory pattern your CI test reuses.

- [ ] **Step 2: Write the failing CI e2e test**

```python
# packages/runtime/tests/test_correlation_run.py
"""CI orchestration e2e (in-memory store, fixture cloud data). The HAS_ACCESS_TO edge
is DERIVED by real identity code from a fixture admin IdentityListing — not supplied.
NOTE: SQLite does not enforce RLS; DB-level tenant isolation is proven by the gated
Postgres test, not here."""
import json
from pathlib import Path

import pytest
# reuse the in-memory async session_factory pattern from investigation's test fixtures
# (sqlite+aiosqlite with tables created); import or replicate it as `session_factory`.
from nexus_runtime.correlation import correlation_run


def _public_pii_inventory(path: Path) -> Path:
    # mirror data-security's _write_inventory / _public_bucket_dict from its test_agent.py
    # one public bucket "acme-pii" with PII so data-security writes is_public + EXPOSES_DATA.
    ...  # fill from data-security test helpers
    return path


@pytest.mark.asyncio
async def test_correlation_run_surfaces_persisted_toxic_combination(
    tmp_path: Path, monkeypatch, session_factory
) -> None:
    # identity reads its listing via aws_iam_list_identities — monkeypatch it to a fixture
    # admin principal (mirror identity test's _patch_listing).
    import identity.agent as identity_agent
    async def _fake_list(**_): return _admin_listing()  # one admin role
    monkeypatch.setattr(identity_agent, "aws_iam_list_identities", _fake_list)

    inv = _public_pii_inventory(tmp_path / "inv.json")
    report = await correlation_run(
        session_factory=session_factory, tenant="t1",
        ds_inventory_feed=inv, workspace_root=tmp_path)

    statements = [h.statement.lower() for h in report.hypotheses]
    assert any("over-permissioned" in s for s in statements), "real toxic combo must surface"
    assert report.to_ocsf()["class_uid"] == 2005


@pytest.mark.asyncio
async def test_correlation_run_dark_when_no_admin(tmp_path, monkeypatch, session_factory):
    import identity.agent as identity_agent
    async def _fake_list(**_): return _non_admin_listing()
    monkeypatch.setattr(identity_agent, "aws_iam_list_identities", _fake_list)
    inv = _public_pii_inventory(tmp_path / "inv.json")
    report = await correlation_run(
        session_factory=session_factory, tenant="t1",
        ds_inventory_feed=inv, workspace_root=tmp_path)
    assert not any("over-permissioned" in h.statement.lower() for h in report.hypotheses)
```

> The `_admin_listing()`/`_non_admin_listing()`/`_public_pii_inventory` fixtures mirror the existing identity + data-security test helpers — copy their shapes (an `IdentityListing` with a role carrying `AdministratorAccess`; a public bucket dict with a PII classifier hit). Read those test files to reproduce exact shapes.

- [ ] **Step 3: Implement the orchestrator**

```python
# packages/runtime/src/nexus_runtime/correlation.py
"""Sequenced correlation run: writers populate one shared graph, then D.7 correlates.

NOT the supervisor's parallel dispatch — correlation is inherently ordered (data-security
writes resources + EXPOSES_DATA, then identity links HAS_ACCESS_TO to them, then D.7 reads).
Returns D.7's IncidentReport; the TOXIC_COMBINATION node + OCSF 2005 are persisted in the
shared store. Cloud input is provided by the caller (fixture feed / live readers); graph
writes are real agent code.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.audit import AuditStore
from charter.memory.semantic import SemanticStore
from data_security.agent import run as data_security_run
from identity.agent import run as identity_run
from investigation.agent import run as investigation_run
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from ulid import ULID

# permitted_tools per agent: mirror each agent's test contract helper (do not invent).
_DS_TOOLS = [...]   # from data-security _make_contract
_ID_TOOLS = [...]   # from identity _contract
_D7_TOOLS = [...]   # from investigation _contract


def _contract(tenant: str, target: str, tools: list[str], ws: Path, outputs: list[str]) -> ExecutionContract:
    ws.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    return ExecutionContract(
        schema_version="0.1",
        delegation_id=str(ULID()),
        source_agent="correlation_run",
        target_agent=target,
        customer_id=tenant,
        task=f"correlation: {target}",
        required_outputs=outputs,
        budget=BudgetSpec(llm_calls=5, tokens=20_000, wall_clock_sec=120.0,
                          cloud_api_calls=50, mb_written=20),
        permitted_tools=tools,
        completion_condition="outputs exist",
        escalation_rules=[],
        workspace=str(ws),
        persistent_root=str(ws / "persistent"),
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )


async def correlation_run(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    tenant: str,
    ds_inventory_feed: Path | str | None,
    workspace_root: Path,
):
    store = SemanticStore(session_factory)
    audit_store = AuditStore(session_factory)

    ds_ws = workspace_root / "data_security"
    id_ws = workspace_root / "identity"
    d7_ws = workspace_root / "investigation"

    # 1. data-security: resources + is_public + EXPOSES_DATA
    await data_security_run(
        _contract(tenant, "data_security", _DS_TOOLS, ds_ws, ["findings.json", "report.md"]),
        s3_inventory_feed=ds_inventory_feed,
        semantic_store=store,
    )
    # 2. identity: IDENTITY nodes + HAS_ACCESS_TO (admin → the resources just written)
    await identity_run(
        _contract(tenant, "identity", _ID_TOOLS, id_ws, ["findings.json", "summary.md"]),
        semantic_store=store,
    )
    # 3. D.7: read the graph + identity's findings → persisted toxic combination
    return await investigation_run(
        _contract(tenant, "investigation", _D7_TOOLS, d7_ws,
                  ["incident_report.json", "timeline.json"]),
        audit_store=audit_store,
        semantic_store=store,
        sibling_workspaces=(ds_ws, id_ws),
        detect_toxic_combinations=True,
    )


__all__ = ["correlation_run"]
```

> Fill `_DS_TOOLS`/`_ID_TOOLS`/`_D7_TOOLS` and `required_outputs` from each agent's test contract helper. Confirm `AuditStore` import path (`charter.memory.audit` or similar) and the `ulid` import (the codebase uses `from ulid import ULID` — `semantic.py` does `str(ULID())`).

- [ ] **Step 4: Verify**

Run: `uv run pytest packages/runtime/tests/test_correlation_run.py -v` → PASS (positive surfaces the toxic combo; no-admin negative stays dark).
Run the runtime suite + the three agents (no regression): `uv run pytest packages/runtime packages/agents/identity packages/agents/data-security packages/agents/investigation -q`.

- [ ] **Step 5: Commit**

```bash
git add packages/runtime/src/nexus_runtime/correlation.py \
        packages/runtime/tests/test_correlation_run.py
git commit -m "feat(runtime): sequenced correlation_run populates graph + persists toxic combo"
```

---

### Task 4: gated real-Postgres orchestration test

**Files:**

- Create: `packages/runtime/tests/integration/test_correlation_live_postgres.py`

**Interfaces:** Consumes Task 1 (`build_session_factory`) + Task 3 (`correlation_run`).

- [ ] **Step 1: Write the gated test**

```python
# packages/runtime/tests/integration/test_correlation_live_postgres.py
"""Gated (NEXUS_LIVE_POSTGRES=1): the FULL correlation run against REAL Postgres — agents
populate one migrated, RLS-scoped graph and D.7's toxic combination is PERSISTED + readable.
Proves what the SQLite CI test cannot: DB-level persistence + RLS."""
import os
from pathlib import Path

import pytest
from charter.memory.graph_types import NodeCategory
from charter.memory.provisioning import build_session_factory
from charter.memory.semantic import SemanticStore
from nexus_runtime.correlation import correlation_run

_LIVE = os.environ.get("NEXUS_LIVE_POSTGRES") == "1"
pytestmark = pytest.mark.skipif(not _LIVE, reason="set NEXUS_LIVE_POSTGRES=1 + reachable Postgres")


@pytest.mark.asyncio
async def test_correlation_persists_toxic_combination_on_postgres(
    tmp_path: Path, monkeypatch, postgres_dsn: str
) -> None:
    import identity.agent as identity_agent
    async def _fake_list(**_): return _admin_listing()  # reuse Task 3 fixture
    monkeypatch.setattr(identity_agent, "aws_iam_list_identities", _fake_list)

    factory = await build_session_factory(postgres_dsn, migrate=True)
    inv = _public_pii_inventory(tmp_path / "inv.json")  # reuse Task 3 fixture
    report = await correlation_run(
        session_factory=factory, tenant="t1", ds_inventory_feed=inv, workspace_root=tmp_path)

    assert any("over-permissioned" in h.statement.lower() for h in report.hypotheses)
    # PERSISTENCE: the TOXIC_COMBINATION node is durably written + readable from Postgres
    store = SemanticStore(factory)
    nodes = await store.list_entities_by_type(
        tenant_id="t1", entity_type=NodeCategory.TOXIC_COMBINATION.value)
    assert len(nodes) >= 1
```

(Reuse the `postgres_dsn`/fresh-DB fixtures from `test_memory_live_postgres.py`, and the `_admin_listing`/`_public_pii_inventory` helpers from Task 3 — import or share them.)

- [ ] **Step 2: Verify**

Gated: `NEXUS_LIVE_POSTGRES=1 uv run pytest packages/runtime/tests/integration/test_correlation_live_postgres.py -v` (with docker Postgres up) → PASS.
Ungated CI: → 1 skipped.

- [ ] **Step 3: Commit**

```bash
git add packages/runtime/tests/integration/test_correlation_live_postgres.py
git commit -m "test(runtime): gated real-Postgres correlation run persists toxic combination"
```

---

## Self-Review

**Spec coverage:**

- `build_semantic_store(dsn)` provisioning → Task 1 (as `build_session_factory`, refined so SemanticStore + AuditStore share one factory — noted). ✓
- Identity real `HAS_ACCESS_TO` (admin → all tenant resources, dormant-code-driven, bounded) → Task 2. ✓
- Sequenced `correlation_run` orchestrator (writers → reader; supervisor placeholder NOT touched) → Task 3. ✓
- CI in-memory e2e + gated real-Postgres persistence test → Tasks 3 + 4; CI-no-RLS caveat in docstrings. ✓
- Cloud input = fixtures, derivation = real code → Task 3 monkeypatch + feed. ✓

**Type consistency:** `correlation_run(*, session_factory, tenant, ds_inventory_feed, workspace_root)` identical across Tasks 3/4. `_write_access_edges(store, customer_id, grants)` identical in Task 2 def + call. `EffectiveGrant`/`record_access`/`list_entities_by_type` used per their confirmed signatures.

**Open items to confirm during execution (tests surface each):**

1. `EffectiveGrant` exact constructor kwargs (`permission_paths.py`) — Task 2 fixture.
2. Each agent's `permitted_tools` + `required_outputs` from its test contract helper — Task 3 (`_DS_TOOLS`/`_ID_TOOLS`/`_D7_TOOLS`).
3. The in-memory `session_factory` fixture pattern (sqlite + tables) from investigation's test_agent.py — Tasks 3 reuse.
4. `AuditStore` import path; `_CHARTER_ROOT` `parents[N]` depth; `ulid` import.
5. data-security's `_write_inventory`/`_public_bucket_dict` + identity's `_patch_listing`/listing shape — Task 3 fixtures.

**Honest scope:** admin-grade HAS_ACCESS_TO only; cloud input fixtures; persistence gated; supervisor placeholder deferred; auto-driven loop deferred — all per the approved spec.
