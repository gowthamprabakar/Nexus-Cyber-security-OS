# Toxic-Combination Slice (Public-Data-Exposure Path) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect and emit ONE end-to-end cross-agent attack path — _a publicly-exposed S3 bucket holding sensitive data, reachable by an over-permissioned identity_ — as a single OCSF 2005 finding, on the Postgres `SemanticStore` that already runs.

**Architecture:** Three existing agent `kg_writer`s already write the nodes and two of the three edges into one shared fleet graph; the only missing pieces are (1) a one-line entity-resolution fix so the same bucket is ONE node across agents, (2) the `HAS_ACCESS_TO` edge that identity deliberately deferred, (3) a thin read-only detector over the existing edge accessor, and (4) instantiation + emission in investigation (D.7). This is **purely additive** — no agent is rewired, no dependency removed, no existing behaviour changed (offline default still writes nothing → artifacts byte-identical). If it goes wrong, delete the branch.

**Tech Stack:** Python 3.12, async, `charter.memory.SemanticStore` (Postgres / in-memory for tests), `fleet_testkit` (`in_memory_semantic_store`), pytest + pytest-asyncio.

## Global Constraints

- **Additive only.** Do not change any existing public method signature, existing edge, or existing finding shape. The data-security/identity offline default (no store injected) MUST keep writing nothing.
- **Typed vocabulary only** — nodes via `NodeCategory`, edges via `EdgeType` (ADR-018). No free-string types. All required members already exist: `CLOUD_RESOURCE`, `IDENTITY`, `DATA_CLASSIFICATION`, `TOXIC_COMBINATION`; `HAS_ACCESS_TO`, `EXPOSES_DATA`, `CONTAINS`, `CONTRIBUTES_TO`.
- **Tenant-scoped** — every write/read pins the writer's `customer_id` via `KnowledgeGraphWriterBase` / `KgQuery`. Never accept a per-call tenant.
- **Read/write separation** — `kg_query` (A.4) stays READ-ONLY. The `TOXIC_COMBINATION` node write happens in the consumer (D.7), never in `kg_query`.
- **S3-only for this slice.** ARN canonicalization is S3-only; mark the ceiling with a `# ponytail:` comment and the upgrade path.
- **Privacy contract preserved** — only `ClassifierLabel` values cross into the graph, never matched substrings (data-security Q6).
- Commit messages ≤100 chars per line (project reset-trap rule). Branch is already `slice-toxic-combo-public-data-exposure`.

---

## File Structure

| File                                                                   | Create/Modify         | Responsibility                                                 |
| ---------------------------------------------------------------------- | --------------------- | -------------------------------------------------------------- |
| `packages/agents/data-security/src/data_security/canonical.py`         | Create                | `s3_bucket_arn(name)` — the shared join key                    |
| `packages/agents/data-security/src/data_security/kg_writer.py`         | Modify (line 44-46)   | Key the storage node by ARN, not bucket name                   |
| `packages/agents/identity/src/identity/kg_writer.py`                   | Modify (add method)   | `record_access()` — write `HAS_ACCESS_TO` to the ARN spine     |
| `packages/agents/meta-harness/src/meta_harness/kg_query.py`            | Modify (add detector) | `find_public_data_exposure()` — read-only toxic-combo detector |
| `packages/agents/investigation/src/investigation/toxic_combination.py` | Create                | Instantiate `TOXIC_COMBINATION` node + build the Hypothesis    |
| `packages/integration/.../tests/test_toxic_combination_slice.py`       | Create                | The end-to-end proof (positive + 2 negatives)                  |

---

### Task 1: Entity-resolution fix — data-security keys the bucket by ARN

The join key. Today cloud-posture/identity write `CLOUD_RESOURCE` keyed by ARN; data-security keys by `bucket.name`, so the same bucket is two disconnected nodes. Fix: data-security upserts the storage node by the canonical S3 ARN. Because `upsert_entity` is idempotent on `(tenant, type, external_id)`, both agents then collapse to ONE node.

**Files:**

- Create: `packages/agents/data-security/src/data_security/canonical.py`
- Modify: `packages/agents/data-security/src/data_security/kg_writer.py:44-46`
- Test: `packages/integration/src/fleet_testkit/tests/test_entity_resolution.py` (cross-agent — lives in the integration package)

**Interfaces:**

- Produces: `s3_bucket_arn(bucket_name: str) -> str` returning `f"arn:aws:s3:::{bucket_name}"`.
- Produces: data-security storage node now keyed `(customer_id, "cloud_resource", <s3 arn>)` — the same key cloud-posture's `upsert_asset(kind, external_id=<arn>, ...)` uses.

- [ ] **Step 1: Write the failing test** (proves the two agents now produce the SAME entity_id)

```python
# packages/integration/src/fleet_testkit/tests/test_entity_resolution.py
import pytest
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CpWriter
from data_security.canonical import s3_bucket_arn
from data_security.kg_writer import KnowledgeGraphWriter as DsWriter
from fleet_testkit import in_memory_semantic_store


@pytest.mark.asyncio
async def test_bucket_is_one_node_across_cloud_posture_and_data_security():
    """The SAME bucket written by cloud-posture (by ARN) and data-security must
    collapse to ONE graph node — the precondition for any cross-agent correlation."""
    name = "acme-pii"
    arn = s3_bucket_arn(name)
    async with in_memory_semantic_store() as store:
        cp = CpWriter(store, "tenant-1")
        cp_id = await cp.upsert_asset("s3-bucket", arn, {"region": "us-east-1"})

        ds = DsWriter(store, "tenant-1")
        ds_id = await store.upsert_entity(
            tenant_id="tenant-1",
            entity_type="cloud_resource",
            external_id=arn,
            properties={},
        )
        # data-security's writer, after the fix, must use the same key:
        assert ds._storage_external_id(name) == arn  # helper added in Step 3
        assert cp_id == ds_id  # one bucket, one node
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest packages/integration/src/fleet_testkit/tests/test_entity_resolution.py -v`
Expected: FAIL — `ModuleNotFoundError: data_security.canonical` (canonical.py not created yet).

- [ ] **Step 3: Create the canonicalizer + apply the fix**

```python
# packages/agents/data-security/src/data_security/canonical.py
"""Canonical cross-agent resource identifiers (the fleet-graph join key)."""
from __future__ import annotations


def s3_bucket_arn(bucket_name: str) -> str:
    """The ARN cloud-posture/identity key their CLOUD_RESOURCE spine node by.

    Using it as data-security's storage-node external_id collapses the bucket
    to ONE graph node across agents (upsert_entity is idempotent on
    (tenant, type, external_id)).

    # ponytail: S3-only. Other resource ARNs aren't name-derivable — add a
    # per-service canonicalizer when a second resource type joins the spine.
    """
    return f"arn:aws:s3:::{bucket_name}"
```

In `kg_writer.py`, add a tiny helper (so the test can assert the key) and use it:

```python
# at module top, with the other imports
from data_security.canonical import s3_bucket_arn

# inside class KnowledgeGraphWriter, add:
    @staticmethod
    def _storage_external_id(bucket_name: str) -> str:
        return s3_bucket_arn(bucket_name)

# in record(), replace the storage_id upsert external_id (was: bucket.name):
            storage_id = await self.upsert_node(
                NodeCategory.CLOUD_RESOURCE,
                self._storage_external_id(bucket.name),
                {
                    "resource_type": "s3-bucket",
                    "region": bucket.region,
                    "is_public": public,
                    "is_encrypted": encrypted,
                    "source": bucket.name,  # keep the human-readable name as a property
                },
            )
```

(Leave the `DATA_CLASSIFICATION` node id as `f"{bucket.name}:{label.value}"` — it is DSPM-owned, not a spine node.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest packages/integration/src/fleet_testkit/tests/test_entity_resolution.py -v`
Expected: PASS.

- [ ] **Step 5: Run data-security's existing writer tests (no regression)**

Run: `uv run pytest packages/agents/data-security/tests/test_kg_writer.py -v`
Expected: PASS. If any test asserts the old `bucket.name` key, update it to the ARN key (that assertion was encoding the bug).

- [ ] **Step 6: Commit**

```bash
git add packages/agents/data-security/src/data_security/canonical.py \
        packages/agents/data-security/src/data_security/kg_writer.py \
        packages/integration/src/fleet_testkit/tests/test_entity_resolution.py
git commit -m "fix(dspm): key storage node by S3 ARN so it joins the fleet-graph spine"
```

---

### Task 2: identity writes `HAS_ACCESS_TO` to the ARN spine

The one genuinely-new edge. Identity's writer deliberately omits `HAS_ACCESS_TO` ("the resource side is owned by D.1/D.5/F.3"). Now that the resource is a stable ARN node, identity can write the edge pointing at that spine node. The writer just persists; _which_ resource ARNs a principal can reach is computed by the agent driver from policy resource statements (out of the writer's scope — passed in).

**Files:**

- Modify: `packages/agents/identity/src/identity/kg_writer.py` (add `record_access`)
- Test: `packages/agents/identity/tests/test_kg_writer.py` (add a case)

**Interfaces:**

- Consumes: `KnowledgeGraphWriterBase.upsert_node`, `.add_edge` (inherited).
- Produces: `async def record_access(self, grants: Sequence[tuple[str, str]]) -> None` — each grant is `(principal_arn, resource_arn)`; upserts both spine nodes (idempotent) and writes `IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE`.

- [ ] **Step 1: Write the failing test**

```python
# add to packages/agents/identity/tests/test_kg_writer.py
import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from identity.kg_writer import KnowledgeGraphWriter


@pytest.mark.asyncio
async def test_record_access_writes_has_access_to_edge_on_arn_spine():
    role_arn = "arn:aws:iam::111122223333:role/app"
    bucket_arn = "arn:aws:s3:::acme-pii"
    async with in_memory_semantic_store() as store:
        w = KnowledgeGraphWriter(store, "tenant-1")
        await w.record_access([(role_arn, bucket_arn)])

        # the role node, resolved by ARN, has an outgoing HAS_ACCESS_TO to the bucket node.
        role_id = await store.upsert_entity(
            tenant_id="tenant-1", entity_type=NodeCategory.IDENTITY.value,
            external_id=role_arn, properties={})
        edges = await store.get_relationships_from(
            tenant_id="tenant-1", src_entity_id=role_id,
            edge_types=(EdgeType.HAS_ACCESS_TO.value,))
        assert len(edges) == 1
        bucket_id = await store.upsert_entity(
            tenant_id="tenant-1", entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=bucket_arn, properties={})
        assert edges[0].dst_entity_id == bucket_id
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest packages/agents/identity/tests/test_kg_writer.py::test_record_access_writes_has_access_to_edge_on_arn_spine -v`
Expected: FAIL — `AttributeError: 'KnowledgeGraphWriter' object has no attribute 'record_access'`.

- [ ] **Step 3: Implement `record_access`**

```python
# add inside class KnowledgeGraphWriter in identity/kg_writer.py
    async def record_access(self, grants: Sequence[tuple[str, str]]) -> None:
        """Write IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE edges (cross-agent spine).

        Each grant is ``(principal_arn, resource_arn)``. Both endpoints are upserted
        idempotently — same ARN ⇒ same spine node cloud-posture/DSPM already own, so
        the edge lands on the shared graph. ``grants`` is computed by the agent driver
        from policy resource statements; the writer only persists.
        """
        for principal_arn, resource_arn in grants:
            principal_node = await self.upsert_node(NodeCategory.IDENTITY, principal_arn, {})
            resource_node = await self.upsert_node(NodeCategory.CLOUD_RESOURCE, resource_arn, {})
            await self.add_edge(
                principal_node or "", resource_node or "", EdgeType.HAS_ACCESS_TO, {}
            )
```

Add `Sequence` to the `TYPE_CHECKING` imports if not already present:

```python
if TYPE_CHECKING:
    from collections.abc import Sequence
    from identity.tools.aws_iam import IdentityListing
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest packages/agents/identity/tests/test_kg_writer.py::test_record_access_writes_has_access_to_edge_on_arn_spine -v`
Expected: PASS.

- [ ] **Step 5: Run the full identity writer suite**

Run: `uv run pytest packages/agents/identity/tests/test_kg_writer.py -v`
Expected: PASS (record_access is additive; record_listing untouched).

- [ ] **Step 6: Commit**

```bash
git add packages/agents/identity/src/identity/kg_writer.py \
        packages/agents/identity/tests/test_kg_writer.py
git commit -m "feat(identity): write HAS_ACCESS_TO edges onto the fleet-graph ARN spine"
```

---

### Task 3: read-only toxic-combination detector in `kg_query`

The cortex. A 2-hop walk over the EXISTING `get_relationships_from` accessor: from each over-permissioned principal, follow `HAS_ACCESS_TO` → bucket, then `EXPOSES_DATA` → data-classification. `EXPOSES_DATA` is only written when the bucket is public (data-security:65-68), so its presence proves the _public_ + _sensitive_ legs in one edge. `kg_query` stays read-only.

**Files:**

- Modify: `packages/agents/meta-harness/src/meta_harness/kg_query.py` (add dataclass + method)
- Test: `packages/agents/meta-harness/tests/test_kg_query.py` (add cases)

**Interfaces:**

- Consumes: `KgQuery._edges_from` (existing private), `RelationshipRow`.
- Produces: `ToxicCombination(principal_id, resource_id, data_classification_id, path: tuple[PathEdge, PathEdge])` and `async def find_public_data_exposure(self, *, over_permissioned_principal_ids: Sequence[str]) -> list[ToxicCombination]`.

- [ ] **Step 1: Write the failing test**

```python
# add to packages/agents/meta-harness/tests/test_kg_query.py
import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery


async def _seed(store, *, public: bool, has_access: bool):
    t = "tenant-1"
    role = await store.upsert_entity(tenant_id=t, entity_type=NodeCategory.IDENTITY.value,
                                     external_id="arn:aws:iam::1:role/app", properties={})
    bucket = await store.upsert_entity(tenant_id=t, entity_type=NodeCategory.CLOUD_RESOURCE.value,
                                       external_id="arn:aws:s3:::acme-pii", properties={})
    data = await store.upsert_entity(tenant_id=t, entity_type=NodeCategory.DATA_CLASSIFICATION.value,
                                     external_id="acme-pii:SSN", properties={"data_type": "SSN"})
    if has_access:
        await store.add_relationship(tenant_id=t, src_entity_id=role, dst_entity_id=bucket,
                                     relationship_type=EdgeType.HAS_ACCESS_TO.value, properties={})
    # CONTAINS is always written; EXPOSES_DATA only when public:
    await store.add_relationship(tenant_id=t, src_entity_id=bucket, dst_entity_id=data,
                                 relationship_type=EdgeType.CONTAINS.value, properties={})
    if public:
        await store.add_relationship(tenant_id=t, src_entity_id=bucket, dst_entity_id=data,
                                     relationship_type=EdgeType.EXPOSES_DATA.value, properties={})
    return role, bucket, data


@pytest.mark.asyncio
async def test_detects_public_data_exposure_path():
    async with in_memory_semantic_store() as store:
        role, bucket, data = await _seed(store, public=True, has_access=True)
        q = KgQuery(store, "tenant-1")
        hits = await q.find_public_data_exposure(over_permissioned_principal_ids=[role])
        assert len(hits) == 1
        assert hits[0].principal_id == role
        assert hits[0].resource_id == bucket
        assert hits[0].data_classification_id == data


@pytest.mark.asyncio
async def test_no_hit_when_bucket_not_public():
    async with in_memory_semantic_store() as store:
        role, _, _ = await _seed(store, public=False, has_access=True)
        q = KgQuery(store, "tenant-1")
        assert await q.find_public_data_exposure(over_permissioned_principal_ids=[role]) == []


@pytest.mark.asyncio
async def test_no_hit_when_principal_has_no_access():
    async with in_memory_semantic_store() as store:
        role, _, _ = await _seed(store, public=True, has_access=False)
        q = KgQuery(store, "tenant-1")
        assert await q.find_public_data_exposure(over_permissioned_principal_ids=[role]) == []
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest packages/agents/meta-harness/tests/test_kg_query.py -k public_data_exposure -v`
Expected: FAIL — `AttributeError: 'KgQuery' object has no attribute 'find_public_data_exposure'`.

- [ ] **Step 3: Implement the detector**

```python
# add near the other dataclasses in kg_query.py
@dataclass(frozen=True, slots=True)
class ToxicCombination:
    """A public-data-exposure attack path: over-permissioned principal → public
    bucket → sensitive data. The `path` is the evidence chain (2 edges)."""

    principal_id: str
    resource_id: str
    data_classification_id: str
    path: tuple[PathEdge, PathEdge]


# add inside class KgQuery (read-only — no writes)
    async def find_public_data_exposure(
        self, *, over_permissioned_principal_ids: Sequence[str]
    ) -> list[ToxicCombination]:
        """Find principal --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data paths.

        EXPOSES_DATA is only written for public buckets, so its presence proves both
        the public and sensitive-data legs. Read-only; seeded by the caller with the
        over-permissioned principals (from identity's OVERPRIVILEGE findings)."""
        hits: list[ToxicCombination] = []
        for principal_id in over_permissioned_principal_ids:
            for access in await self._edges_from(principal_id, (EdgeType.HAS_ACCESS_TO.value,)):
                bucket_id = access.dst_entity_id
                for expose in await self._edges_from(bucket_id, (EdgeType.EXPOSES_DATA.value,)):
                    hits.append(
                        ToxicCombination(
                            principal_id=principal_id,
                            resource_id=bucket_id,
                            data_classification_id=expose.dst_entity_id,
                            path=(
                                PathEdge(principal_id, bucket_id, access.relationship_type),
                                PathEdge(bucket_id, expose.dst_entity_id, expose.relationship_type),
                            ),
                        )
                    )
        return hits
```

Add the import + export: `from charter.memory.graph_types import EdgeType` at the top, add `Sequence` (`from collections.abc import Sequence`), and add `"ToxicCombination"` to `__all__`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest packages/agents/meta-harness/tests/test_kg_query.py -k public_data_exposure -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Run the full kg_query suite**

Run: `uv run pytest packages/agents/meta-harness/tests/test_kg_query.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/agents/meta-harness/src/meta_harness/kg_query.py \
        packages/agents/meta-harness/tests/test_kg_query.py
git commit -m "feat(meta-harness): read-only public-data-exposure detector over the fleet graph"
```

---

### Task 4: instantiate the `TOXIC_COMBINATION` node + Hypothesis (investigation D.7)

The decorations + evidence step — the moment the never-instantiated `TOXIC_COMBINATION` node finally gets created, and the path becomes an emittable hypothesis. This is a small, self-contained module so it is independently reviewable before wiring into D.7's run loop (Task 5).

**Files:**

- Create: `packages/agents/investigation/src/investigation/toxic_combination.py`
- Test: `packages/agents/investigation/tests/test_toxic_combination.py`

**Interfaces:**

- Consumes: `ToxicCombination` (Task 3), `KnowledgeGraphWriterBase`, `Hypothesis` (investigation `schemas.py`: fields `hypothesis_id, statement, confidence, evidence_refs`).
- Produces:
  - `class ToxicCombinationWriter(KnowledgeGraphWriterBase)` with `async def record(self, combo: ToxicCombination) -> str | None` — upserts a `TOXIC_COMBINATION` node and `CONTRIBUTES_TO` edges from the 3 contributors to it; returns the node id.
  - `def to_hypothesis(combo: ToxicCombination, *, evidence_refs: tuple[str, ...]) -> Hypothesis`.

- [ ] **Step 1: Write the failing test**

```python
# packages/agents/investigation/tests/test_toxic_combination.py
import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import PathEdge, ToxicCombination
from investigation.toxic_combination import ToxicCombinationWriter, to_hypothesis


def _combo():
    return ToxicCombination(
        principal_id="P", resource_id="R", data_classification_id="D",
        path=(PathEdge("P", "R", EdgeType.HAS_ACCESS_TO.value),
              PathEdge("R", "D", EdgeType.EXPOSES_DATA.value)),
    )


@pytest.mark.asyncio
async def test_record_creates_toxic_combination_node_and_edges():
    async with in_memory_semantic_store() as store:
        w = ToxicCombinationWriter(store, "tenant-1")
        node_id = await w.record(_combo())
        assert node_id
        # each contributor has a CONTRIBUTES_TO edge into the toxic-combination node.
        for contributor in ("P", "R", "D"):
            edges = await store.get_relationships_from(
                tenant_id="tenant-1", src_entity_id=contributor,
                edge_types=(EdgeType.CONTRIBUTES_TO.value,))
            assert any(e.dst_entity_id == node_id for e in edges)


def test_to_hypothesis_carries_evidence_refs():
    h = to_hypothesis(_combo(), evidence_refs=("finding:dspm-1", "finding:ciem-2"))
    assert h.confidence == 1.0
    assert h.evidence_refs == ("finding:dspm-1", "finding:ciem-2")
    assert "over-permissioned" in h.statement.lower()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest packages/agents/investigation/tests/test_toxic_combination.py -v`
Expected: FAIL — `ModuleNotFoundError: investigation.toxic_combination`.

- [ ] **Step 3: Implement the module**

```python
# packages/agents/investigation/src/investigation/toxic_combination.py
"""Instantiate the TOXIC_COMBINATION node + build its emittable hypothesis (D.7).

Consumes the read-only ToxicCombination paths from meta-harness `kg_query` and
turns them into (a) a graph decoration — the TOXIC_COMBINATION node the catalogue
defines but nothing has instantiated until now — and (b) an OCSF-2005 Hypothesis
with evidence refs to the contributing findings.
"""
from __future__ import annotations

import hashlib

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase

from investigation.schemas import Hypothesis
from meta_harness.kg_query import ToxicCombination


def _combo_external_id(combo: ToxicCombination) -> str:
    raw = f"{combo.principal_id}|{combo.resource_id}|{combo.data_classification_id}"
    return "toxic:" + hashlib.sha256(raw.encode()).hexdigest()[:16]


class ToxicCombinationWriter(KnowledgeGraphWriterBase):
    """Writes the TOXIC_COMBINATION node + CONTRIBUTES_TO edges from contributors."""

    async def record(self, combo: ToxicCombination) -> str | None:
        node_id = await self.upsert_node(
            NodeCategory.TOXIC_COMBINATION,
            _combo_external_id(combo),
            {"kind": "public-data-exposure"},
        )
        for contributor in (combo.principal_id, combo.resource_id, combo.data_classification_id):
            await self.add_edge(contributor, node_id or "", EdgeType.CONTRIBUTES_TO, {})
        return node_id


def to_hypothesis(combo: ToxicCombination, *, evidence_refs: tuple[str, ...]) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=_combo_external_id(combo),
        statement=(
            "Public bucket holds sensitive data and is reachable by an "
            "over-permissioned principal (public-data-exposure attack path)."
        ),
        confidence=1.0,  # graph-evidenced (all three legs present), not LLM-inferred
        evidence_refs=evidence_refs,
    )


__all__ = ["ToxicCombinationWriter", "to_hypothesis"]
```

> If `Hypothesis`'s exact field names differ, read `packages/agents/investigation/src/investigation/schemas.py` and adjust the constructor — the failing test will tell you immediately.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest packages/agents/investigation/tests/test_toxic_combination.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/agents/investigation/src/investigation/toxic_combination.py \
        packages/agents/investigation/tests/test_toxic_combination.py
git commit -m "feat(investigation): instantiate TOXIC_COMBINATION node + build its hypothesis"
```

---

### Task 5: the end-to-end proof — full slice across three writers + detector + emit

The proof the user signed off for: seed a realistic scenario through the THREE real writers (cloud-posture, data-security, identity), run the detector, build the hypothesis + node, and assert ONE toxic combination lights up — plus the two negatives (non-public, no-access) stay dark.

**Files:**

- Create: `packages/integration/src/fleet_testkit/tests/test_toxic_combination_slice.py`

**Interfaces:**

- Consumes everything from Tasks 1-4.

- [ ] **Step 1: Write the end-to-end test**

```python
# packages/integration/src/fleet_testkit/tests/test_toxic_combination_slice.py
"""End-to-end proof: public bucket + PII + over-permissioned role → ONE toxic finding.

Drives the REAL agent writers (not hand-built edges) so the slice proves the
cross-agent wiring, not just the detector in isolation."""
import pytest
from charter.memory.graph_types import NodeCategory
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CpWriter
from data_security.canonical import s3_bucket_arn
from data_security.kg_writer import KnowledgeGraphWriter as DsWriter
from data_security.schemas import ClassifierLabel
from fleet_testkit import in_memory_semantic_store
from identity.kg_writer import KnowledgeGraphWriter as IdWriter
from investigation.toxic_combination import ToxicCombinationWriter, to_hypothesis
from meta_harness.kg_query import KgQuery


class _Acl:
    grants_all_users = True
    grants_authenticated_users = False


class _Enc:
    algorithm = "NONE"


class _Bucket:  # minimal stand-in for BucketInventory
    def __init__(self, name, public):
        self.name = name
        self.region = "us-east-1"
        self.acl = _Acl() if public else type("A", (), {"grants_all_users": False,
                                                         "grants_authenticated_users": False})()
        self.encryption = _Enc()


async def _run_slice(store, *, public, has_access):
    t = "tenant-1"
    name = "acme-pii"
    arn = s3_bucket_arn(name)
    role_arn = "arn:aws:iam::1:role/app"

    await CpWriter(store, t).upsert_asset("s3-bucket", arn, {"region": "us-east-1"})
    await DsWriter(store, t).record(
        [_Bucket(name, public)], {name: [ClassifierLabel.SSN]})
    if has_access:
        await IdWriter(store, t).record_access([(role_arn, arn)])

    role_id = await store.upsert_entity(tenant_id=t, entity_type=NodeCategory.IDENTITY.value,
                                        external_id=role_arn, properties={})
    return await KgQuery(store, t).find_public_data_exposure(
        over_permissioned_principal_ids=[role_id])


@pytest.mark.asyncio
async def test_full_slice_lights_up_one_toxic_combination():
    async with in_memory_semantic_store() as store:
        hits = await _run_slice(store, public=True, has_access=True)
        assert len(hits) == 1
        node_id = await ToxicCombinationWriter(store, "tenant-1").record(hits[0])
        assert node_id
        h = to_hypothesis(hits[0], evidence_refs=("finding:dspm-acme-pii-SSN",))
        assert h.confidence == 1.0


@pytest.mark.asyncio
async def test_full_slice_dark_when_private():
    async with in_memory_semantic_store() as store:
        assert await _run_slice(store, public=False, has_access=True) == []


@pytest.mark.asyncio
async def test_full_slice_dark_when_no_access():
    async with in_memory_semantic_store() as store:
        assert await _run_slice(store, public=True, has_access=False) == []
```

> `ClassifierLabel.SSN` and the `BucketInventory` field shape (`acl.grants_all_users`, `encryption.algorithm`) are taken from data-security's writer (kg_writer.py:42-43). If the real `ClassifierLabel` member name differs, read `data_security/schemas.py` and adjust — the test will tell you.

- [ ] **Step 2: Run it to verify it fails, then passes as you complete Tasks 1-4**

Run: `uv run pytest packages/integration/src/fleet_testkit/tests/test_toxic_combination_slice.py -v`
Expected (with Tasks 1-4 done): PASS (3 passed) — the positive lights up, both negatives stay dark.

- [ ] **Step 3: Run the three touched agents' full suites + the integration package (no regression)**

Run:

```bash
uv run pytest packages/agents/data-security packages/agents/identity \
              packages/agents/meta-harness packages/agents/investigation \
              packages/integration -q
```

Expected: all PASS, 0 failed.

- [ ] **Step 4: Commit**

```bash
git add packages/integration/src/fleet_testkit/tests/test_toxic_combination_slice.py
git commit -m "test(fleet): end-to-end proof of the public-data-exposure toxic combination"
```

---

## Self-Review

**Spec coverage:**

- Entity resolution (the bug) → Task 1. ✓
- `HAS_ACCESS_TO` edge (the missing leg) → Task 2. ✓
- Toxic-combo detector reusing existing BFS/accessor → Task 3. ✓
- `TOXIC_COMBINATION` node finally instantiated + hypothesis → Task 4. ✓
- End-to-end proof across real writers, positive + 2 negatives → Task 5. ✓
- OCSF 2005 emission into D.7's run loop → **deliberately NOT in this slice.** Task 4 produces the `Hypothesis`; folding it into `IncidentReport.to_ocsf()` and the bus-emit path is a follow-up once the detection is proven. Flagged here so it isn't mistaken for done.

**Type consistency:** `ToxicCombination` (Task 3) is consumed unchanged in Tasks 4-5. `s3_bucket_arn` (Task 1) used in Tasks 2(test)/5. `record_access(grants)` (Task 2) called in Task 5. `to_hypothesis`/`ToxicCombinationWriter.record` (Task 4) called in Task 5. Consistent.

**Open items to confirm during execution (test will surface each):**

1. `Hypothesis` field names — read `investigation/schemas.py` (Task 4).
2. `ClassifierLabel.SSN` member name + `BucketInventory` field shape — read `data_security/schemas.py` / `tools/s3_inventory.py` (Task 5).
3. `in_memory_semantic_store()` exact import path from `fleet_testkit` (it backs the L1 wiring tests — confirm the public name).

**Honest scope note:** This proves the moat _path_, single-tenant, in-memory. It does NOT wire live cloud reads, does NOT add the OCSF emit to the run loop, and is S3-only. Those are the next slices — earned only after this one is green.
