"""Tests for ``meta_harness.attack_path_writer.AttackPathWriter``.

Two assertions verified here:

1. **Write**: after ``persist(ranked, now=T1)``, an ``ATTACK_PATH`` node exists in the
   semantic store with the expected properties (``path_type``, ``expected_loss``,
   ``title``, ``first_seen==T1``, ``last_seen==T1``) and a ``CONTRIBUTES_TO`` edge from
   each entity in the path.

2. **Cross-scan dedup (ADR-022)**: ``persist(ranked, now=T2)`` a second time produces
   exactly ONE node (same key, no duplicate), ``first_seen`` unchanged (== T1), and
   ``last_seen`` bumped to T2.  This is the set-once / bump contract the design spec
   requires.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.attack_path_writer import AttackPathWriter, _attack_path_external_id
from meta_harness.attack_paths import AttackPath

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_T1 = datetime(2026, 7, 6, 10, 0, 0, tzinfo=UTC)
_T2 = datetime(2026, 7, 6, 11, 0, 0, tzinfo=UTC)

_TENANT = "acme"


def _make_path(
    path_type: str = "crown_jewel",
    entities: tuple[str, ...] = ("arn:role/a", "arn:bucket/b"),
    evidence: tuple[str, ...] = ("CVE-2021-1234",),
    severity: int = 95,
    title: str = "Test crown jewel",
    count: int = 1,
    sink_id: str = "",
    kev: bool = False,
    epss: float | None = None,
) -> AttackPath:
    return AttackPath(
        path_type=path_type,
        severity=severity,
        title=title,
        entities=entities,
        evidence=evidence,
        count=count,
        sink_id=sink_id,
        kev=kev,
        epss=epss,
    )


def _ranked(
    path: AttackPath, expected_loss: float = 100_000.0, blast: int = 5
) -> list[tuple[AttackPath, float, int]]:
    return [(path, expected_loss, blast)]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_persist_creates_attack_path_node() -> None:
    """persist(ranked, now=T1) writes one ATTACK_PATH node with correct properties."""
    path = _make_path()
    async with in_memory_semantic_store() as store:
        writer = AttackPathWriter(store, _TENANT)
        await writer.persist(_ranked(path), now=_T1)

        nodes = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.ATTACK_PATH.value
        )
        assert len(nodes) == 1, f"expected 1 ATTACK_PATH node, got {len(nodes)}"
        node = nodes[0]
        props = node.properties
        assert props["path_type"] == path.path_type
        assert props["title"] == path.title
        assert abs(props["expected_loss"] - 100_000.0) < 1e-6
        assert props["first_seen"] == _T1.isoformat()
        assert props["last_seen"] == _T1.isoformat()
        assert props["entities"] == list(path.entities)
        assert props["evidence"] == list(path.evidence)


@pytest.mark.asyncio
async def test_persist_creates_contributes_to_edges() -> None:
    """persist writes CONTRIBUTES_TO from each entity in the path to the ATTACK_PATH node.

    ``path.entities`` contains graph entity_ids (ULIDs), not external ARN strings —
    the ranker stores them that way (e.g. ``h.workload_id``, ``h.role_id`` etc.).
    We pre-seed two nodes, capture their ULID entity_ids, and build the path with those.
    """
    async with in_memory_semantic_store() as store:
        # Pre-seed entity nodes; capture their graph entity_ids (ULIDs).
        role_eid = await store.upsert_entity(
            tenant_id=_TENANT,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:role/x",
            properties={},
        )
        bucket_eid = await store.upsert_entity(
            tenant_id=_TENANT,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:bucket/y",
            properties={},
        )
        # Build path using the graph entity_ids, as the ranker does.
        entities = (role_eid, bucket_eid)
        path = _make_path(entities=entities)

        writer = AttackPathWriter(store, _TENANT)
        await writer.persist(_ranked(path), now=_T1)

        # Get the ATTACK_PATH node_id.
        ap_nodes = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.ATTACK_PATH.value
        )
        assert len(ap_nodes) == 1
        ap_node_id = ap_nodes[0].entity_id

        # Verify CONTRIBUTES_TO edges from each entity node.
        for src_eid in (role_eid, bucket_eid):
            rels = await store.get_relationships_from(
                tenant_id=_TENANT,
                src_entity_id=src_eid,
                edge_types=(EdgeType.CONTRIBUTES_TO.value,),
            )
            assert any(r.dst_entity_id == ap_node_id for r in rels), (
                f"expected CONTRIBUTES_TO edge from entity {src_eid!r} → ATTACK_PATH node"
            )


@pytest.mark.asyncio
async def test_cross_scan_dedup_preserves_first_seen_and_bumps_last_seen() -> None:
    """Cross-scan dedup (ADR-022): second persist → same node, first_seen unchanged, last_seen bumped."""
    path = _make_path()
    async with in_memory_semantic_store() as store:
        writer = AttackPathWriter(store, _TENANT)

        # First scan at T1.
        await writer.persist(_ranked(path), now=_T1)
        nodes_after_t1 = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.ATTACK_PATH.value
        )
        assert len(nodes_after_t1) == 1

        # Second scan at T2 — use a fresh writer instance to reset within-run edge dedup.
        writer2 = AttackPathWriter(store, _TENANT)
        await writer2.persist(_ranked(path), now=_T2)

        nodes_after_t2 = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.ATTACK_PATH.value
        )

        # Exactly ONE node — no duplicate.
        assert len(nodes_after_t2) == 1, (
            f"cross-scan dedup failed: expected 1 ATTACK_PATH node, got {len(nodes_after_t2)}"
        )

        node = nodes_after_t2[0]
        props = node.properties

        # first_seen is preserved from T1.
        assert props["first_seen"] == _T1.isoformat(), (
            f"first_seen must stay at T1={_T1.isoformat()!r}, got {props['first_seen']!r}"
        )

        # last_seen is bumped to T2.
        assert props["last_seen"] == _T2.isoformat(), (
            f"last_seen must be bumped to T2={_T2.isoformat()!r}, got {props['last_seen']!r}"
        )


@pytest.mark.asyncio
async def test_inert_when_no_store() -> None:
    """Writer with store=None is a no-op — no errors raised."""
    path = _make_path()
    writer = AttackPathWriter(None, _TENANT)  # type: ignore[arg-type]
    # Must not raise.
    await writer.persist(_ranked(path), now=_T1)


@pytest.mark.asyncio
async def test_external_id_is_deterministic() -> None:
    """Same path_type + entities always produce the same external_id (stable key contract)."""
    path1 = _make_path(entities=("b", "a"))  # different order
    path2 = _make_path(entities=("a", "b"))  # sorted → same key
    assert _attack_path_external_id(path1) == _attack_path_external_id(path2)
    assert _attack_path_external_id(path1).startswith("attackpath:")


@pytest.mark.asyncio
async def test_persist_multiple_paths() -> None:
    """persist with two distinct paths creates two separate ATTACK_PATH nodes."""
    path_a = _make_path(path_type="crown_jewel", entities=("arn:role/1",), title="Path A")
    path_b = _make_path(path_type="public_secret", entities=("arn:secret/2",), title="Path B")
    ranked = [(path_a, 100_000.0, 5), (path_b, 50_000.0, 3)]
    async with in_memory_semantic_store() as store:
        writer = AttackPathWriter(store, _TENANT)
        await writer.persist(ranked, now=_T1)

        nodes = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.ATTACK_PATH.value
        )
        assert len(nodes) == 2
        types = {n.properties["path_type"] for n in nodes}
        assert types == {"crown_jewel", "public_secret"}
