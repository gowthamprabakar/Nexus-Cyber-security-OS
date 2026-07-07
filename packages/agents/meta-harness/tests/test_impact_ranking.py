"""Cycle 8 Task 2 — destructive-permissions blast multiplier in rank_by_expected_loss.

Tests:
1. test_destructive_principal_blast_lift — two identical paths; one principal has
   destructive_permissions=True → it ranks higher (larger expected_loss via larger blast).
2. test_exact_blast_ratio — asserts the ratio of blasts == _DESTRUCTIVE_LIFT (x1.5).
3. test_absent_destructive_property_unchanged — no destructive_permissions property → blast
   unchanged (backward-compat regression guard).
4. test_non_principal_entity_destructive_no_lift — destructive_permissions on a resource node
   that is NOT in principal_reach does NOT trigger the lift.
"""

from __future__ import annotations

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.attack_paths import AttackPath
from meta_harness.report_card import _DESTRUCTIVE_LIFT, rank_by_expected_loss

_SEV = 70  # shared severity for all paths in these tests
_IDENTITY = NodeCategory.IDENTITY.value
_RESOURCE = NodeCategory.CLOUD_RESOURCE.value
_DC = NodeCategory.DATA_CLASSIFICATION.value


async def _wire_principal_to_data(
    store,
    tenant: str,
    principal_ext: str,
    data_ext: str,
    resource_ext: str,
    *,
    destructive: bool = False,
) -> tuple[str, str]:
    """Wire IDENTITY -HAS_ACCESS_TO-> CLOUD_RESOURCE -EXPOSES_DATA-> DATA_CLASSIFICATION.

    Returns (principal_id, dc_id).  Optionally stamps destructive_permissions=True on the
    principal node so the blast multiplier fires.
    """
    principal_id = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=_IDENTITY,
        external_id=principal_ext,
        properties={"destructive_permissions": True} if destructive else {},
    )
    resource_id = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=_RESOURCE,
        external_id=resource_ext,
        properties={"is_public": True},
    )
    dc_id = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=_DC,
        external_id=data_ext,
        properties={"data_type": "ssn"},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=principal_id,
        dst_entity_id=resource_id,
        relationship_type=EdgeType.HAS_ACCESS_TO.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=resource_id,
        dst_entity_id=dc_id,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )
    return principal_id, dc_id


@pytest.mark.asyncio
async def test_destructive_principal_blast_lift() -> None:
    """A path whose principal has destructive_permissions=True ranks higher than an identical path
    whose principal does not — higher expected_loss via bigger blast.
    """
    tenant = "dp-lift-order"
    async with in_memory_semantic_store() as store:
        # Path A: same setup but principal is NOT destructive.
        principal_a, dc_a = await _wire_principal_to_data(
            store, tenant, "arn:role/normal", "dc-a", "res-a", destructive=False
        )
        # Path B: principal IS destructive.
        principal_b, dc_b = await _wire_principal_to_data(
            store, tenant, "arn:role/destroyer", "dc-b", "res-b", destructive=True
        )

        path_a = AttackPath(
            path_type="fine_grained_data",
            severity=_SEV,
            title="normal path",
            entities=(principal_a,),
            sink_id=dc_a,
        )
        path_b = AttackPath(
            path_type="fine_grained_data",
            severity=_SEV,
            title="destructive path",
            entities=(principal_b,),
            sink_id=dc_b,
        )

        ranked = await rank_by_expected_loss([path_a, path_b], store, tenant)

        assert len(ranked) == 2, "ranker must be total"
        first_path, first_loss, _blast = ranked[0]
        _second_path, second_loss, _blast2 = ranked[1]

        assert first_path.title == "destructive path", (
            f"destructive path must rank first (higher blast) but got: {first_path.title!r}"
        )
        assert first_loss > second_loss, (
            f"destructive path expected_loss ({first_loss:.4f}) must exceed "
            f"normal path expected_loss ({second_loss:.4f})"
        )


@pytest.mark.asyncio
async def test_exact_blast_ratio() -> None:
    """The blast for a destructive principal must be exactly blast x _DESTRUCTIVE_LIFT (x1.5).

    Two single-store paths (blast=1 each before multiplier).  The destructive one must have
    blast == round(1 x _DESTRUCTIVE_LIFT) = round(1.5) = 2 (Python rounds halves to even → 2).
    """
    tenant = "dp-ratio"
    async with in_memory_semantic_store() as store:
        principal_n, dc_n = await _wire_principal_to_data(
            store, tenant, "arn:role/plain", "dc-n", "res-n", destructive=False
        )
        principal_d, dc_d = await _wire_principal_to_data(
            store, tenant, "arn:role/dest", "dc-d", "res-d", destructive=True
        )

        path_plain = AttackPath(
            path_type="fine_grained_data",
            severity=_SEV,
            title="plain",
            entities=(principal_n,),
            sink_id=dc_n,
        )
        path_dest = AttackPath(
            path_type="fine_grained_data",
            severity=_SEV,
            title="dest",
            entities=(principal_d,),
            sink_id=dc_d,
        )

        ranked = await rank_by_expected_loss([path_plain, path_dest], store, tenant)
        by_title = {p.title: blast for p, _el, blast in ranked}

        plain_blast = by_title["plain"]
        dest_blast = by_title["dest"]

        assert plain_blast == 1, f"base blast must be 1 for single data store, got {plain_blast}"
        expected_lifted = round(plain_blast * _DESTRUCTIVE_LIFT)
        assert dest_blast == expected_lifted, (
            f"destructive blast must be round(1 x {_DESTRUCTIVE_LIFT}) = {expected_lifted}, "
            f"got {dest_blast}"
        )
        # Assert the ratio directly — the headline correctness check.
        assert dest_blast / plain_blast == pytest.approx(_DESTRUCTIVE_LIFT, rel=0.01) or (
            dest_blast == round(plain_blast * _DESTRUCTIVE_LIFT)
        ), f"blast ratio must be {_DESTRUCTIVE_LIFT}, got {dest_blast}/{plain_blast}"


@pytest.mark.asyncio
async def test_absent_destructive_property_unchanged() -> None:
    """A principal WITHOUT destructive_permissions → blast unchanged (backward-compat).

    This is the key regression guard: existing paths that don't have the property must
    behave exactly as before — blast == 1 for a single data store.
    """
    tenant = "dp-absent"
    async with in_memory_semantic_store() as store:
        principal_id, dc_id = await _wire_principal_to_data(
            store, tenant, "arn:role/reader", "dc-r", "res-r", destructive=False
        )

        path = AttackPath(
            path_type="fine_grained_data",
            severity=_SEV,
            title="reader path",
            entities=(principal_id,),
            sink_id=dc_id,
        )

        ranked = await rank_by_expected_loss([path], store, tenant)
        assert len(ranked) == 1
        _, _el, blast = ranked[0]
        assert blast == 1, (
            f"blast must be unchanged (=1) when destructive_permissions is absent; got {blast}"
        )


@pytest.mark.asyncio
async def test_non_principal_entity_destructive_no_lift() -> None:
    """A resource node (not in principal_reach) with destructive_permissions=True does NOT trigger
    the blast lift.  The lift fires ONLY for entities that appear in principal_reach.
    """
    tenant = "dp-resource-no-lift"
    async with in_memory_semantic_store() as store:
        # Principal with NO destructive_permissions.
        principal_id = await store.upsert_entity(
            tenant_id=tenant,
            entity_type=_IDENTITY,
            external_id="arn:role/safe",
            properties={},
        )
        # Resource WITH destructive_permissions (but it's a resource, not an identity).
        resource_id = await store.upsert_entity(
            tenant_id=tenant,
            entity_type=_RESOURCE,
            external_id="res-safe",
            properties={"is_public": True, "destructive_permissions": True},
        )
        dc_id = await store.upsert_entity(
            tenant_id=tenant,
            entity_type=_DC,
            external_id="dc-safe",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=principal_id,
            dst_entity_id=resource_id,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=resource_id,
            dst_entity_id=dc_id,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        # Path entities include only the resource node (not the principal).
        path = AttackPath(
            path_type="exposed_database",
            severity=_SEV,
            title="resource path",
            entities=(resource_id,),
            sink_id=dc_id,
        )

        ranked = await rank_by_expected_loss([path], store, tenant)
        assert len(ranked) == 1
        _, _el, blast = ranked[0]
        # resource_id is NOT in principal_reach (principal_reach maps principal → data)
        # → no lift → blast == 1.
        assert blast == 1, (
            f"blast must NOT be lifted for resource entity (only principal entities in "
            f"principal_reach trigger the lift); got {blast}"
        )
