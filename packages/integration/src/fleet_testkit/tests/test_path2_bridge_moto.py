"""Path 2 slice 2b — RUNS_IMAGE bridge + internet-exposure (moto ECS, REAL).

Proves the mechanism-② bridge REAL through cloud-posture's own code: a moto ECS service
running ``myreg/app:1.0`` with a real ``0.0.0.0/0`` security group + public IP is read by
the *real* ``read_ecs_workloads`` (exposure derived from the real SG ingress), and the
*real* ``record_workloads`` writes the workload ``CLOUD_RESOURCE{is_public}`` node +
``RUNS_IMAGE`` → image node. No fixtures, no fake ECS. moto is in-process → unskipped CI.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.moto_aws import (
    drive_cloud_workloads,
    moto_ecs_clients,
    setup_ecs_workload,
)

_TENANT = "tenant-path2b"
_IMAGE_REF = "myreg/app:1.0"


async def _nodes_by_external_id(store):
    rows = await store.list_entities_by_type(
        tenant_id=_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value
    )
    return {r.external_id: r for r in rows}


@pytest.mark.asyncio
async def test_public_ecs_service_writes_exposed_workload_and_runs_image_edge() -> None:
    async with in_memory_semantic_store() as store:
        with moto_ecs_clients() as (ecs, ec2):
            svc_arn = setup_ecs_workload(ecs, ec2, image_ref=_IMAGE_REF, public=True)
            workloads = await drive_cloud_workloads(
                store, tenant_id=_TENANT, ecs_client=ecs, ec2_client=ec2
            )

        assert len(workloads) == 1
        assert workloads[0].image_ref == _IMAGE_REF
        assert workloads[0].is_public is True

        nodes = await _nodes_by_external_id(store)
        svc = nodes[svc_arn]
        assert svc.properties.get("is_public") is True
        assert svc.properties.get("kind") == "ecs-service"

        # RUNS_IMAGE bridge: workload → image node (keyed by the image ref).
        edges = await store.get_relationships_from(
            tenant_id=_TENANT,
            src_entity_id=svc.entity_id,
            edge_types=(EdgeType.RUNS_IMAGE.value,),
        )
        assert len(edges) == 1
        assert edges[0].dst_entity_id == nodes[_IMAGE_REF].entity_id


@pytest.mark.asyncio
async def test_private_ecs_service_is_not_public() -> None:
    # Closed SG + no public IP → workload written but is_public=False (no exposure leg).
    async with in_memory_semantic_store() as store:
        with moto_ecs_clients() as (ecs, ec2):
            svc_arn = setup_ecs_workload(ecs, ec2, image_ref=_IMAGE_REF, public=False)
            workloads = await drive_cloud_workloads(
                store, tenant_id=_TENANT, ecs_client=ecs, ec2_client=ec2
            )

        assert workloads[0].is_public is False
        nodes = await _nodes_by_external_id(store)
        assert nodes[svc_arn].properties.get("is_public") is False
        # The bridge edge still exists — exposure is a property, not the edge.
        edges = await store.get_relationships_from(
            tenant_id=_TENANT,
            src_entity_id=nodes[svc_arn].entity_id,
            edge_types=(EdgeType.RUNS_IMAGE.value,),
        )
        assert len(edges) == 1
