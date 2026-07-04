"""Unit tests — EC2/ECS topology written into the KG via run() injectable seam.

Task 9 of the operating-path wiring cycle.

The run() injectable seam mirrors identity's iam_listing pattern (NEX-004a):
when ec2_workloads / ecs_workloads are provided, run() writes them directly
to the KG without calling live AWS readers.

Tests assert:
1. An injected Ec2Workload lands as a CLOUD_RESOURCE node with is_public +
   private_ips + iac_artifact properties.
2. An injected EcsWorkload lands as a CLOUD_RESOURCE node with is_public +
   a RUNS_IMAGE edge to the image node.
3. When both params are omitted AND no live clients are present, no topology
   nodes are written (unchanged behavior — offline eval stays byte-identical).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory import SemanticStore
from cloud_posture.agent import run
from cloud_posture.tools.aws_ec2 import Ec2Workload
from cloud_posture.tools.aws_ecs import EcsWorkload

# ----------------------------- fixtures --------------------------------------


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_topology_test",
        task="Scan AWS account 111122223333 us-east-1 for posture issues",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=500,
            mb_written=10,
        ),
        permitted_tools=[
            "prowler_scan",
            "aws_s3_list_buckets",
            "aws_s3_describe",
            "aws_iam_list_users_without_mfa",
            "aws_iam_list_admin_policies",
            "kg_upsert_asset",
            "kg_upsert_finding",
        ],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _patch_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace external tool wrappers with deterministic no-op stubs."""
    from cloud_posture.tools import aws_iam, prowler

    async def fake_run_prowler_aws(**_kwargs: Any) -> prowler.ProwlerResult:
        return prowler.ProwlerResult(raw_findings=[])

    monkeypatch.setattr(prowler, "run_prowler_aws", fake_run_prowler_aws)
    monkeypatch.setattr(aws_iam, "list_users_without_mfa", AsyncMock(return_value=[]))
    monkeypatch.setattr(aws_iam, "list_admin_policies", AsyncMock(return_value=[]))


class _FakeStore:
    """Minimal SemanticStore stand-in that records upsert_entity calls.

    Returns deterministic entity_ids memoized by (entity_type, external_id).
    Stores the last-seen properties per (entity_type, external_id) so tests
    can assert what properties were written. Supports list_entities_by_type
    to verify CLOUD_RESOURCE nodes.
    """

    def __init__(self) -> None:
        self._entity_ids: dict[tuple[str, str], str] = {}
        self._properties: dict[tuple[str, str], dict[str, Any]] = {}
        self._rel_counter = 0

    async def upsert_entity(
        self,
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str:
        del tenant_id
        key = (entity_type, external_id)
        if key not in self._entity_ids:
            self._entity_ids[key] = f"ent_{entity_type}_{len(self._entity_ids)}"
        # Merge in the latest properties (reflecting real upsert semantics).
        if properties:
            self._properties.setdefault(key, {}).update(properties)
        return self._entity_ids[key]

    async def add_relationship(
        self,
        *,
        tenant_id: str,
        src_entity_id: str,
        dst_entity_id: str,
        relationship_type: str,
        properties: dict[str, Any] | None = None,
    ) -> int:
        del tenant_id, src_entity_id, dst_entity_id, relationship_type, properties
        self._rel_counter += 1
        return self._rel_counter

    async def list_entities_by_type(self, *, tenant_id: str, entity_type: str) -> list[Any]:
        del tenant_id
        results = []
        for (etype, ext_id), entity_id in self._entity_ids.items():
            if etype == entity_type:
                props = self._properties.get((etype, ext_id), {})

                class _FakeEntity:
                    pass

                e = _FakeEntity()
                e.external_id = ext_id  # type: ignore[attr-defined]
                e.entity_id = entity_id  # type: ignore[attr-defined]
                e.properties = props  # type: ignore[attr-defined]
                results.append(e)
        return results

    def get_properties(self, entity_type: str, external_id: str) -> dict[str, Any]:
        """Helper: return the stored properties for a node (empty dict if absent)."""
        return dict(self._properties.get((entity_type, external_id), {}))


def _make_store() -> _FakeStore:
    return _FakeStore()


# ----------------------------- EC2 topology ----------------------------------


@pytest.mark.asyncio
async def test_run_writes_ec2_workload_cloud_resource_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Injected Ec2Workload lands as CLOUD_RESOURCE with is_public + private_ips."""
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)
    store = _make_store()

    ec2_wl = Ec2Workload(
        instance_arn="arn:aws:ec2:us-east-1:111122223333:instance/i-0abc123",
        is_public=True,
        private_ips=("10.0.0.5", "10.0.1.7"),
        iac_artifact="my-repo:infra/ec2.tf",
        role_arn="",
    )

    await run(
        contract=contract,
        semantic_store=cast(SemanticStore, store),
        ec2_workloads=[ec2_wl],
    )

    # The EC2 instance must be written as a CLOUD_RESOURCE node.
    cloud_resources = await store.list_entities_by_type(
        tenant_id="cust_topology_test", entity_type="cloud_resource"
    )
    arns = [r.external_id for r in cloud_resources]
    assert "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc123" in arns

    # Properties: is_public + private_ips must be stored.
    props = store.get_properties(
        "cloud_resource", "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc123"
    )
    assert props.get("is_public") is True
    assert "10.0.0.5" in props.get("private_ips", [])


@pytest.mark.asyncio
async def test_run_writes_ec2_iac_artifact_property(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Injected Ec2Workload with iac_artifact carries the provenance property."""
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)
    store = _make_store()

    ec2_wl = Ec2Workload(
        instance_arn="arn:aws:ec2:us-east-1:111122223333:instance/i-iac001",
        is_public=False,
        private_ips=("10.0.2.1",),
        iac_artifact="nexus-infra:modules/app.tf",
        role_arn="",
    )

    await run(
        contract=contract,
        semantic_store=cast(SemanticStore, store),
        ec2_workloads=[ec2_wl],
    )

    props = store.get_properties(
        "cloud_resource", "arn:aws:ec2:us-east-1:111122223333:instance/i-iac001"
    )
    assert props.get("iac_artifact") == "nexus-infra:modules/app.tf"


# ----------------------------- ECS topology ----------------------------------


@pytest.mark.asyncio
async def test_run_writes_ecs_workload_cloud_resource_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Injected EcsWorkload lands as CLOUD_RESOURCE with is_public."""
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)
    store = _make_store()

    ecs_wl = EcsWorkload(
        service_arn="arn:aws:ecs:us-east-1:111122223333:service/cluster/web-svc",
        image_ref="111122223333.dkr.ecr.us-east-1.amazonaws.com/web:latest",
        is_public=True,
        task_role_arn="",
    )

    await run(
        contract=contract,
        semantic_store=cast(SemanticStore, store),
        ecs_workloads=[ecs_wl],
    )

    cloud_resources = await store.list_entities_by_type(
        tenant_id="cust_topology_test", entity_type="cloud_resource"
    )
    arns = [r.external_id for r in cloud_resources]
    assert "arn:aws:ecs:us-east-1:111122223333:service/cluster/web-svc" in arns

    props = store.get_properties(
        "cloud_resource",
        "arn:aws:ecs:us-east-1:111122223333:service/cluster/web-svc",
    )
    assert props.get("is_public") is True


@pytest.mark.asyncio
async def test_run_writes_runs_image_edge_for_ecs_workload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Injected EcsWorkload creates a RUNS_IMAGE edge + container-image node."""
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)
    store = _make_store()

    image = "111122223333.dkr.ecr.us-east-1.amazonaws.com/api:sha-abc"
    ecs_wl = EcsWorkload(
        service_arn="arn:aws:ecs:us-east-1:111122223333:service/cluster/api-svc",
        image_ref=image,
        is_public=False,
        task_role_arn="",
    )

    await run(
        contract=contract,
        semantic_store=cast(SemanticStore, store),
        ecs_workloads=[ecs_wl],
    )

    cloud_resources = await store.list_entities_by_type(
        tenant_id="cust_topology_test", entity_type="cloud_resource"
    )
    arns = [r.external_id for r in cloud_resources]
    # The image node must also land.
    assert image in arns
    # At least one RUNS_IMAGE relationship must have been written.
    assert store._rel_counter >= 1


# ----------------------------- unchanged behavior ----------------------------


@pytest.mark.asyncio
async def test_run_without_workloads_writes_no_topology_nodes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When no workloads are injected and no live clients, topology is unchanged.

    The existing offline eval suite must stay byte-identical — no new
    CLOUD_RESOURCE nodes should appear unless workloads are explicitly provided.
    """
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)
    store = _make_store()

    await run(
        contract=contract,
        semantic_store=cast(SemanticStore, store),
        # No ec2_workloads / ecs_workloads → topology path skipped.
    )

    cloud_resources = await store.list_entities_by_type(
        tenant_id="cust_topology_test", entity_type="cloud_resource"
    )
    # Only Prowler-findings-derived CLOUD_RESOURCE nodes should exist.
    # With zero prowler findings (our stub), the list must be empty.
    assert cloud_resources == []
