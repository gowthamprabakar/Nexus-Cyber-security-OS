"""KG integration — ECS env extraction + STORES_SECRET edge (Task 10).

Security constraint tests (non-negotiable):
- AWS access key IDs (AKIA/ASIA) are written as cleartext convergence keys.
- All other credential material must NOT appear as plaintext in the graph;
  stored_secret_grants already fingerprints it — our job here is to confirm
  that non-AKIA env values never produce a STORES_SECRET edge at all
  (the classifier ignores them, so no plaintext bleeds through).
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
from cloud_posture.tools.aws_ecs import EcsWorkload

# Assembled so push-protection doesn't flag a literal key.
_AKIA_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_ECS_ARN = "arn:aws:ecs:us-east-1:111122223333:service/cluster/secret-svc"

# A plausible-looking non-AWS credential token (no AKIA/ASIA prefix) — test fixture only.
_NON_AWS_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH"  # noqa: S105


# ----------------------------- helpers ---------------------------------------


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_stored_secret_test",
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
    """SemanticStore stand-in that records nodes and typed relationships.

    Captures ``(src_entity_id, dst_entity_id, relationship_type)`` so tests
    can assert specific edge types were written (e.g. STORES_SECRET).
    """

    def __init__(self) -> None:
        self._entity_ids: dict[tuple[str, str], str] = {}
        self._properties: dict[tuple[str, str], dict[str, Any]] = {}
        self._relationships: list[tuple[str, str, str]] = []

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
        del tenant_id, properties
        self._relationships.append((src_entity_id, dst_entity_id, relationship_type))
        return len(self._relationships)

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

    def has_edge(self, *, relationship_type: str) -> bool:
        """True if any relationship of the given type was recorded."""
        return any(rel_type == relationship_type for _, _, rel_type in self._relationships)

    def secret_external_ids(self) -> list[str]:
        """Return external_ids of all SECRET-category nodes written."""
        return [ext_id for (etype, ext_id) in self._entity_ids if etype == "secret"]


# ----------------------------- tests -----------------------------------------


@pytest.mark.asyncio
async def test_ecs_akia_env_writes_stores_secret_edge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EcsWorkload with AKIA key in env_values → CLOUD_RESOURCE --STORES_SECRET--> SECRET."""
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)
    store = _FakeStore()

    ecs_wl = EcsWorkload(
        service_arn=_ECS_ARN,
        image_ref="111122223333.dkr.ecr.us-east-1.amazonaws.com/web:latest",
        is_public=False,
        task_role_arn="",
        env_values=(_AKIA_KEY,),
    )

    await run(
        contract=contract,
        semantic_store=cast(SemanticStore, store),
        ecs_workloads=[ecs_wl],
    )

    # A STORES_SECRET edge must have been written.
    assert store.has_edge(relationship_type="STORES_SECRET"), (
        "Expected a STORES_SECRET edge for the ECS workload carrying an AKIA key"
    )

    # The SECRET node must be keyed by the access key ID (cleartext — the approved
    # non-secret identifier, not the secret access key itself).
    secret_ids = store.secret_external_ids()
    assert _AKIA_KEY in secret_ids, (
        f"SECRET node must be keyed by the AKIA key id {_AKIA_KEY!r}; got {secret_ids}"
    )


@pytest.mark.asyncio
async def test_non_aws_token_produces_no_stores_secret_edge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Non-AKIA credential in env_values → no STORES_SECRET edge (fingerprinted, not persisted).

    Security constraint: stored_secret_grants only extracts AKIA/ASIA keys.
    A non-AWS credential (e.g. a GitHub PAT, a random token) must NOT produce
    a STORES_SECRET edge — the classifier ignores it, so no raw credential
    material leaks into the graph.
    """
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)
    store = _FakeStore()

    ecs_wl = EcsWorkload(
        service_arn=_ECS_ARN,
        image_ref="111122223333.dkr.ecr.us-east-1.amazonaws.com/web:latest",
        is_public=False,
        task_role_arn="",
        env_values=(_NON_AWS_TOKEN,),
    )

    await run(
        contract=contract,
        semantic_store=cast(SemanticStore, store),
        ecs_workloads=[ecs_wl],
    )

    # No STORES_SECRET edge — the token is not an AKIA/ASIA key.
    assert not store.has_edge(relationship_type="STORES_SECRET"), (
        "Non-AKIA env value must not produce a STORES_SECRET edge"
    )

    # The raw token must NOT appear as any node's external_id (plaintext constraint).
    all_ext_ids = [ext_id for (_, ext_id) in store._entity_ids]
    assert _NON_AWS_TOKEN not in all_ext_ids, (
        f"Non-AWS token {_NON_AWS_TOKEN!r} must not appear in plaintext as a graph node"
    )


@pytest.mark.asyncio
async def test_ecs_without_env_values_writes_no_stores_secret_edge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EcsWorkload with no env_values (default) → no STORES_SECRET edge."""
    contract = _contract(tmp_path)
    _patch_tools(monkeypatch)
    store = _FakeStore()

    ecs_wl = EcsWorkload(
        service_arn=_ECS_ARN,
        image_ref="111122223333.dkr.ecr.us-east-1.amazonaws.com/web:latest",
        is_public=False,
        task_role_arn="",
        # env_values not provided → default empty tuple
    )

    await run(
        contract=contract,
        semantic_store=cast(SemanticStore, store),
        ecs_workloads=[ecs_wl],
    )

    assert not store.has_edge(relationship_type="STORES_SECRET")
