"""Fleet Test Level 1 — cloud-posture (F.3) wiring smoke (reference harness).

Tier A: writes the graph + emits OCSF findings → the full §2.3 wiring assertions. This is one
of the two reference harnesses (with runtime-threat) that lock the L1 pattern; the other 18
agents' `test_wiring.py` copy this shape.

L1 is SMOKE, not capability — it proves the plumbing (run completes, kg_writer writes, OCSF
valid, tenant isolated, audit chain clean, inert offline). It does NOT measure precision/recall
or assert "the agent found the right violation" — that is L2 (v2 directive §3).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from charter.memory.graph_types import NodeCategory
from cloud_posture.agent import run
from fleet_testkit import (
    assert_audit_chain,
    assert_entity_written,
    assert_no_entities,
    assert_ocsf_valid,
    assert_two_tenant_disjoint,
    in_memory_semantic_store,
    wiring_contract,
)

_PERMITTED = [
    "prowler_scan",
    "aws_s3_list_buckets",
    "aws_s3_describe",
    "aws_iam_list_users_without_mfa",
    "aws_iam_list_admin_policies",
    "kg_upsert_asset",
    "kg_upsert_finding",
]
_CATEGORIES = (NodeCategory.CLOUD_RESOURCE, NodeCategory.MISCONFIGURATION_FINDING)
_OCSF_CLASS = 2003  # Compliance Finding (cloud_posture.schemas)


def _seed_tool_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed cloud-posture's tool surface with a realistic, deterministic finding set.

    Reuses the established unit-test fakes (the live-lane fakes mirror real Prowler/boto
    response shapes, swiss-bar #3): one IAM-no-MFA + one public-S3 Prowler finding, plus an
    admin-policy + no-MFA user from the boto wrappers.
    """
    from cloud_posture.tools import aws_iam, aws_s3, prowler

    async def fake_run_prowler_aws(**_kwargs: Any) -> prowler.ProwlerResult:
        return prowler.ProwlerResult(
            raw_findings=[
                {
                    "CheckID": "iam_user_no_mfa",
                    "Severity": "high",
                    "Status": "FAIL",
                    "ResourceArn": "arn:aws:iam::111122223333:user/bob",
                    "ResourceType": "AwsIamUser",
                    "Region": "us-east-1",
                    "AccountId": "111122223333",
                    "StatusExtended": "User bob has no MFA",
                },
                {
                    "CheckID": "s3_bucket_public_access",
                    "Severity": "high",
                    "Status": "FAIL",
                    "ResourceArn": "arn:aws:s3:::acme-public",
                    "ResourceType": "AwsS3Bucket",
                    "Region": "us-east-1",
                    "AccountId": "111122223333",
                    "StatusExtended": "Bucket has public ACL grant",
                },
            ]
        )

    monkeypatch.setattr(prowler, "run_prowler_aws", fake_run_prowler_aws)
    monkeypatch.setattr(aws_s3, "list_buckets", AsyncMock(return_value=[]))
    monkeypatch.setattr(aws_iam, "list_users_without_mfa", AsyncMock(return_value=["bob"]))
    monkeypatch.setattr(
        aws_iam,
        "list_admin_policies",
        AsyncMock(
            return_value=[
                {
                    "policy_name": "TooBroad",
                    "policy_arn": "arn:aws:iam::111122223333:policy/TooBroad",
                    "document": {
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                    },
                }
            ]
        ),
    )


def _findings(workspace: Path) -> list[dict[str, Any]]:
    import json

    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


@pytest.mark.asyncio
async def test_wiring_cloud_posture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier A full §2.3: run completes · OCSF 2003 valid · CLOUD_RESOURCE +
    MISCONFIGURATION_FINDING written · audit chain hash-verifies · tenant isolation."""
    _seed_tool_surface(monkeypatch)
    async with in_memory_semantic_store() as store:
        # tenant A
        ws_a = tmp_path / "a"
        contract_a = wiring_contract(
            ws_a, target_agent="cloud_posture", permitted_tools=_PERMITTED, customer_id="tenant_a"
        )
        report_a = await run(contract=contract_a, semantic_store=store, regions=["us-east-1"])

        # run-completes + produced findings
        assert report_a.total >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"

        # OCSF valid (every emitted finding)
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)

        # kg_writer wrote the expected ADR-018 node types
        await assert_entity_written(
            store, tenant_id="tenant_a", category=NodeCategory.CLOUD_RESOURCE
        )
        await assert_entity_written(
            store, tenant_id="tenant_a", category=NodeCategory.MISCONFIGURATION_FINDING
        )

        # audit chain hash-verifies
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation: same input under tenant_b → disjoint subgraph
        ws_b = tmp_path / "b"
        contract_b = wiring_contract(
            ws_b,
            target_agent="cloud_posture",
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
        )
        await run(contract=contract_b, semantic_store=store, regions=["us-east-1"])
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_cloud_posture_inert_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live-lane gate default-off (no semantic_store) → no graph writes; findings still emit."""
    _seed_tool_surface(monkeypatch)
    async with in_memory_semantic_store() as store:
        contract = wiring_contract(
            tmp_path, target_agent="cloud_posture", permitted_tools=_PERMITTED, customer_id="t_off"
        )
        report = await run(contract=contract, semantic_store=None, regions=["us-east-1"])
        assert report.total >= 1  # detection still runs offline
        # The injected store (unused by the run) stays empty — inert/byte-identical offline.
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
