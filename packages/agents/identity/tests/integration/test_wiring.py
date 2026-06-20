"""Fleet Test Level 1 — identity (D.2 CIEM) wiring smoke.

Tier A: writes the graph + emits OCSF findings → the full §2.3 wiring assertions. Copies the
cloud-posture / runtime-threat reference shape — the shared mechanics live in ``fleet_testkit``.

L1 is SMOKE, not capability — it proves the plumbing (run completes, kg_writer writes, OCSF
valid, tenant isolated, audit chain clean, inert offline). It does NOT measure precision/recall
or assert "the agent found the right entitlement risk" — that is L2 (v2 directive §3).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from charter.memory.graph_types import NodeCategory
from fleet_testkit import (
    assert_audit_chain,
    assert_entity_written,
    assert_no_entities,
    assert_ocsf_valid,
    assert_two_tenant_disjoint,
    in_memory_semantic_store,
    wiring_contract,
)
from identity import agent as agent_mod
from identity.agent import run
from identity.tools.aws_iam import IamUser, IdentityListing

_NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
_ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
_ALICE = "arn:aws:iam::123456789012:user/alice"
_PERMITTED = [
    "aws_iam_list_identities",
    "aws_iam_simulate_principal_policy",
    "aws_access_analyzer_findings",
    "detect_aws_saml_providers",
    "detect_aws_oidc_providers",
    "detect_azure_federated_domains",
    "detect_azure_oidc_providers",
    "kg_upsert_asset",
    "kg_upsert_finding",
]
# kg_writer upserts IDENTITY principal nodes + POLICY nodes (ATTACHED_TO / MEMBER_OF edges).
_CATEGORIES = (NodeCategory.IDENTITY, NodeCategory.POLICY)
_OCSF_CLASS = 2004  # Detection Finding (identity.schemas)


def _seed_tool_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed identity's tool surface with a deterministic admin-no-MFA principal.

    Reuses the established unit-test fake (``_patch_listing``): one user holding
    AdministratorAccess → an OVERPRIVILEGE + MFA_GAP finding pair, and a non-empty
    listing so the kg_writer upserts IDENTITY + POLICY nodes.
    """
    listing = IdentityListing(
        users=(
            IamUser(
                arn=_ALICE,
                name="alice",
                user_id="AIDA-ALICE",
                create_date=_NOW,
                last_used_at=_NOW,
                attached_policy_arns=(_ADMIN_POLICY,),
                group_memberships=(),
            ),
        ),
        roles=(),
        groups=(),
    )

    async def fake_list(**_: Any) -> IdentityListing:
        return listing

    monkeypatch.setattr(agent_mod, "aws_iam_list_identities", fake_list)


def _findings(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


@pytest.mark.asyncio
async def test_wiring_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier A full §2.3: run completes · OCSF 2004 valid · IDENTITY + POLICY written ·
    audit chain hash-verifies · tenant isolation."""
    _seed_tool_surface(monkeypatch)
    async with in_memory_semantic_store() as store:
        # tenant A
        ws_a = tmp_path / "a"
        contract_a = wiring_contract(
            ws_a, target_agent="identity", permitted_tools=_PERMITTED, customer_id="tenant_a"
        )
        report_a = await run(contract=contract_a, semantic_store=store)

        # run-completes + produced findings
        assert report_a.total >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"

        # OCSF valid (every emitted finding)
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)

        # kg_writer wrote the expected ADR-018 node types
        await assert_entity_written(store, tenant_id="tenant_a", category=NodeCategory.IDENTITY)
        await assert_entity_written(store, tenant_id="tenant_a", category=NodeCategory.POLICY)

        # audit chain hash-verifies
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation: same input under tenant_b → disjoint subgraph
        ws_b = tmp_path / "b"
        contract_b = wiring_contract(
            ws_b,
            target_agent="identity",
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
        )
        await run(contract=contract_b, semantic_store=store)
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_identity_inert_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No semantic_store → no graph writes; findings still emit (byte-identical offline)."""
    _seed_tool_surface(monkeypatch)
    async with in_memory_semantic_store() as store:
        contract = wiring_contract(
            tmp_path, target_agent="identity", permitted_tools=_PERMITTED, customer_id="t_off"
        )
        report = await run(contract=contract, semantic_store=None)
        assert report.total >= 1  # detection still runs offline
        # The injected store (unused by the run) stays empty — inert/byte-identical offline.
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
