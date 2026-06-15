"""A-4 (v0.3) — effective-perms simulator wired into run().

Verifies the ``assess_effective_perms`` gate: when ON, run() drives the IAM
SimulatePrincipalPolicy simulator per principal (over CURATED_RISK_ACTIONS) and
resolves decisions into grants that refine OVERPRIVILEGE; when OFF (default), the
simulator is never called and the v0.1 attached-policy path is byte-identical.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter.contract import BudgetSpec, ExecutionContract
from identity import agent as agent_mod
from identity.agent import run
from identity.tools.aws_iam import IamUser, IdentityListing, SimulationDecision

NOW = datetime(2026, 6, 15, tzinfo=UTC)
ALICE = "arn:aws:iam::123456789012:user/alice"


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="identity",
        customer_id="cust_test",
        task="Scan identity effective perms",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=500,
            mb_written=10,
        ),
        permitted_tools=[
            "aws_iam_list_identities",
            "aws_iam_simulate_principal_policy",
            "aws_access_analyzer_findings",
        ],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _user(arn: str, name: str) -> IamUser:
    return IamUser(
        arn=arn,
        name=name,
        user_id=f"AIDA-{name.upper()}",
        create_date=NOW,
        last_used_at=NOW,
        attached_policy_arns=(),
        group_memberships=(),
    )


def _patch_listing(monkeypatch: pytest.MonkeyPatch, listing: IdentityListing) -> None:
    async def fake_list(**_: Any) -> IdentityListing:
        return listing

    monkeypatch.setattr(agent_mod, "aws_iam_list_identities", fake_list)


def _patch_simulator(
    monkeypatch: pytest.MonkeyPatch, decisions: Sequence[SimulationDecision]
) -> dict[str, int]:
    calls = {"n": 0}

    async def fake_sim(*, principal_arn: str, **_: Any) -> tuple[SimulationDecision, ...]:
        calls["n"] += 1
        return tuple(d for d in decisions if d.principal_arn == principal_arn)

    monkeypatch.setattr(agent_mod, "aws_iam_simulate_principal_policy", fake_sim)
    return calls


@pytest.mark.asyncio
async def test_assess_effective_perms_drives_simulator_overprivilege(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ON: alice has NO attached admin policy, but the simulator returns an
    allowed iam:* grant → OVERPRIVILEGE surfaces purely from the simulator."""
    _patch_listing(
        monkeypatch, IdentityListing(users=(_user(ALICE, "alice"),), roles=(), groups=())
    )
    calls = _patch_simulator(
        monkeypatch,
        [
            SimulationDecision(
                principal_arn=ALICE,
                action="iam:*",
                resource="*",
                decision="allowed",
                matched_statement_ids=("InlineAdmin",),
            )
        ],
    )

    await run(_contract(tmp_path), assess_effective_perms=True)

    assert calls["n"] == 1  # one principal simulated
    payload = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {f["finding_info"]["types"][0] for f in payload["findings"]}
    assert "overprivilege" in types


@pytest.mark.asyncio
async def test_default_off_never_calls_simulator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OFF (default): the simulator must not be invoked (attached-policy path)."""
    _patch_listing(
        monkeypatch, IdentityListing(users=(_user(ALICE, "alice"),), roles=(), groups=())
    )

    async def boom(**_: Any) -> tuple[SimulationDecision, ...]:
        raise AssertionError("simulator must not be called when assess_effective_perms=False")

    monkeypatch.setattr(agent_mod, "aws_iam_simulate_principal_policy", boom)

    report = await run(_contract(tmp_path))  # no flag → default OFF
    assert report.agent == "identity"


@pytest.mark.asyncio
async def test_assess_effective_perms_empty_listing_no_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ON with an empty listing → no principals to simulate, no calls, no crash."""
    _patch_listing(monkeypatch, IdentityListing(users=(), roles=(), groups=()))
    calls = _patch_simulator(monkeypatch, [])

    await run(_contract(tmp_path), assess_effective_perms=True)
    assert calls["n"] == 0
