"""Phase C SS3 — supervisor invariants are load-bearing on the dispatch path.

Cycle 12 defined ``assert_no_peer_to_peer`` (WI-O8/H2) and ``assert_signed_contract``
(WI-O9) but never invoked them from ``run()``. These tests prove the Phase C wiring: every
dispatched ``DelegationContract`` passes BOTH guards before it leaves the supervisor — the
source is always the supervisor (no peer-to-peer), and the contract is signed + verified
(HMAC tamper-evidence). Spy-style: monkeypatch the names as bound in ``supervisor.agent`` and
assert what ``run()`` calls.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import supervisor.agent as agent_mod
from supervisor.agent import run as agent_run
from supervisor.contract_signing import UnsignedContractError, sign_delegation
from supervisor.hierarchy import SUPERVISOR_AGENT_ID, PeerToPeerViolationError
from supervisor.schemas import IncomingTask, RoutingRule, TriggerSource

_NOW = datetime(2026, 6, 13, 12, 0, tzinfo=UTC)


def _rule(rule_id: str = "r1", target: str = "cloud_posture") -> RoutingRule:
    return RoutingRule(
        rule_id=rule_id,
        target_agent=target,
        target_agent_declared=target,
        permitted_tools=("prowler_scan",),
        priority=10,
    )


def _task(target_agent: str = "cloud_posture") -> IncomingTask:
    return IncomingTask(
        task_id="t1",
        customer_id="acme",
        trigger_source=TriggerSource.OPERATOR_CLI,
        target_agent=target_agent,
        received_at=_NOW,
    )


@pytest.mark.asyncio
async def test_run_invokes_both_guards_per_dispatched_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() calls assert_no_peer_to_peer + assert_signed_contract for the dispatched contract."""
    p2p_calls: list[tuple[str, str]] = []
    sign_calls: list[str] = []

    real_p2p = agent_mod.assert_no_peer_to_peer
    real_sign = agent_mod.assert_signed_contract

    def spy_p2p(source: str, target: str) -> None:
        p2p_calls.append((source, target))
        real_p2p(source, target)

    def spy_sign(signed: object, *, secret: bytes) -> None:
        sign_calls.append(signed.contract.target_agent)  # type: ignore[attr-defined]
        real_sign(signed, secret=secret)  # type: ignore[arg-type]

    monkeypatch.setattr(agent_mod, "assert_no_peer_to_peer", spy_p2p)
    monkeypatch.setattr(agent_mod, "assert_signed_contract", spy_sign)

    report = await agent_run(
        customer_id="acme",
        workspace_root=tmp_path,
        routing_rules=[_rule()],
        triggers=[_task()],
    )

    assert report.total_delegations == 1
    # Hierarchy guard: source is always the supervisor; target is the routed agent.
    assert p2p_calls == [(SUPERVISOR_AGENT_ID, "cloud_posture")]
    # Signature guard ran for the same dispatched contract.
    assert sign_calls == ["cloud_posture"]


@pytest.mark.asyncio
async def test_no_match_dispatches_nothing_so_no_guard_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-matching trigger builds no contract, so neither guard fires (escalation only)."""
    p2p_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        agent_mod,
        "assert_no_peer_to_peer",
        lambda s, t: p2p_calls.append((s, t)),
    )

    report = await agent_run(
        customer_id="acme",
        workspace_root=tmp_path,
        routing_rules=[_rule()],
        triggers=[_task(target_agent="ghost")],
    )

    assert report.total_delegations == 0
    assert report.total_escalations == 1
    assert p2p_calls == []


@pytest.mark.asyncio
async def test_signature_is_valid_under_the_run_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The signature run() passes the guard is genuinely valid (not an empty/forged stub)."""
    secret = b"fixed-test-secret-key-32-bytes!!"
    verified: list[bool] = []

    def spy_sign(signed: object, *, secret: bytes) -> None:
        # Recompute the canonical signature and confirm it matches the one run() attached.
        expected = sign_delegation(signed.contract, secret=secret)  # type: ignore[attr-defined]
        verified.append(signed.signature == expected.signature)  # type: ignore[attr-defined]

    monkeypatch.setattr(agent_mod, "assert_signed_contract", spy_sign)

    await agent_run(
        customer_id="acme",
        workspace_root=tmp_path,
        routing_rules=[_rule()],
        triggers=[_task()],
        signing_secret=secret,
    )

    assert verified == [True]


def test_guards_reject_violations() -> None:
    """Sanity: the wired guards actually reject a peer-to-peer source + an unsigned contract."""
    with pytest.raises(PeerToPeerViolationError):
        agent_mod.assert_no_peer_to_peer("vulnerability", "remediation")

    from supervisor.contract_signing import SignedDelegation
    from supervisor.schemas import DelegationContract

    unsigned = SignedDelegation(
        contract=DelegationContract(
            delegation_id="d1",
            task_id="t1",
            customer_id="acme",
            target_agent="cloud_posture",
            permitted_tools=("prowler_scan",),
            budget_wall_clock_sec=30.0,
            budget_max_tool_calls=50,
            created_at=_NOW,
        ),
        signature="",
    )
    with pytest.raises(UnsignedContractError):
        agent_mod.assert_signed_contract(unsigned, secret=b"k")
