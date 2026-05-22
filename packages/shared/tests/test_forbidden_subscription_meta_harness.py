"""ADR-012 v1.1 — A.4 Meta-Harness forbidden-subscription tests (Task 11).

7 tests that lock in the third forbidden subscriber added to
``packages/shared/src/shared/fabric/client.py`` by A.4 v0.2 Task 11.
Each test maps to a clause of ADR-012 §v1.1 amendment + the WI-5
carry-forward from Supervisor v0.1's verification record:

1.  ``meta_harness`` is in the ``_FORBIDDEN_SUBSCRIPTIONS`` registry.
2.  The forbidden pattern is exactly ``frozenset({"claims.>"})`` —
    matches the verbatim WI-5 text.
3.  Attempting to subscribe to ``claims.>`` raises
    ``ForbiddenSubscriptionError`` BEFORE the NATS call.
4.  Specific subjects under ``claims.>`` (e.g.
    ``claims.tenant.acme.agent.curiosity``) are equally blocked —
    pattern matching, not literal equality.
5.  The fence is targeted: ``meta_harness`` may still subscribe to
    ``findings.>`` and ``events.>`` (only ``claims.>`` is forbidden).
6.  A client constructed with a different ``agent_id`` (e.g.
    ``investigation``) is NOT blocked from ``claims.>`` — the meta-
    harness fence applies to the meta-harness agent only.
7.  Q-ARCH-1 trajectory CLOSED: the registry has exactly three
    forbidden subscribers (remediation, supervisor, meta_harness) —
    matches the v1.1 amendment's "three subscribers, no further
    additions queued for Phase 1" statement.

NATS mocking helpers are kept module-local (a tiny duplication of the
helpers in ``test_fabric_client.py``) so this file remains the
self-contained ADR-012 v1.1 conformance harness for the meta-harness
fence — easier to find in audit and easier to delete if the fence is
ever removed.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_mock import MockerFixture
from shared.fabric.client import (
    _FORBIDDEN_SUBSCRIPTIONS,
    ForbiddenSubscriptionError,
    JetStreamClient,
)
from shared.fabric.streams import CLAIMS_STREAM, EVENTS_STREAM, FINDINGS_STREAM


def _make_nats_mock() -> tuple[MagicMock, AsyncMock]:
    """Return (nc_mock, js_mock) wired up like a connected nats-py client."""
    js = MagicMock()
    js.stream_info = AsyncMock(side_effect=None)
    js.add_stream = AsyncMock()
    js.publish = AsyncMock(return_value=MagicMock(stream="x", seq=1))
    js.subscribe = AsyncMock(return_value=MagicMock(name="Subscription"))
    nc = MagicMock()
    nc.is_connected = True
    nc.jetstream = MagicMock(return_value=js)
    nc.close = AsyncMock()
    return nc, js


def _patch_nats_connect(mocker: MockerFixture, nc_mock: MagicMock) -> AsyncMock:
    """Patch ``shared.fabric.client.nats.connect`` to return ``nc_mock``."""
    return mocker.patch(
        "shared.fabric.client.nats.connect",
        new_callable=AsyncMock,
        return_value=nc_mock,
    )


def test_meta_harness_registered_in_forbidden_subscriptions() -> None:
    """ADR-012 §v1.1 forbidden-subscriber table includes A.4 Meta-Harness."""
    assert "meta_harness" in _FORBIDDEN_SUBSCRIPTIONS


def test_meta_harness_forbidden_pattern_is_claims_wildcard() -> None:
    """WI-5 carry-forward text verbatim: ``frozenset({"claims.>"})``."""
    assert _FORBIDDEN_SUBSCRIPTIONS["meta_harness"] == frozenset({"claims.>"})


@pytest.mark.asyncio
async def test_meta_harness_agent_forbidden_from_claims_subscription(
    mocker: MockerFixture,
) -> None:
    """A.4 attempting to subscribe to claims.> raises before the NATS call."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc)
    client = JetStreamClient(servers=["nats://localhost:4222"], agent_id="meta_harness")
    await client.connect()

    async def _cb(msg: Any) -> None:
        return None

    with pytest.raises(ForbiddenSubscriptionError, match="meta_harness"):
        await client.subscribe(
            CLAIMS_STREAM,
            "claims.tenant.acme.>",
            _cb,
            durable_name="d1",
        )
    js.subscribe.assert_not_awaited()


@pytest.mark.asyncio
async def test_meta_harness_forbidden_for_specific_claims_subject(
    mocker: MockerFixture,
) -> None:
    """Pattern matching is wildcard-based — specific subjects under
    claims.> (e.g. claims.tenant.acme.agent.curiosity) are equally
    blocked. Mirrors the existing A.1 / Supervisor coverage."""
    nc, _js = _make_nats_mock()
    _patch_nats_connect(mocker, nc)
    client = JetStreamClient(servers=["nats://localhost:4222"], agent_id="meta_harness")
    await client.connect()

    async def _cb(msg: Any) -> None:
        return None

    with pytest.raises(ForbiddenSubscriptionError):
        await client.subscribe(
            CLAIMS_STREAM,
            "claims.tenant.acme.agent.curiosity",
            _cb,
            durable_name="d1",
        )


@pytest.mark.asyncio
async def test_meta_harness_can_still_subscribe_to_findings_and_events(
    mocker: MockerFixture,
) -> None:
    """The fence is targeted — A.4 may freely subscribe to findings.>
    and events.>; only claims.> is forbidden. A.4 v0.2 needs findings.>
    for cross-agent eval data + events.> for lifecycle observation."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc)
    client = JetStreamClient(servers=["nats://localhost:4222"], agent_id="meta_harness")
    await client.connect()

    async def _cb(msg: Any) -> None:
        return None

    await client.subscribe(
        FINDINGS_STREAM,
        "findings.tenant.acme.>",
        _cb,
        durable_name="d_findings",
    )
    await client.subscribe(
        EVENTS_STREAM,
        "events.tenant.acme.>",
        _cb,
        durable_name="d_events",
    )
    assert js.subscribe.await_count == 2


@pytest.mark.asyncio
async def test_meta_harness_fence_does_not_block_other_agents(
    mocker: MockerFixture,
) -> None:
    """The fence applies only to clients constructed with
    ``agent_id="meta_harness"``. Other agents (e.g. investigation,
    data_security, curiosity, threat_intel) continue to subscribe to
    claims.> as normal per ADR-012 §"Non-acting consumers of claims.>"."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc)
    client = JetStreamClient(servers=["nats://localhost:4222"], agent_id="investigation")
    await client.connect()

    async def _cb(msg: Any) -> None:
        return None

    await client.subscribe(
        CLAIMS_STREAM,
        "claims.tenant.acme.>",
        _cb,
        durable_name="d1",
    )
    js.subscribe.assert_awaited_once()


def test_q_arch_1_trajectory_closed_at_three_forbidden_subscribers() -> None:
    """ADR-012 §v1.1 closure: the registry contains exactly three forbidden
    subscribers (remediation, supervisor, meta_harness). No further additions
    are queued for Phase 1; new auto-acting agents inherit the standing rule."""
    assert set(_FORBIDDEN_SUBSCRIPTIONS.keys()) == {"remediation", "supervisor", "meta_harness"}
