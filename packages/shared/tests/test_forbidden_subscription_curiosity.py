"""Phase D pre-flight P3-4 — D.12 Curiosity producer-only forbidden-subscription fence.

Curiosity is the PRODUCER of claims.> (it publishes claims.curiosity.>). Unlike the three
consumer-laundering subscribers (remediation, supervisor, meta_harness), curiosity is fenced to
prevent a generative feedback loop — a producer reading its OWN claims back as input would amplify
speculation. Curiosity already enforces this at the code level (assert_no_claims_subscription,
WI-X14); P3-4 adds the substrate-level belt-and-suspenders fence in shared.fabric. These tests lock
it in. NATS mocking helpers are module-local (self-contained ADR-012 conformance harness).
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
    return mocker.patch(
        "shared.fabric.client.nats.connect", new_callable=AsyncMock, return_value=nc_mock
    )


def test_curiosity_registered_in_forbidden_subscriptions() -> None:
    """P3-4: curiosity is in the forbidden-subscriber registry, pattern claims.>."""
    assert _FORBIDDEN_SUBSCRIPTIONS["curiosity"] == frozenset({"claims.>"})


@pytest.mark.asyncio
async def test_curiosity_forbidden_from_claims_subscription(mocker: MockerFixture) -> None:
    """D.12 attempting to subscribe to claims.> raises before the NATS call — the producer-only
    fence prevents the self-read generative feedback loop."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc)
    client = JetStreamClient(servers=["nats://localhost:4222"], agent_id="curiosity")
    await client.connect()

    async def _cb(msg: Any) -> None:
        return None

    with pytest.raises(ForbiddenSubscriptionError, match="curiosity"):
        await client.subscribe(CLAIMS_STREAM, "claims.tenant.acme.>", _cb, durable_name="d1")
    js.subscribe.assert_not_awaited()


@pytest.mark.asyncio
async def test_curiosity_forbidden_even_for_its_own_subject(mocker: MockerFixture) -> None:
    """Even curiosity's own published subject is blocked on the read side — wildcard match, and the
    exact path the feedback loop would take."""
    nc, _js = _make_nats_mock()
    _patch_nats_connect(mocker, nc)
    client = JetStreamClient(servers=["nats://localhost:4222"], agent_id="curiosity")
    await client.connect()

    async def _cb(msg: Any) -> None:
        return None

    with pytest.raises(ForbiddenSubscriptionError):
        await client.subscribe(
            CLAIMS_STREAM, "claims.tenant.acme.agent.curiosity", _cb, durable_name="d1"
        )


@pytest.mark.asyncio
async def test_curiosity_can_still_subscribe_to_findings_and_events(mocker: MockerFixture) -> None:
    """The fence is targeted to claims.> only — curiosity may still read findings.>/events.>."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc)
    client = JetStreamClient(servers=["nats://localhost:4222"], agent_id="curiosity")
    await client.connect()

    async def _cb(msg: Any) -> None:
        return None

    await client.subscribe(FINDINGS_STREAM, "findings.tenant.acme.>", _cb, durable_name="d_f")
    await client.subscribe(EVENTS_STREAM, "events.tenant.acme.>", _cb, durable_name="d_e")
    assert js.subscribe.await_count == 2
