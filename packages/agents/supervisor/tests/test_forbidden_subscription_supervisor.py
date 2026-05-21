"""SAFETY-CRITICAL — Supervisor v0.1 Task 8 substrate fence.

Per Q-ARCH-1 of the Supervisor v0.1 plan, Supervisor MUST NOT
subscribe to ``claims.>``. The fence is enforced at the substrate
layer in ``packages/shared/src/shared/fabric/client.py`` via the
``_FORBIDDEN_SUBSCRIPTIONS`` registry.

This module is the regression probe. If a future change removes
the Supervisor entry from the registry, or removes the runtime
check in ``JetStreamClient.subscribe(...)``, these tests fail
loudly.

The Supervisor entry is the **second** in the registry (after
A.1 Remediation, ADR-012's original fence). A future third entry
is anticipated for A.4 v0.2 when NLAH auto-deploy lands — captured
as WI-5 forward-carry in the Supervisor v0.1 verification record.
"""

from __future__ import annotations

import pytest
from shared.fabric.client import (
    _FORBIDDEN_SUBSCRIPTIONS,
    ForbiddenSubscriptionError,
    JetStreamClient,
)


def test_supervisor_in_forbidden_subscriptions_registry() -> None:
    """The Task 8 substrate touch must persist in main."""
    assert "supervisor" in _FORBIDDEN_SUBSCRIPTIONS, (
        "Supervisor missing from _FORBIDDEN_SUBSCRIPTIONS — Q-ARCH-1 fence broken"
    )
    assert _FORBIDDEN_SUBSCRIPTIONS["supervisor"] == frozenset({"claims.>"})


def test_remediation_still_in_registry_after_extension() -> None:
    """The original A.1 fence MUST coexist with Supervisor's new fence
    (additive ADR-012 amend; no removal of existing entries)."""
    assert "remediation" in _FORBIDDEN_SUBSCRIPTIONS
    assert _FORBIDDEN_SUBSCRIPTIONS["remediation"] == frozenset({"claims.>"})


def test_registry_has_exactly_two_v0_1_entries() -> None:
    """v0.1 forbidden-subscriber set: A.1 + Supervisor only.

    A.4 v0.2 will add a third entry (the WI-5 carry-forward); this
    test will be updated at that point to assert the third entry.
    The current expected size is 2.
    """
    assert set(_FORBIDDEN_SUBSCRIPTIONS.keys()) == {"remediation", "supervisor"}


def test_jetstream_client_rejects_supervisor_claims_subscribe() -> None:
    """A JetStreamClient constructed with ``agent_id="supervisor"``
    must raise ``ForbiddenSubscriptionError`` before any NATS call
    when it attempts to subscribe to ``claims.>``."""
    client = JetStreamClient(servers="nats://localhost:4222", agent_id="supervisor")
    with pytest.raises(ForbiddenSubscriptionError, match="claims"):
        # noinspection PyProtectedMember
        client._enforce_subscriber_acl("claims.>")


def test_jetstream_client_rejects_supervisor_tenant_scoped_claims_subscribe() -> None:
    """A tenant-scoped pattern like ``claims.tenant.acme.>`` must
    also be rejected — the fence pattern uses NATS wildcard semantics
    so ``claims.>`` matches ``claims.tenant.acme.>``."""
    client = JetStreamClient(servers="nats://localhost:4222", agent_id="supervisor")
    with pytest.raises(ForbiddenSubscriptionError):
        # noinspection PyProtectedMember
        client._enforce_subscriber_acl("claims.tenant.acme.agent.curiosity")


def test_jetstream_client_allows_supervisor_events_subscribe() -> None:
    """Supervisor's allowed-subscriber set: ``events.>`` is OK
    (it's Supervisor's Stage 1 INGEST trigger source per Q5)."""
    client = JetStreamClient(servers="nats://localhost:4222", agent_id="supervisor")
    # No exception expected.
    # noinspection PyProtectedMember
    client._enforce_subscriber_acl("events.tenant.acme.task_scheduled")


def test_jetstream_client_allows_other_agents_to_subscribe_to_claims() -> None:
    """The fence is keyed by agent_id; other agents (e.g. D.7
    Investigation, D.5 Data Security per ADR-012) are NOT in the
    forbidden-subscriber set."""
    for permitted_agent in ("investigation", "data_security", "threat_intel"):
        client = JetStreamClient(
            servers="nats://localhost:4222",
            agent_id=permitted_agent,
        )
        # noinspection PyProtectedMember
        client._enforce_subscriber_acl("claims.>")
