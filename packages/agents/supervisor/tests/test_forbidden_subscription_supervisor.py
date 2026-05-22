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
A.1 Remediation, ADR-012's original fence). The third entry —
A.4 Meta-Harness — landed in A.4 v0.2 Task 11 (ADR-012 §v1.1
amendment, 2026-05-22), realising the WI-5 forward-carry from
the Supervisor v0.1 verification record. The trajectory CLOSES
at three subscribers for Phase 1; ``test_registry_has_three_entries``
locks that in.
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


def test_registry_has_three_entries_after_a_4_v0_2() -> None:
    """Forbidden-subscriber set after A.4 v0.2 Task 11 (ADR-012 §v1.1):
    A.1 Remediation + Supervisor + A.4 Meta-Harness.

    The Q-ARCH-1 trajectory CLOSES at three subscribers for Phase 1 —
    no further additions are queued. Future auto-acting agents inherit
    the standing rule; they don't pre-register here.
    """
    assert set(_FORBIDDEN_SUBSCRIPTIONS.keys()) == {
        "remediation",
        "supervisor",
        "meta_harness",
    }


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
