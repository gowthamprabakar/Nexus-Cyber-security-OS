"""Tests for `investigation.bus_emit` (F.7 v0.2 Task 3 surface).

All tests in this module run against a mocked `JetStreamClient`. The
live-broker lane (`NEXUS_LIVE_NATS=1` against a real NATS server) is
owned by F.7 v0.2 Task 5 (a separate PR, SAFETY-CRITICAL).

The non-fatal failure semantics this module proves at the unit level
are then re-proven end-to-end against the real agent driver in
`test_agent.py`'s F.7 v0.2 wiring tests, and finally proven against a
real broker in Task 5's `test_bus_emit_live.py`. Three concentric
proofs; this is the innermost.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from charter.audit import AuditLog
from investigation.bus_emit import (
    BUS_PUBLISH_ATTEMPT_ACTION,
    BUS_PUBLISH_FAILURE_ACTION,
    BUS_PUBLISH_SUCCESS_ACTION,
    BusEmitter,
    mint_investigation_id,
)
from shared.fabric import (
    CORRELATION_ID_HEADER,
    EVENTS_STREAM,
    FabricConnectionError,
    MissingCorrelationIdError,
)

_TENANT_A = "01HV0T0000000000000000TENA"
_CID = "01J7M3X9Z1K8RPVQNH2T8DBHFZ"


@pytest.fixture
def audit_log(tmp_path: Any) -> AuditLog:
    return AuditLog(path=tmp_path / "audit.jsonl", agent="investigation", run_id="run-1")


def _mock_client(*, publish_side_effect: Any = None) -> MagicMock:
    """Build a mock JetStreamClient with the standard async surface.

    By default `publish` returns a PubAck-shaped MagicMock with stream
    and seq attributes; pass `publish_side_effect` to make it raise.
    """
    client = MagicMock()
    client.connect = AsyncMock()
    client.close = AsyncMock()
    if publish_side_effect is not None:
        client.publish = AsyncMock(side_effect=publish_side_effect)
    else:
        client.publish = AsyncMock(return_value=MagicMock(stream="events", seq=42))
    return client


def _audit_actions(audit_log: AuditLog) -> Sequence[str]:
    """Read every action in order from the audit-jsonl file the log writes to."""
    return tuple(
        json.loads(line)["action"] for line in audit_log.path.read_text().splitlines() if line
    )


def _audit_payloads(audit_log: AuditLog) -> Sequence[dict[str, Any]]:
    return tuple(
        json.loads(line)["payload"] for line in audit_log.path.read_text().splitlines() if line
    )


# ---------------------------- audit action constants ----------------------------


def test_audit_action_constants_are_additive_per_adr_010_cond_4() -> None:
    """The 3 new audit action types are net-new strings.

    They do NOT collide with charter.audit's existing vocabulary
    (`invocation_started` / `invocation_completed` / `invocation_failed`
    / `tool_call` / `output_written`). The `investigation.*` namespace
    is reserved for D.7's per-agent action types.
    """
    assert BUS_PUBLISH_ATTEMPT_ACTION == "investigation.bus_publish.attempt"
    assert BUS_PUBLISH_SUCCESS_ACTION == "investigation.bus_publish.success"
    assert BUS_PUBLISH_FAILURE_ACTION == "investigation.bus_publish.failure"
    # All under the agent-namespaced `investigation.bus_publish.*` prefix.
    for action in (
        BUS_PUBLISH_ATTEMPT_ACTION,
        BUS_PUBLISH_SUCCESS_ACTION,
        BUS_PUBLISH_FAILURE_ACTION,
    ):
        assert action.startswith("investigation.bus_publish.")


def test_mint_investigation_id_returns_26_char_ulid() -> None:
    iid = mint_investigation_id()
    assert isinstance(iid, str)
    assert len(iid) == 26


# ---------------------------- construction --------------------------------


def test_bus_emitter_rejects_empty_servers_list() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        BusEmitter(servers=[])


def test_bus_emitter_constructs_with_injected_client() -> None:
    client = _mock_client()
    emitter = BusEmitter(servers=["nats://test:4222"], client=client)
    assert emitter._client is client


# ---------------------------- connect / close -----------------------------


@pytest.mark.asyncio
async def test_connect_happy_path_calls_underlying_client() -> None:
    client = _mock_client()
    emitter = BusEmitter(servers=["nats://test"], client=client)
    await emitter.connect()
    client.connect.assert_awaited_once()


@pytest.mark.asyncio
async def test_connect_fabric_connection_error_does_not_raise() -> None:
    """Connect failures are best-effort — subsequent emits will see
    "not connected" via publish() and record bus_publish.failure."""
    client = _mock_client()
    client.connect = AsyncMock(side_effect=FabricConnectionError("broker down"))
    emitter = BusEmitter(servers=["nats://test"], client=client)
    await emitter.connect()  # MUST NOT raise


@pytest.mark.asyncio
async def test_close_safe_when_never_connected() -> None:
    client = _mock_client()
    emitter = BusEmitter(servers=["nats://test"], client=client)
    await emitter.close()
    client.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_close_swallows_underlying_exceptions() -> None:
    client = _mock_client()
    client.close = AsyncMock(side_effect=RuntimeError("close failed"))
    emitter = BusEmitter(servers=["nats://test"], client=client)
    await emitter.close()  # MUST NOT raise


# ---------------------------- emit_started --------------------------------


@pytest.mark.asyncio
async def test_emit_started_happy_path_records_attempt_then_success(
    audit_log: AuditLog,
) -> None:
    client = _mock_client()
    emitter = BusEmitter(servers=["nats://test"], client=client)
    iid = mint_investigation_id()

    await emitter.emit_started(
        audit_log=audit_log,
        tenant_id=_TENANT_A,
        correlation_id=_CID,
        investigation_id=iid,
    )

    actions = _audit_actions(audit_log)
    # Charter __init__ writes "invocation_started" via AuditLog only when
    # the Charter context manager runs; we use a bare AuditLog here so
    # only our entries appear.
    assert actions == (BUS_PUBLISH_ATTEMPT_ACTION, BUS_PUBLISH_SUCCESS_ACTION)


@pytest.mark.asyncio
async def test_emit_started_publishes_to_correct_subject(audit_log: AuditLog) -> None:
    client = _mock_client()
    emitter = BusEmitter(servers=["nats://test"], client=client)
    iid = mint_investigation_id()

    await emitter.emit_started(
        audit_log=audit_log,
        tenant_id=_TENANT_A,
        correlation_id=_CID,
        investigation_id=iid,
    )

    client.publish.assert_awaited_once()
    args = client.publish.await_args.args
    kwargs = client.publish.await_args.kwargs
    assert args[0] is EVENTS_STREAM  # the StreamSpec instance
    assert args[1] == f"events.tenant.{_TENANT_A}.investigation.started"
    assert kwargs["correlation_id"] == _CID


@pytest.mark.asyncio
async def test_emit_started_payload_bytes_match_schema_encoding(
    audit_log: AuditLog,
) -> None:
    """The bytes published are exactly InvestigationLifecycleEvent.to_payload_bytes()
    — sort_keys=True + separators=(",",":") + exclude_none=True."""
    client = _mock_client()
    emitter = BusEmitter(servers=["nats://test"], client=client)
    iid = mint_investigation_id()

    await emitter.emit_started(
        audit_log=audit_log,
        tenant_id=_TENANT_A,
        correlation_id=_CID,
        investigation_id=iid,
    )

    payload_bytes: bytes = client.publish.await_args.args[2]
    decoded = json.loads(payload_bytes)
    assert decoded["event_type"] == "started"
    assert decoded["investigation_id"] == iid
    assert decoded["tenant_id"] == _TENANT_A
    assert decoded["correlation_id"] == _CID
    # Success path → no stage / no error_class (exclude_none=True).
    assert "stage" not in decoded
    assert "error_class" not in decoded


# ---------------------------- emit_completed ------------------------------


@pytest.mark.asyncio
async def test_emit_completed_publishes_completed_event_type(audit_log: AuditLog) -> None:
    client = _mock_client()
    emitter = BusEmitter(servers=["nats://test"], client=client)
    iid = mint_investigation_id()

    await emitter.emit_completed(
        audit_log=audit_log,
        tenant_id=_TENANT_A,
        correlation_id=_CID,
        investigation_id=iid,
    )

    args = client.publish.await_args.args
    assert args[1] == f"events.tenant.{_TENANT_A}.investigation.completed"
    payload_bytes: bytes = args[2]
    decoded = json.loads(payload_bytes)
    assert decoded["event_type"] == "completed"
    assert "stage" not in decoded


# ---------------------------- emit_failed ---------------------------------


@pytest.mark.asyncio
async def test_emit_failed_publishes_failed_event_type_with_stage_and_error_class(
    audit_log: AuditLog,
) -> None:
    client = _mock_client()
    emitter = BusEmitter(servers=["nats://test"], client=client)
    iid = mint_investigation_id()

    await emitter.emit_failed(
        audit_log=audit_log,
        tenant_id=_TENANT_A,
        correlation_id=_CID,
        investigation_id=iid,
        stage="synthesize",
        error_class="RuntimeError",
    )

    args = client.publish.await_args.args
    assert args[1] == f"events.tenant.{_TENANT_A}.investigation.failed"
    payload_bytes: bytes = args[2]
    decoded = json.loads(payload_bytes)
    assert decoded["event_type"] == "failed"
    assert decoded["stage"] == "synthesize"
    assert decoded["error_class"] == "RuntimeError"


@pytest.mark.asyncio
async def test_emit_failed_never_raises_even_when_publish_explodes(
    audit_log: AuditLog,
) -> None:
    """emit_failed is called from the agent's exception handler; it must
    NEVER mask the underlying D.7 failure by raising itself."""
    client = _mock_client(publish_side_effect=FabricConnectionError("broker down"))
    emitter = BusEmitter(servers=["nats://test"], client=client)
    iid = mint_investigation_id()

    # MUST NOT raise:
    await emitter.emit_failed(
        audit_log=audit_log,
        tenant_id=_TENANT_A,
        correlation_id=_CID,
        investigation_id=iid,
        stage="scope",
        error_class="ValueError",
    )
    # Failure was recorded to the chain.
    actions = _audit_actions(audit_log)
    assert actions == (BUS_PUBLISH_ATTEMPT_ACTION, BUS_PUBLISH_FAILURE_ACTION)


# ---------------------------- non-fatal failure proofs --------------------


@pytest.mark.parametrize(
    "exc",
    [
        FabricConnectionError("broker unreachable"),
        MissingCorrelationIdError("no correlation_id"),
        OSError("network unreachable"),
    ],
    ids=["FabricConnectionError", "MissingCorrelationIdError", "OSError"],
)
@pytest.mark.asyncio
async def test_publish_failure_caught_and_recorded_non_fatally(
    audit_log: AuditLog, exc: Exception
) -> None:
    """The 3 expected publish-failure exception types are all caught;
    audit chain records `bus_publish.failure`; emit returns normally."""
    client = _mock_client(publish_side_effect=exc)
    emitter = BusEmitter(servers=["nats://test"], client=client)
    iid = mint_investigation_id()

    await emitter.emit_started(  # MUST NOT raise
        audit_log=audit_log,
        tenant_id=_TENANT_A,
        correlation_id=_CID,
        investigation_id=iid,
    )

    actions = _audit_actions(audit_log)
    assert actions == (BUS_PUBLISH_ATTEMPT_ACTION, BUS_PUBLISH_FAILURE_ACTION)
    failure_payload = _audit_payloads(audit_log)[1]
    assert failure_payload["event_type"] == "started"
    assert failure_payload["exception_class"] == exc.__class__.__name__
    assert (
        exc.__class__.__name__ in str(failure_payload.get("message", ""))
        or str(exc) == failure_payload["message"]
    )


@pytest.mark.asyncio
async def test_success_audit_entry_carries_pub_ack_metadata(audit_log: AuditLog) -> None:
    """The success audit entry includes the broker's stream+seq for
    forensic reconstruction (the bus-side anchor of the lifecycle event)."""
    client = MagicMock()
    client.connect = AsyncMock()
    client.close = AsyncMock()
    client.publish = AsyncMock(return_value=MagicMock(stream="events", seq=4242))
    emitter = BusEmitter(servers=["nats://test"], client=client)
    iid = mint_investigation_id()

    await emitter.emit_started(
        audit_log=audit_log,
        tenant_id=_TENANT_A,
        correlation_id=_CID,
        investigation_id=iid,
    )

    success_payload = _audit_payloads(audit_log)[1]
    assert success_payload["ack_stream"] == "events"
    assert success_payload["ack_seq"] == 4242


# ---------------------------- header round-trip via mocked client --------


@pytest.mark.asyncio
async def test_publish_invocation_carries_correlation_id_kwarg(audit_log: AuditLog) -> None:
    """The correlation_id flows from the BusEmitter into JetStreamClient.publish's
    kwarg — the F.7 v0.1 client then sets it as the Nexus-Correlation-Id
    header on the wire (proven separately in F.7 v0.1 Tasks 4 + 6)."""
    client = _mock_client()
    emitter = BusEmitter(servers=["nats://test"], client=client)
    iid = mint_investigation_id()

    await emitter.emit_completed(
        audit_log=audit_log,
        tenant_id=_TENANT_A,
        correlation_id=_CID,
        investigation_id=iid,
    )

    assert client.publish.await_args.kwargs["correlation_id"] == _CID
    # Sanity: the header constant the F.7 v0.1 substrate uses is still
    # "Nexus-Correlation-Id" — pinned here in case a future refactor
    # accidentally renames it (which would break Task 5's live proof).
    assert CORRELATION_ID_HEADER == "Nexus-Correlation-Id"
