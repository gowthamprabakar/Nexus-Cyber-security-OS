"""Tests for `shared.fabric.client.JetStreamClient` (F.7 v0.1 Task 3 surface).

All tests in this module run in the default mocked lane — nats-py is
mocked at the import boundary of `shared.fabric.client`. The live lane
(`NEXUS_LIVE_NATS=1` against a real broker) is owned by F.7 v0.1 Task 6
(`tests/integration/test_fabric_client_live.py`, separate PR).

Scope per F.7 v0.1 plan Task 3 — this file covers:
- Construction validation.
- `connect()` happy / timeout / no-server / OSError paths + idempotency.
- `ensure_streams()` create-when-missing / no-op-when-matching /
  raise-on-drift (subjects / max_age / discard).
- `publish()` happy / missing-correlation-id / cross-stream-subject.
- `publish_finding()` envelope-wrap / non-findings-subject rejection.
- `subscribe()` happy / cross-stream-subject / empty-durable rejection.
- `close()` idempotency.
- "not connected" guards on publish / subscribe / ensure_streams.

F.7 v0.1 Task 5 will expand to ~15-20 additional cases (subscribe
callback-exception paths, parameterized error matrices, etc.). Task 4
adds the correlation_id contextvar-fallback + header-propagation tests.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from nats.errors import NoServersError
from nats.errors import TimeoutError as NATSTimeoutError
from nats.js.api import DiscardPolicy as NATSDiscardPolicy
from nats.js.api import StreamConfig
from nats.js.errors import NotFoundError as NATSNotFoundError
from pytest_mock import MockerFixture
from shared.fabric.client import (
    FabricConnectionError,
    JetStreamClient,
    MissingCorrelationIdError,
    StreamSpecMismatchError,
)
from shared.fabric.envelope import NexusEnvelope
from shared.fabric.streams import (
    ALL_STREAMS,
    AUDIT_STREAM,
    EVENTS_STREAM,
    FINDINGS_STREAM,
    StreamSpec,
)


def _make_nats_mock(stream_info_side_effect: Any = None) -> tuple[MagicMock, AsyncMock]:
    """Return (nc_mock, js_mock) wired up like a connected nats-py client.

    `nc_mock.is_connected` is True after `nats.connect` returns it.
    `js_mock.stream_info` / `add_stream` / `publish` / `subscribe` are
    all `AsyncMock`s that tests can configure.
    """
    js = MagicMock()
    js.stream_info = AsyncMock(side_effect=stream_info_side_effect)
    js.add_stream = AsyncMock()
    js.publish = AsyncMock(return_value=MagicMock(stream="x", seq=1))
    js.subscribe = AsyncMock(return_value=MagicMock(name="Subscription"))
    nc = MagicMock()
    nc.is_connected = True
    nc.jetstream = MagicMock(return_value=js)
    nc.close = AsyncMock()
    return nc, js


def _patch_nats_connect(
    mocker: MockerFixture,
    nc_mock: MagicMock | None = None,
    side_effect: Any = None,
) -> AsyncMock:
    """Patch `shared.fabric.client.nats.connect`. Returns the AsyncMock."""
    if nc_mock is None and side_effect is None:
        nc_mock, _ = _make_nats_mock()
    return mocker.patch(
        "shared.fabric.client.nats.connect",
        new_callable=AsyncMock,
        return_value=nc_mock,
        side_effect=side_effect,
    )


def _spec_to_existing_config(spec: StreamSpec) -> StreamConfig:
    """Build a `StreamConfig` that `stream_info().config` would return for an in-sync stream."""
    return StreamConfig(
        name=spec.name,
        subjects=list(spec.subjects),
        max_age=spec.retention_seconds,
        max_msgs_per_subject=spec.max_msgs_per_subject,
        discard=NATSDiscardPolicy.OLD if spec.discard_policy == "old" else NATSDiscardPolicy.NEW,
    )


# ─── construction ───────────────────────────────────────────────────────────


def test_init_rejects_empty_servers_list() -> None:
    with pytest.raises(ValueError, match="non-empty list"):
        JetStreamClient(servers=[])


def test_init_stores_servers_immutably() -> None:
    servers = ["nats://a:4222"]
    client = JetStreamClient(servers=servers)
    servers.append("nats://b:4222")  # should not affect client
    assert client._servers == ["nats://a:4222"]


def test_init_uses_5_second_default_timeout() -> None:
    client = JetStreamClient(servers=["nats://localhost:4222"])
    assert client._connect_timeout == 5


# ─── connect() ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_connect_happy_path_acquires_jetstream_context(mocker: MockerFixture) -> None:
    nc, js = _make_nats_mock()
    connect = _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    connect.assert_awaited_once()
    assert client.is_connected is True
    assert client._js is js


@pytest.mark.asyncio
async def test_connect_is_idempotent(mocker: MockerFixture) -> None:
    nc, _ = _make_nats_mock()
    connect = _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.connect()
    assert connect.await_count == 1


@pytest.mark.asyncio
async def test_connect_raises_fabric_connection_error_on_timeout(
    mocker: MockerFixture,
) -> None:
    _patch_nats_connect(mocker, side_effect=NATSTimeoutError())
    client = JetStreamClient(servers=["nats://localhost:4222"])
    with pytest.raises(FabricConnectionError, match="failed to connect"):
        await client.connect()
    assert client.is_connected is False


@pytest.mark.asyncio
async def test_connect_raises_fabric_connection_error_on_no_servers(
    mocker: MockerFixture,
) -> None:
    _patch_nats_connect(mocker, side_effect=NoServersError())
    client = JetStreamClient(servers=["nats://localhost:4222"])
    with pytest.raises(FabricConnectionError):
        await client.connect()


@pytest.mark.asyncio
async def test_connect_raises_fabric_connection_error_on_oserror(
    mocker: MockerFixture,
) -> None:
    _patch_nats_connect(mocker, side_effect=OSError("connection refused"))
    client = JetStreamClient(servers=["nats://localhost:4222"])
    with pytest.raises(FabricConnectionError, match="connection refused"):
        await client.connect()


@pytest.mark.asyncio
async def test_connect_raises_fabric_connection_error_on_asyncio_timeout(
    mocker: MockerFixture,
) -> None:
    _patch_nats_connect(mocker, side_effect=TimeoutError())
    client = JetStreamClient(servers=["nats://localhost:4222"])
    with pytest.raises(FabricConnectionError):
        await client.connect()


@pytest.mark.asyncio
async def test_connect_passes_connect_timeout_to_nats(mocker: MockerFixture) -> None:
    nc, _ = _make_nats_mock()
    connect = _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"], connect_timeout_seconds=3)
    await client.connect()
    assert connect.await_args.kwargs["connect_timeout"] == 3


# ─── ensure_streams() ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ensure_streams_creates_missing_streams(mocker: MockerFixture) -> None:
    nc, js = _make_nats_mock(stream_info_side_effect=NATSNotFoundError())
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.ensure_streams()
    assert js.add_stream.await_count == len(ALL_STREAMS)
    # Spot-check that one of the created configs has the right name + subjects
    created_names = {call.args[0].name for call in js.add_stream.await_args_list}
    assert created_names == {s.name for s in ALL_STREAMS}


@pytest.mark.asyncio
async def test_ensure_streams_no_op_when_matching(mocker: MockerFixture) -> None:
    def matching_stream_info(name: str) -> MagicMock:
        spec = next(s for s in ALL_STREAMS if s.name == name)
        info = MagicMock()
        info.config = _spec_to_existing_config(spec)
        return info

    nc, js = _make_nats_mock(stream_info_side_effect=matching_stream_info)
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.ensure_streams()
    js.add_stream.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_streams_raises_on_subjects_drift(mocker: MockerFixture) -> None:
    def drifted(name: str) -> MagicMock:
        spec = next(s for s in ALL_STREAMS if s.name == name)
        info = MagicMock()
        cfg = _spec_to_existing_config(spec)
        cfg.subjects = [f"{spec.name}.broker-drifted.>"]
        info.config = cfg
        return info

    nc, _ = _make_nats_mock(stream_info_side_effect=drifted)
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with pytest.raises(StreamSpecMismatchError, match="subjects:"):
        await client.ensure_streams()


@pytest.mark.asyncio
async def test_ensure_streams_raises_on_max_age_drift(mocker: MockerFixture) -> None:
    def drifted(name: str) -> MagicMock:
        spec = next(s for s in ALL_STREAMS if s.name == name)
        info = MagicMock()
        cfg = _spec_to_existing_config(spec)
        cfg.max_age = spec.retention_seconds + 1  # tiny drift
        info.config = cfg
        return info

    nc, _ = _make_nats_mock(stream_info_side_effect=drifted)
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with pytest.raises(StreamSpecMismatchError, match="max_age:"):
        await client.ensure_streams()


@pytest.mark.asyncio
async def test_ensure_streams_raises_on_discard_drift(mocker: MockerFixture) -> None:
    def drifted(name: str) -> MagicMock:
        spec = next(s for s in ALL_STREAMS if s.name == name)
        info = MagicMock()
        cfg = _spec_to_existing_config(spec)
        cfg.discard = NATSDiscardPolicy.NEW  # specs all declare "old"
        info.config = cfg
        return info

    nc, _ = _make_nats_mock(stream_info_side_effect=drifted)
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with pytest.raises(StreamSpecMismatchError, match="discard:"):
        await client.ensure_streams()


@pytest.mark.asyncio
async def test_ensure_streams_before_connect_raises_connection_error() -> None:
    client = JetStreamClient(servers=["nats://localhost:4222"])
    with pytest.raises(FabricConnectionError, match="not connected"):
        await client.ensure_streams()


# ─── publish() ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_publish_happy_path(mocker: MockerFixture) -> None:
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.publish(
        EVENTS_STREAM,
        "events.tenant.t1.scan_completed",
        b"payload",
        correlation_id="cid-1",
    )
    js.publish.assert_awaited_once_with(
        "events.tenant.t1.scan_completed",
        b"payload",
        stream="events",
    )


@pytest.mark.asyncio
async def test_publish_raises_missing_correlation_id_on_none_kwarg(
    mocker: MockerFixture,
) -> None:
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with pytest.raises(MissingCorrelationIdError, match="explicit correlation_id"):
        await client.publish(
            EVENTS_STREAM,
            "events.tenant.t1.foo",
            b"payload",
            correlation_id=None,
        )


@pytest.mark.asyncio
async def test_publish_rejects_subject_outside_stream_namespace(
    mocker: MockerFixture,
) -> None:
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with pytest.raises(ValueError, match="does not match stream"):
        await client.publish(
            EVENTS_STREAM,
            "findings.tenant.t1.asset.abc",  # wrong root
            b"payload",
            correlation_id="cid",
        )


@pytest.mark.asyncio
async def test_publish_before_connect_raises_connection_error() -> None:
    client = JetStreamClient(servers=["nats://localhost:4222"])
    with pytest.raises(FabricConnectionError, match="not connected"):
        await client.publish(
            AUDIT_STREAM,
            "audit.tenant.t1",
            b"x",
            correlation_id="cid",
        )


# ─── publish_finding() ──────────────────────────────────────────────────────


def _make_envelope(correlation_id: str = "cid-finding-1") -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id="tnt-abc",
        agent_id="cloud-posture",
        nlah_version="1.2",
        model_pin="claude-opus-4-7",
        charter_invocation_id="charter-01",
    )


@pytest.mark.asyncio
async def test_publish_finding_wraps_via_envelope_and_publishes_to_findings(
    mocker: MockerFixture,
) -> None:
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()

    ocsf_event = {"class_uid": 2007, "severity": "high"}
    envelope = _make_envelope()
    await client.publish_finding(
        "findings.tenant.tnt-abc.asset.abc123",
        ocsf_event,
        envelope,
    )

    js.publish.assert_awaited_once()
    args, kwargs = js.publish.await_args
    assert args[0] == "findings.tenant.tnt-abc.asset.abc123"
    payload_bytes: bytes = args[1]
    assert kwargs["stream"] == "findings"
    # Payload is JSON-encoded; the wrapped dict contains both OCSF + envelope
    import json as _json

    decoded = _json.loads(payload_bytes.decode("utf-8"))
    assert decoded["class_uid"] == 2007
    assert decoded["severity"] == "high"
    assert decoded["nexus_envelope"]["correlation_id"] == "cid-finding-1"
    assert decoded["nexus_envelope"]["tenant_id"] == "tnt-abc"


@pytest.mark.asyncio
async def test_publish_finding_rejects_non_findings_subject(
    mocker: MockerFixture,
) -> None:
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with pytest.raises(ValueError, match="findings\\.\\* subject"):
        await client.publish_finding(
            "events.tenant.t1.foo",
            {"class_uid": 2007},
            _make_envelope(),
        )


# ─── subscribe() ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_subscribe_happy_path_passes_durable_name(mocker: MockerFixture) -> None:
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()

    async def cb(msg: Any) -> None:
        pass

    await client.subscribe(
        EVENTS_STREAM,
        "events.tenant.t1.>",
        cb,
        durable_name="d-1",
    )
    js.subscribe.assert_awaited_once_with(
        "events.tenant.t1.>",
        cb=cb,
        durable="d-1",
        stream="events",
    )


@pytest.mark.asyncio
async def test_subscribe_rejects_subject_outside_stream_namespace(
    mocker: MockerFixture,
) -> None:
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()

    async def cb(msg: Any) -> None:
        pass

    with pytest.raises(ValueError, match="does not lie under stream"):
        await client.subscribe(
            EVENTS_STREAM,
            "findings.tenant.t1.>",
            cb,
            durable_name="d-1",
        )


@pytest.mark.asyncio
async def test_subscribe_rejects_empty_durable_name(mocker: MockerFixture) -> None:
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()

    async def cb(msg: Any) -> None:
        pass

    with pytest.raises(ValueError, match="durable_name"):
        await client.subscribe(
            EVENTS_STREAM,
            "events.tenant.t1.>",
            cb,
            durable_name="",
        )


# ─── close() ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_close_is_idempotent_when_never_connected() -> None:
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.close()
    await client.close()  # second call should also be a no-op
    assert client.is_connected is False


@pytest.mark.asyncio
async def test_close_calls_underlying_close_once(mocker: MockerFixture) -> None:
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.close()
    nc.close.assert_awaited_once()
    # After close, publish should refuse
    with pytest.raises(FabricConnectionError):
        await client.publish(
            AUDIT_STREAM,
            "audit.tenant.t1",
            b"x",
            correlation_id="cid",
        )


# ─── findings stream uses the right helper ─────────────────────────────────


@pytest.mark.asyncio
async def test_findings_stream_constant_matches_publish_finding_path(
    mocker: MockerFixture,
) -> None:
    """publish_finding() routes to FINDINGS_STREAM, not whatever the
    caller might pass. This guards against a Task-4+ refactor that
    introduces a second findings-like stream and lets a subtle bug slip
    in where publish_finding writes to the wrong stream.
    """
    assert FINDINGS_STREAM.name == "findings"
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.publish_finding(
        "findings.tenant.t1.asset.xyz",
        {"class_uid": 2007},
        _make_envelope(),
    )
    assert js.publish.await_args.kwargs["stream"] == "findings"
