"""Tests for `shared.fabric.client.JetStreamClient` (F.7 v0.1 client surface).

All tests in this module run in the default mocked lane — nats-py is
mocked at the import boundary of `shared.fabric.client`. The live lane
(`NEXUS_LIVE_NATS=1` against a real broker) is owned by F.7 v0.1 Task 6
(`tests/integration/test_fabric_client_live.py`, separate PR). The
mocked round-trip in this module is necessary but not sufficient;
Task 6 is the load-bearing live proof of the substrate.

Coverage:
- Construction validation.
- `connect()` happy / timeout / no-server / OSError / asyncio-timeout
  paths + idempotency + connect-timeout passthrough.
- `ensure_streams()` create-when-missing / no-op-when-matching /
  raise-on-drift (subjects / max_age / discard) / empty-specs no-op /
  partial-specs / after-close raises / not-connected raises.
- `publish()` happy + per-stream parameterized / Q3 4-prong path
  matrix (explicit kwarg / contextvar fallback / both absent / header
  round-trip / kwarg-over-contextvar precedence / refusal before subject
  validation) / cross-stream-subject / subject-prefix-must-end-with-dot
  / return-value-passthrough / payload-not-mutated.
- `publish_finding()` envelope-wrap / non-findings rejection /
  envelope-correlation-id-to-header / JSON-encoding-deterministic /
  6-field envelope serialized in payload / after-close raises.
- `subscribe()` happy / wildcard subject_filter / callback-by-reference /
  cross-stream rejection / empty-durable rejection / multiple-calls
  independent / after-close raises.
- `close()` idempotency / lifecycle re-init (close→connect→use).
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
    CORRELATION_ID_HEADER,
    FabricConnectionError,
    ForbiddenSubscriptionError,
    JetStreamClient,
    MissingCorrelationIdError,
    StreamSpecMismatchError,
)
from shared.fabric.correlation import correlation_scope
from shared.fabric.envelope import NexusEnvelope
from shared.fabric.streams import (
    ALL_STREAMS,
    APPROVALS_STREAM,
    AUDIT_STREAM,
    CLAIMS_STREAM,
    COMMANDS_STREAM,
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
        headers={CORRELATION_ID_HEADER: "cid-1"},
    )


@pytest.mark.asyncio
async def test_publish_raises_missing_correlation_id_when_both_absent(
    mocker: MockerFixture,
) -> None:
    """Q3 refusal path: kwarg None + no active correlation_scope → raise."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with pytest.raises(MissingCorrelationIdError, match="bus refuses messages"):
        await client.publish(
            EVENTS_STREAM,
            "events.tenant.t1.foo",
            b"payload",
            correlation_id=None,
        )
    # The refusal happens BEFORE the network call — the mocked publish was
    # never awaited.
    js.publish.assert_not_awaited()


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


# ─── Q3 correlation_id-as-bus-property (Task 4 surface) ────────────────────


@pytest.mark.asyncio
async def test_publish_uses_explicit_kwarg_in_header(mocker: MockerFixture) -> None:
    """Path (a): explicit kwarg → header carries that exact value."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.publish(
        AUDIT_STREAM,
        "audit.tenant.t1",
        b"x",
        correlation_id="explicit-cid",
    )
    headers = js.publish.await_args.kwargs["headers"]
    assert headers == {CORRELATION_ID_HEADER: "explicit-cid"}


@pytest.mark.asyncio
async def test_publish_falls_back_to_contextvar_when_kwarg_absent(
    mocker: MockerFixture,
) -> None:
    """Path (b): kwarg None + active correlation_scope → contextvar value used."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with correlation_scope("ctxvar-cid"):
        await client.publish(EVENTS_STREAM, "events.tenant.t1.foo", b"x")
    headers = js.publish.await_args.kwargs["headers"]
    assert headers == {CORRELATION_ID_HEADER: "ctxvar-cid"}


@pytest.mark.asyncio
async def test_publish_kwarg_takes_precedence_over_contextvar(
    mocker: MockerFixture,
) -> None:
    """Explicit kwarg overrides the ambient contextvar.

    Important for callers that want to publish a message under a
    different correlation_id than the surrounding scope (e.g.,
    audit-chain anchor messages that mint their own root).
    """
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with correlation_scope("ambient-cid"):
        await client.publish(
            EVENTS_STREAM,
            "events.tenant.t1.foo",
            b"x",
            correlation_id="explicit-cid",
        )
    headers = js.publish.await_args.kwargs["headers"]
    assert headers == {CORRELATION_ID_HEADER: "explicit-cid"}


@pytest.mark.asyncio
async def test_publish_header_round_trip_via_mocked_js_publish(
    mocker: MockerFixture,
) -> None:
    """Path (d): the header reaches the wire-level publish call.

    Mocked round-trip — Task 6 (NEXUS_LIVE_NATS=1 against a live
    broker) is the load-bearing live round-trip. This unit-level
    assertion proves the header is set on the outbound call; the live
    test will prove the broker preserves it end-to-end to subscribers.
    """
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.publish(
        EVENTS_STREAM,
        "events.tenant.t1.foo",
        b"payload",
        correlation_id="round-trip-cid",
    )
    js.publish.assert_awaited_once_with(
        "events.tenant.t1.foo",
        b"payload",
        stream="events",
        headers={CORRELATION_ID_HEADER: "round-trip-cid"},
    )
    # Header constant is exactly the wire-format name ADR-004's
    # correlation_id contract requires — guard against accidental rename.
    assert CORRELATION_ID_HEADER == "Nexus-Correlation-Id"


@pytest.mark.asyncio
async def test_publish_finding_propagates_envelope_correlation_id_to_header(
    mocker: MockerFixture,
) -> None:
    """publish_finding() routes the envelope's correlation_id through to
    the header. A caller who provides only an envelope (no separate
    kwarg) still ends up with the header set on the outbound message.
    """
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    envelope = _make_envelope(correlation_id="env-cid-xyz")
    await client.publish_finding(
        "findings.tenant.tnt-abc.asset.abc",
        {"class_uid": 2007},
        envelope,
    )
    headers = js.publish.await_args.kwargs["headers"]
    assert headers == {CORRELATION_ID_HEADER: "env-cid-xyz"}


@pytest.mark.asyncio
async def test_publish_refusal_happens_before_subject_validation(
    mocker: MockerFixture,
) -> None:
    """The Q3 refusal precondition runs BEFORE subject validation —
    a caller missing both correlation sources gets the MissingCorrelationIdError,
    not a misleading subject ValueError, even if the subject is also wrong.
    """
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with pytest.raises(MissingCorrelationIdError):
        await client.publish(
            EVENTS_STREAM,
            "wrong.subject.root.foo",  # would also fail subject validation
            b"x",
            correlation_id=None,
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


# ─── Task 5 expansion: ensure_streams() edge cases ─────────────────────────


@pytest.mark.asyncio
async def test_ensure_streams_with_empty_specs_is_no_op(mocker: MockerFixture) -> None:
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.ensure_streams(specs=())
    js.stream_info.assert_not_awaited()
    js.add_stream.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_streams_with_partial_specs_only_acts_on_those(
    mocker: MockerFixture,
) -> None:
    nc, js = _make_nats_mock(stream_info_side_effect=NATSNotFoundError())
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.ensure_streams(specs=(EVENTS_STREAM, AUDIT_STREAM))
    assert js.stream_info.await_count == 2
    assert js.add_stream.await_count == 2
    created_names = {call.args[0].name for call in js.add_stream.await_args_list}
    assert created_names == {"events", "audit"}


# ─── Task 5 expansion: publish() edge cases ────────────────────────────────


@pytest.mark.asyncio
async def test_publish_subject_prefix_must_be_followed_by_dot(
    mocker: MockerFixture,
) -> None:
    """`events_typo` is NOT a valid events subject; the prefix check
    requires the stream root followed by a literal dot."""
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with pytest.raises(ValueError, match="does not match stream"):
        await client.publish(
            EVENTS_STREAM,
            "events_typo.foo",
            b"x",
            correlation_id="cid",
        )


@pytest.mark.asyncio
async def test_publish_subject_equal_to_stream_root_alone_rejected(
    mocker: MockerFixture,
) -> None:
    """`events` alone (no `.` suffix) is rejected — the prefix is
    `events.` not `events`."""
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    with pytest.raises(ValueError, match="does not match stream"):
        await client.publish(
            EVENTS_STREAM,
            "events",
            b"x",
            correlation_id="cid",
        )


@pytest.mark.asyncio
async def test_publish_returns_puback_from_underlying_js(mocker: MockerFixture) -> None:
    """publish() returns nats-py's PubAck unchanged (no wrapping)."""
    nc, js = _make_nats_mock()
    ack_sentinel = MagicMock(stream="events", seq=42)
    js.publish = AsyncMock(return_value=ack_sentinel)
    nc.jetstream = MagicMock(return_value=js)
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    result = await client.publish(
        EVENTS_STREAM,
        "events.tenant.t1.foo",
        b"x",
        correlation_id="cid",
    )
    assert result is ack_sentinel


@pytest.mark.asyncio
async def test_publish_does_not_mutate_or_reencode_payload(
    mocker: MockerFixture,
) -> None:
    """The bytes object the caller hands in reaches `js.publish` by
    reference. Guards against a future change that might decode/
    re-encode the payload and silently change its bytes.
    """
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    payload = b"specific-bytes-\x00\x01\x02-payload"
    await client.publish(
        EVENTS_STREAM,
        "events.tenant.t1.foo",
        payload,
        correlation_id="cid",
    )
    assert js.publish.await_args.args[1] is payload


@pytest.mark.parametrize(
    "stream,subject",
    [
        (EVENTS_STREAM, "events.tenant.t1.scan_started"),
        (COMMANDS_STREAM, "commands.edge.e1.rule_pack_update"),
        (APPROVALS_STREAM, "approvals.tenant.t1.finding.f1"),
        (AUDIT_STREAM, "audit.tenant.t1"),
    ],
    ids=["events", "commands", "approvals", "audit"],
)
@pytest.mark.asyncio
async def test_publish_per_non_findings_stream(
    mocker: MockerFixture,
    stream: StreamSpec,
    subject: str,
) -> None:
    """publish() round-trips bytes through to js.publish for each of
    the four non-findings streams. Q5: arbitrary bytes accepted; only
    findings.> enforces the OCSF envelope (via publish_finding())."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.publish(stream, subject, b"payload", correlation_id="cid")
    js.publish.assert_awaited_once_with(
        subject,
        b"payload",
        stream=stream.name,
        headers={CORRELATION_ID_HEADER: "cid"},
    )


# ─── Task 5 expansion: publish_finding() determinism + envelope coverage ──


@pytest.mark.asyncio
async def test_publish_finding_json_encoding_is_deterministic(
    mocker: MockerFixture,
) -> None:
    """Two publish_finding() calls with the same dict produce the same
    bytes. sort_keys=True + separators=(',', ':') is the contract; any
    future change here is a wire-format change that breaks consumers."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    ocsf_event = {"b_key": 2, "a_key": 1, "c_key": 3}
    envelope = _make_envelope()
    await client.publish_finding("findings.tenant.t1.asset.abc", ocsf_event, envelope)
    await client.publish_finding("findings.tenant.t1.asset.abc", ocsf_event, envelope)
    first = js.publish.await_args_list[0].args[1]
    second = js.publish.await_args_list[1].args[1]
    assert first == second
    # Sort-keys guarantees alphabetical ordering of top-level keys.
    decoded = first.decode("utf-8")
    assert decoded.index('"a_key"') < decoded.index('"b_key"') < decoded.index('"c_key"')


@pytest.mark.asyncio
async def test_publish_finding_all_six_envelope_fields_in_payload(
    mocker: MockerFixture,
) -> None:
    """The full 6-field NexusEnvelope contract serializes into the
    payload's nexus_envelope sub-dict — none lost in transit."""
    import json as _json

    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    envelope = NexusEnvelope(
        correlation_id="cid-1",
        tenant_id="tnt-1",
        agent_id="agent-1",
        nlah_version="1.2",
        model_pin="claude-opus-4-7",
        charter_invocation_id="charter-1",
    )
    await client.publish_finding(
        "findings.tenant.tnt-1.asset.abc",
        {"class_uid": 2007},
        envelope,
    )
    payload_bytes: bytes = js.publish.await_args.args[1]
    decoded = _json.loads(payload_bytes.decode("utf-8"))
    env_serialized = decoded["nexus_envelope"]
    assert env_serialized == {
        "correlation_id": "cid-1",
        "tenant_id": "tnt-1",
        "agent_id": "agent-1",
        "nlah_version": "1.2",
        "model_pin": "claude-opus-4-7",
        "charter_invocation_id": "charter-1",
    }


# ─── Task 5 expansion: subscribe() behaviour + variations ──────────────────


@pytest.mark.asyncio
async def test_subscribe_with_wildcard_subject_filter(mocker: MockerFixture) -> None:
    """JetStream wildcard subjects (e.g., `events.tenant.t1.>`) are
    passed through unchanged."""
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
        durable_name="wildcard-consumer",
    )
    assert js.subscribe.await_args.args[0] == "events.tenant.t1.>"
    assert js.subscribe.await_args.kwargs["durable"] == "wildcard-consumer"


@pytest.mark.asyncio
async def test_subscribe_passes_callback_by_reference(mocker: MockerFixture) -> None:
    """The wrapper does NOT decorate / wrap / curry the user's callback.
    Exception handling, ack/nak, redelivery all stay nats-py's domain.
    """
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()

    async def my_cb(msg: Any) -> None:
        pass

    await client.subscribe(EVENTS_STREAM, "events.tenant.t1.>", my_cb, durable_name="d-1")
    assert js.subscribe.await_args.kwargs["cb"] is my_cb


@pytest.mark.asyncio
async def test_subscribe_multiple_calls_produce_independent_subscriptions(
    mocker: MockerFixture,
) -> None:
    nc, js = _make_nats_mock()
    sub_a = MagicMock(name="SubA")
    sub_b = MagicMock(name="SubB")
    js.subscribe = AsyncMock(side_effect=[sub_a, sub_b])
    nc.jetstream = MagicMock(return_value=js)
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()

    async def cb(msg: Any) -> None:
        pass

    result_a = await client.subscribe(EVENTS_STREAM, "events.tenant.t1.>", cb, durable_name="d-a")
    result_b = await client.subscribe(EVENTS_STREAM, "events.tenant.t1.>", cb, durable_name="d-b")
    assert result_a is sub_a
    assert result_b is sub_b
    assert result_a is not result_b
    assert js.subscribe.await_count == 2


# ─── Task 5 expansion: post-close lifecycle guards ─────────────────────────


@pytest.mark.asyncio
async def test_subscribe_after_close_raises_connection_error(
    mocker: MockerFixture,
) -> None:
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.close()

    async def cb(msg: Any) -> None:
        pass

    with pytest.raises(FabricConnectionError, match="not connected"):
        await client.subscribe(EVENTS_STREAM, "events.tenant.t1.>", cb, durable_name="d-1")


@pytest.mark.asyncio
async def test_ensure_streams_after_close_raises_connection_error(
    mocker: MockerFixture,
) -> None:
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.close()
    with pytest.raises(FabricConnectionError, match="not connected"):
        await client.ensure_streams()


@pytest.mark.asyncio
async def test_publish_finding_after_close_raises_connection_error(
    mocker: MockerFixture,
) -> None:
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.close()
    with pytest.raises(FabricConnectionError, match="not connected"):
        await client.publish_finding(
            "findings.tenant.t1.asset.abc",
            {"class_uid": 2007},
            _make_envelope(),
        )


@pytest.mark.asyncio
async def test_reconnect_after_close_works(mocker: MockerFixture) -> None:
    """close() then connect() restores a usable client. Mirrors the
    cold-start lifecycle a long-lived process might do for failover."""
    nc, js = _make_nats_mock()
    # nats.connect needs to return a fresh nc on the second call;
    # AsyncMock with return_value returns the same object both times,
    # which is fine for the mocked lane since we just need is_connected
    # to flip back to True.
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])
    await client.connect()
    await client.close()
    assert client.is_connected is False
    await client.connect()
    assert client.is_connected is True
    # And the new lifecycle accepts a publish call.
    await client.publish(
        EVENTS_STREAM,
        "events.tenant.t1.foo",
        b"x",
        correlation_id="cid",
    )
    js.publish.assert_awaited()


# ─── ADR-012 — subscriber ACL (autonomous-action safety) ────────────────────


@pytest.mark.asyncio
async def test_remediation_agent_forbidden_from_claims_subscription(
    mocker: MockerFixture,
) -> None:
    """A.1 attempting to subscribe to claims.> raises before the NATS call."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"], agent_id="remediation")
    await client.connect()

    async def _cb(msg: Any) -> None:
        return None

    with pytest.raises(ForbiddenSubscriptionError, match="remediation"):
        await client.subscribe(
            CLAIMS_STREAM,
            "claims.tenant.acme.>",
            _cb,
            durable_name="d1",
        )
    js.subscribe.assert_not_awaited()


@pytest.mark.asyncio
async def test_remediation_forbidden_for_specific_claims_subject(
    mocker: MockerFixture,
) -> None:
    """The fence matches subjects that fall under the forbidden pattern,
    not just literal `claims.>`. A.1 subscribing to a specific tenant
    or agent under claims is equally blocked."""
    nc, _ = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"], agent_id="remediation")
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
async def test_remediation_can_still_subscribe_to_findings(mocker: MockerFixture) -> None:
    """The fence is targeted — A.1 may freely subscribe to findings.>;
    only claims.> is forbidden."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"], agent_id="remediation")
    await client.connect()

    async def _cb(msg: Any) -> None:
        return None

    await client.subscribe(
        FINDINGS_STREAM,
        "findings.tenant.acme.>",
        _cb,
        durable_name="d1",
    )
    js.subscribe.assert_awaited_once()


@pytest.mark.asyncio
async def test_non_remediation_agent_may_subscribe_to_claims(mocker: MockerFixture) -> None:
    """Curiosity / Investigation / Threat-Intel / Data-Security / Meta-Harness
    subscribe to claims.> as a normal operation. Only agents enumerated in
    _FORBIDDEN_SUBSCRIPTIONS are blocked."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
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


@pytest.mark.asyncio
async def test_unset_agent_id_skips_acl_check(mocker: MockerFixture) -> None:
    """Backwards-compat: clients constructed without agent_id (tests +
    library callers) skip the ACL check. Production agent drivers MUST
    pass their agent_id."""
    nc, js = _make_nats_mock()
    _patch_nats_connect(mocker, nc_mock=nc)
    client = JetStreamClient(servers=["nats://localhost:4222"])  # no agent_id
    await client.connect()

    async def _cb(msg: Any) -> None:
        return None

    # Even though "claims.>" is a forbidden pattern for the remediation
    # agent, this client carries no agent identity so the check is skipped.
    await client.subscribe(
        CLAIMS_STREAM,
        "claims.tenant.acme.>",
        _cb,
        durable_name="d1",
    )
    js.subscribe.assert_awaited_once()


def test_forbidden_subscription_error_inherits_from_permission_error() -> None:
    """Per ADR-012: defensive code can catch the stdlib PermissionError
    category without importing the fabric module."""
    assert issubclass(ForbiddenSubscriptionError, PermissionError)


@pytest.mark.parametrize(
    ("subject", "pattern", "expected"),
    [
        ("claims.tenant.acme.>", "claims.>", True),
        ("claims.tenant.acme.agent.curiosity", "claims.>", True),
        ("claims", "claims.>", True),  # bare bus name matches
        ("findings.tenant.acme.>", "claims.>", False),
        ("findings.tenant.acme.agent.curiosity", "claims.>", False),
        ("claimsx.tenant.acme.>", "claims.>", False),  # not a prefix match
    ],
)
def test_subject_pattern_matcher(subject: str, pattern: str, expected: bool) -> None:
    """The matcher correctly distinguishes prefix matches from substring matches."""
    from shared.fabric.client import _subject_matches_pattern

    assert _subject_matches_pattern(subject, pattern) is expected
