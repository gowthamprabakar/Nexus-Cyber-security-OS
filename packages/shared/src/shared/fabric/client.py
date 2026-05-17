"""Async JetStream client for the F.7 fabric runtime.

Wraps `nats-py`'s async JetStream API to deliver the public surface that
[F.7 v0.1 plan Task 3](../../../../../../docs/superpowers/plans/2026-05-17-f-7-v0-1-fabric-runtime.md)
and [ADR-004](../../../../../../docs/_meta/decisions/ADR-004-fabric-layer.md)
specify, with the resolutions from the plan's Q1-Q7 questions table.

Q1 (resolved): `nats-py` (the official async Python client; pulls in
`nats.aio` under the hood). Aligns with ADR-005's async convention.

Q2 (resolved): `ensure_streams()` is idempotent on connect — checks each
`StreamSpec` against `js.stream_info()`; missing streams are created;
existing streams whose config drifts from the spec produce a
`StreamSpecMismatchError` (the client never silently overwrites).

Q3 (Task 3 baseline only): `publish()` requires an explicit
`correlation_id` kwarg; raises `MissingCorrelationIdError` if `None`.
F.7 v0.1 Task 4 will relax this to consult
`shared.fabric.correlation.current_correlation_id()` before raising
(contextvar fallback) and propagate the resolved correlation_id as a
NATS message header `Nexus-Correlation-Id`. Task 3 ships the shape;
Task 4 ships the bus-property contract.

Q5 (resolved): The OCSF v1.3 envelope is enforced on `findings.>` only,
via the typed `publish_finding()` helper. The other four streams accept
arbitrary `bytes`.

Q7 (resolved): `connect()` uses a 5-second timeout (configurable via
`__init__`); any connection failure raises `FabricConnectionError`. The
client does not silently fall back to in-process delivery or filesystem
routing — connect failure is the operator's signal that the bus isn't
reachable, not a behaviour the client compensates for.

Not in v0.1 of this module:
- KMS-signed `audit.>` messages (F.7 v0.x hardening per ADR-004).
- Tenant ACL enforcement via NATS auth tokens (F.7 v0.x hardening).
- Pull / ordered / queue-group consumer shapes — Task 3 ships durable
  push subscriptions only; the other shapes land when the first
  consumer plan needs them.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

import nats
from nats.aio.client import Client as NATSClient
from nats.aio.msg import Msg
from nats.aio.subscription import Subscription
from nats.errors import NoServersError
from nats.errors import TimeoutError as NATSTimeoutError
from nats.js import JetStreamContext
from nats.js.api import (
    DiscardPolicy as NATSDiscardPolicy,
)
from nats.js.api import (
    PubAck,
    RetentionPolicy,
    StorageType,
    StreamConfig,
)
from nats.js.errors import NotFoundError as NATSNotFoundError

from shared.fabric.envelope import NexusEnvelope, wrap_ocsf
from shared.fabric.streams import ALL_STREAMS, FINDINGS_STREAM, StreamSpec

_DEFAULT_CONNECT_TIMEOUT_SECONDS = 5
"""Q7: connect timeout (seconds). nats-py expects an int."""

_DISCARD_POLICY_MAP: dict[str, NATSDiscardPolicy] = {
    "old": NATSDiscardPolicy.OLD,
    "new": NATSDiscardPolicy.NEW,
}


class FabricConnectionError(RuntimeError):
    """`JetStreamClient.connect()` failed within the configured timeout.

    Raised when no NATS server is reachable, the connect handshake
    times out, or the broker rejects the connection. Callers decide
    retry / fallback / fail-loud policy; the client itself does not
    auto-retry or auto-fall-back to filesystem / in-process delivery.
    """


class StreamSpecMismatchError(RuntimeError):
    """An existing NATS stream's configuration drifts from the declared `StreamSpec`.

    Raised by `ensure_streams()` when the broker reports a stream with
    the same `name` but different `subjects` / `max_age` / `discard`
    policy than the in-process spec. Operators must reconcile manually
    (delete + re-create the stream, or update the declaration to match
    the broker); `ensure_streams()` does NOT overwrite a drifted stream.
    """


class MissingCorrelationIdError(ValueError):
    """`publish()` was called without a `correlation_id` kwarg.

    Task 3 baseline: this fires whenever the explicit kwarg is `None`.

    Task 4 will relax the precondition to consult
    `shared.fabric.correlation.current_correlation_id()` before raising,
    so callers running inside a `correlation_scope` can omit the kwarg.
    The exception class is shared between both versions; only the
    precondition logic changes.
    """


class JetStreamClient:
    """Async wrapper for nats-py's JetStream API.

    One instance per long-lived process. `connect()` and `close()` are
    idempotent at the lifecycle boundary; `publish()` / `subscribe()` /
    `ensure_streams()` require an active connection and raise
    `FabricConnectionError` if called before `connect()` (or after
    `close()`).
    """

    def __init__(
        self,
        servers: list[str],
        creds: str | None = None,
        connect_timeout_seconds: int = _DEFAULT_CONNECT_TIMEOUT_SECONDS,
    ) -> None:
        if not servers:
            raise ValueError("servers must be a non-empty list of NATS URIs")
        self._servers = list(servers)
        self._creds = creds
        self._connect_timeout = connect_timeout_seconds
        self._nc: NATSClient | None = None
        self._js: JetStreamContext | None = None

    @property
    def is_connected(self) -> bool:
        return self._nc is not None and self._nc.is_connected

    async def connect(self) -> None:
        """Connect to NATS and acquire a JetStream context.

        Idempotent: calling on an already-connected client is a no-op.
        Raises `FabricConnectionError` on any connection failure; does
        not auto-retry.
        """
        if self.is_connected:
            return
        connect_kwargs: dict[str, Any] = {
            "servers": self._servers,
            "connect_timeout": self._connect_timeout,
            "allow_reconnect": True,
        }
        if self._creds is not None:
            connect_kwargs["user_credentials"] = self._creds
        try:
            self._nc = await nats.connect(**connect_kwargs)
        except (TimeoutError, NoServersError, NATSTimeoutError, OSError) as exc:
            raise FabricConnectionError(
                f"failed to connect to NATS servers={self._servers!r} "
                f"within {self._connect_timeout}s: {exc}"
            ) from exc
        self._js = self._nc.jetstream()

    async def ensure_streams(
        self,
        specs: tuple[StreamSpec, ...] = ALL_STREAMS,
    ) -> None:
        """Create missing streams; verify existing streams match the spec.

        Q2: Idempotent. For each spec:
        - If the stream does not exist on the broker, it is created
          with the declared configuration.
        - If the stream exists and matches the spec on `subjects`,
          `max_age`, and `discard`, the call is a no-op for that spec.
        - If the stream exists but drifts, `StreamSpecMismatchError` is
          raised. The client does NOT overwrite drifted streams;
          operators reconcile manually.
        """
        js = self._require_js()
        for spec in specs:
            await self._ensure_one_stream(js, spec)

    @staticmethod
    async def _ensure_one_stream(js: JetStreamContext, spec: StreamSpec) -> None:
        config = JetStreamClient._spec_to_config(spec)
        try:
            info = await js.stream_info(spec.name)
        except NATSNotFoundError:
            await js.add_stream(config)
            return
        JetStreamClient._raise_if_drifted(spec, config, info.config)

    @staticmethod
    def _spec_to_config(spec: StreamSpec) -> StreamConfig:
        return StreamConfig(
            name=spec.name,
            subjects=list(spec.subjects),
            retention=RetentionPolicy.LIMITS,
            storage=StorageType.FILE,
            max_age=spec.retention_seconds,
            max_msgs_per_subject=spec.max_msgs_per_subject,
            discard=_DISCARD_POLICY_MAP[spec.discard_policy],
        )

    @staticmethod
    def _raise_if_drifted(
        spec: StreamSpec,
        declared: StreamConfig,
        existing: StreamConfig,
    ) -> None:
        drifts: list[str] = []
        if list(existing.subjects or []) != list(declared.subjects or []):
            drifts.append(f"subjects: declared={declared.subjects} existing={existing.subjects}")
        declared_max_age = declared.max_age
        existing_max_age = existing.max_age
        if (
            declared_max_age is not None
            and existing_max_age is not None
            and int(existing_max_age) != int(declared_max_age)
        ):
            drifts.append(f"max_age: declared={declared_max_age}s existing={existing_max_age}s")
        if existing.discard != declared.discard:
            drifts.append(f"discard: declared={declared.discard} existing={existing.discard}")
        if drifts:
            raise StreamSpecMismatchError(
                f"stream {spec.name!r} on the broker drifts from the declared "
                f"StreamSpec: {'; '.join(drifts)}. Manual reconciliation required "
                f"(ensure_streams does not overwrite drifted streams)."
            )

    async def publish(
        self,
        stream: StreamSpec,
        subject: str,
        message: bytes,
        *,
        correlation_id: str | None = None,
    ) -> PubAck:
        """Publish a raw bytes message to a stream.

        Q3 (Task 3 baseline): `correlation_id` must be supplied as an
        explicit kwarg; raises `MissingCorrelationIdError` if `None`.
        Task 4 will relax this to consult the contextvar before raising
        AND set the resolved id as a `Nexus-Correlation-Id` header on
        the outbound message.

        Q5: `message` is arbitrary bytes for the four non-findings
        streams (`events.>` / `commands.>` / `approvals.>` / `audit.>`).
        Use `publish_finding()` to publish to `findings.>` — that
        helper enforces the OCSF v1.3 envelope.

        Subject validation: the subject must start with the stream's
        root name + `"."` (e.g., `events.tenant.xyz.foo` for the events
        stream). Cross-stream subject reuse is rejected at the publish
        boundary so a typo can't silently route to the wrong stream.
        """
        if correlation_id is None:
            raise MissingCorrelationIdError(
                "publish() requires an explicit correlation_id kwarg "
                "(Task 3 baseline; Task 4 will fall back to "
                "shared.fabric.correlation.current_correlation_id())"
            )
        expected_prefix = stream.name + "."
        if not subject.startswith(expected_prefix):
            raise ValueError(
                f"subject {subject!r} does not match stream {stream.name!r}; "
                f"expected prefix {expected_prefix!r}"
            )
        js = self._require_js()
        return await js.publish(subject, message, stream=stream.name)

    async def publish_finding(
        self,
        subject: str,
        ocsf_event: dict[str, Any],
        envelope: NexusEnvelope,
    ) -> PubAck:
        """Publish an OCSF v1.3 finding to `findings.>`.

        Wraps `ocsf_event` via `NexusEnvelope` before JSON-encoding and
        publishing. Per Q5, the OCSF envelope is enforced on
        `findings.>` only — other streams use the raw `publish()` path.

        The envelope's `correlation_id` is propagated to `publish()`'s
        kwarg, which means a single `publish_finding()` call satisfies
        the correlation_id precondition without the caller needing to
        pass it twice.
        """
        if not subject.startswith("findings."):
            raise ValueError(f"publish_finding() requires a findings.* subject; got {subject!r}")
        wrapped = wrap_ocsf(ocsf_event, envelope)
        payload = json.dumps(wrapped, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return await self.publish(
            FINDINGS_STREAM,
            subject,
            payload,
            correlation_id=envelope.correlation_id,
        )

    async def subscribe(
        self,
        stream: StreamSpec,
        subject_filter: str,
        callback: Callable[[Msg], Awaitable[None]],
        *,
        durable_name: str,
    ) -> Subscription:
        """Subscribe with a durable push consumer.

        `durable_name` is required: F.7 v0.1's named-bus semantics
        (especially `approvals.>` "outlives reconnects" and `audit.>`
        "mirrored upstream") require durable consumers. Ephemeral and
        pull / ordered / queue-group consumers land when their first
        consumer's plan needs them.

        `subject_filter` must lie under the stream's root; cross-stream
        subscription is rejected to prevent the same typo class
        `publish()` rejects.
        """
        expected_prefix = stream.name + "."
        if not subject_filter.startswith(expected_prefix) and subject_filter != stream.name:
            raise ValueError(
                f"subject_filter {subject_filter!r} does not lie under stream "
                f"{stream.name!r}; expected prefix {expected_prefix!r}"
            )
        if not durable_name:
            raise ValueError("durable_name must be a non-empty string")
        js = self._require_js()
        return await js.subscribe(
            subject_filter,
            cb=callback,
            durable=durable_name,
            stream=stream.name,
        )

    async def close(self) -> None:
        """Drain and close the underlying NATS connection.

        Idempotent: calling on an already-closed client is a no-op.
        After `close()`, subsequent `publish()` / `subscribe()` /
        `ensure_streams()` calls raise `FabricConnectionError`.
        """
        if self._nc is not None:
            await self._nc.close()
        self._nc = None
        self._js = None

    def _require_js(self) -> JetStreamContext:
        if self._js is None:
            raise FabricConnectionError(
                "JetStreamClient is not connected; call `await connect()` first"
            )
        return self._js
