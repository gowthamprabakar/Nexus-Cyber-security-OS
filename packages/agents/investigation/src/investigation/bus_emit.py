"""D.7 bus-emit helper for F.7 v0.2 lifecycle events on `events.>`.

Wraps F.7 v0.1's `JetStreamClient` with D.7-specific event-shape helpers:
`emit_started(...)`, `emit_completed(...)`, `emit_failed(...)`. The agent
driver invokes these at Stage-1 SCOPE entry and Stage-6 HANDOFF exit
(success and failure paths) when the `--publish-events-to-bus` flag is on.

**Non-fatal by design (F.7 v0.2 plan Q4).** Every emit method catches
publish failures (`FabricConnectionError`, `MissingCorrelationIdError`,
network exceptions) and records `investigation.bus_publish.failure` to
the F.6 audit chain. The investigation continues; D.7's 4 filesystem
artifacts are still written. A broken bus does NOT break D.7's
"filesystem artifacts are the contract" guarantee.

**Audit action vocabulary (ADR-010 condition 4 — additive only).** Three
new action types added to D.7's chain vocabulary:

- `investigation.bus_publish.attempt` — emitted before each publish call.
- `investigation.bus_publish.success` — emitted after a successful publish;
  payload carries the resolved subject + PubAck stream/seq for forensic
  reconstruction.
- `investigation.bus_publish.failure` — emitted after a failed publish;
  payload carries the exception class + message.

No existing audit action is renamed, removed, or repurposed.

**Watch-item HELD (D.7 only consumes F.7 v0.1's public API).** This
module IMPORTS from `shared.fabric` (the F.7 v0.1 substrate) but does
NOT modify it. The substrate is treated as a sealed public surface.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from shared.fabric import (
    EVENTS_STREAM,
    FabricConnectionError,
    JetStreamClient,
    MissingCorrelationIdError,
    events_subject,
)
from ulid import ULID

from investigation.schemas import InvestigationLifecycleEvent

if TYPE_CHECKING:
    from charter.audit import AuditLog

_LOG = logging.getLogger(__name__)


# ----------------------------------------------------------------------------
# Audit action vocabulary — F.7 v0.2 additive extension to D.7's chain.
# Per ADR-010 condition 4: new types only; no existing type renamed.
# ----------------------------------------------------------------------------

BUS_PUBLISH_ATTEMPT_ACTION = "investigation.bus_publish.attempt"
"""Emitted to the F.6 chain BEFORE each bus-publish attempt."""

BUS_PUBLISH_SUCCESS_ACTION = "investigation.bus_publish.success"
"""Emitted to the F.6 chain AFTER a successful publish. Payload carries
the resolved subject, publish stream/seq, and the lifecycle event_type."""

BUS_PUBLISH_FAILURE_ACTION = "investigation.bus_publish.failure"
"""Emitted to the F.6 chain when a publish fails. Payload carries the
exception class name, message, and the lifecycle event_type that was
being published. Investigation continues despite this event."""


def mint_investigation_id() -> str:
    """Mint a fresh investigation_id (26-char ULID) at Stage-1 entry.

    Distinct from `IncidentReport.incident_id` (which identifies the
    produced incident artefact, minted at Stage-6 `_build_incident_report`).
    The `investigation_id` identifies the PROCESS / RUN; consumers
    correlate process events via the `Nexus-Correlation-Id` header
    rather than this id directly.
    """
    return str(ULID())


class BusEmitter:
    """Owns the bus-publish lifecycle for one D.7 investigation run.

    Construction: `BusEmitter(servers=[...])` — the client is built but
    not connected. Call `connect()` once before the first `emit_*`. If
    the connect raises `FabricConnectionError`, the emitter remains in
    a "not-connected" state and subsequent `emit_*` calls will see a
    publish failure (caught + recorded as `bus_publish.failure`; the
    investigation continues).

    Lifecycle: one BusEmitter per investigation run; `close()` is safe
    to call at the end whether or not connect succeeded.
    """

    def __init__(
        self,
        *,
        servers: list[str],
        client: JetStreamClient | None = None,
    ) -> None:
        if not servers:
            raise ValueError("servers must be a non-empty list of NATS URIs")
        # The `client` kwarg exists for test injection. Production passes
        # only `servers` and gets a real JetStreamClient.
        self._client = client if client is not None else JetStreamClient(servers=servers)

    async def connect(self) -> None:
        """Connect to NATS. Best-effort — exceptions are logged and
        swallowed so the investigation proceeds. Subsequent emit calls
        will see "not connected" and record the failure to the chain.
        """
        try:
            await self._client.connect()
        except FabricConnectionError as exc:
            _LOG.warning(
                "bus_emit: connect failed (%s); subsequent emits will be no-ops",
                exc,
            )

    async def close(self) -> None:
        """Drain and close. Safe to call regardless of connect state."""
        try:
            await self._client.close()
        except Exception as exc:
            _LOG.warning("bus_emit: close failed (%s); ignored", exc)

    async def emit_started(
        self,
        *,
        audit_log: AuditLog,
        tenant_id: str,
        correlation_id: str,
        investigation_id: str,
    ) -> None:
        """Emit `investigation.started` at Stage-1 SCOPE entry."""
        event = InvestigationLifecycleEvent(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            event_type="started",
            emitted_at=datetime.now(UTC),
        )
        await self._publish(audit_log=audit_log, event=event)

    async def emit_completed(
        self,
        *,
        audit_log: AuditLog,
        tenant_id: str,
        correlation_id: str,
        investigation_id: str,
    ) -> None:
        """Emit `investigation.completed` at Stage-6 HANDOFF success."""
        event = InvestigationLifecycleEvent(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            event_type="completed",
            emitted_at=datetime.now(UTC),
        )
        await self._publish(audit_log=audit_log, event=event)

    async def emit_failed(
        self,
        *,
        audit_log: AuditLog,
        tenant_id: str,
        correlation_id: str,
        investigation_id: str,
        stage: str,
        error_class: str,
    ) -> None:
        """Emit `investigation.failed` when a pipeline stage raises.

        Called best-effort from the agent driver's exception handler.
        Never raises — exceptions are caught + recorded; the original
        D.7 failure propagates from the caller, not from this method.
        """
        event = InvestigationLifecycleEvent(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            event_type="failed",
            stage=stage,
            error_class=error_class,
            emitted_at=datetime.now(UTC),
        )
        await self._publish(audit_log=audit_log, event=event)

    async def _publish(
        self,
        *,
        audit_log: AuditLog,
        event: InvestigationLifecycleEvent,
    ) -> None:
        """Publish one lifecycle event with non-fatal failure handling.

        Records the F.6 audit chain entries (`attempt` → `success` |
        `failure`). Never raises — publish failures are caught + logged
        + recorded; the investigation continues.
        """
        # Build the F.7 v0.2 Q2 subject `events.tenant.<tid>.investigation.<event_type>`.
        # The shared helper enforces tenant_id validation but expects a
        # single-token suffix (`^[A-Za-z0-9_-]+$`). Use it for the
        # `investigation` segment (which validates tenant_id), then
        # append the event_type token explicitly. event_type is a
        # closed Literal ("started"/"completed"/"failed") so it cannot
        # smuggle dots or other NATS-meta characters.
        subject = f"{events_subject(event.tenant_id, 'investigation')}.{event.event_type}"
        attempt_payload: dict[str, Any] = {
            "event_type": event.event_type,
            "subject": subject,
            "investigation_id": event.investigation_id,
        }
        audit_log.append(action=BUS_PUBLISH_ATTEMPT_ACTION, payload=attempt_payload)
        try:
            ack = await self._client.publish(
                EVENTS_STREAM,
                subject,
                event.to_payload_bytes(),
                correlation_id=event.correlation_id,
            )
        except (
            FabricConnectionError,
            MissingCorrelationIdError,
            OSError,
            ValueError,
        ) as exc:
            _LOG.warning(
                "bus_emit: publish %s failed (%s: %s); investigation continues",
                event.event_type,
                exc.__class__.__name__,
                exc,
            )
            audit_log.append(
                action=BUS_PUBLISH_FAILURE_ACTION,
                payload={
                    "event_type": event.event_type,
                    "subject": subject,
                    "investigation_id": event.investigation_id,
                    "exception_class": exc.__class__.__name__,
                    "message": str(exc),
                },
            )
            return
        # Success path: record the PubAck for forensic reconstruction.
        ack_stream = getattr(ack, "stream", None)
        ack_seq = getattr(ack, "seq", None)
        audit_log.append(
            action=BUS_PUBLISH_SUCCESS_ACTION,
            payload={
                "event_type": event.event_type,
                "subject": subject,
                "investigation_id": event.investigation_id,
                "ack_stream": ack_stream,
                "ack_seq": ack_seq,
            },
        )


__all__ = [
    "BUS_PUBLISH_ATTEMPT_ACTION",
    "BUS_PUBLISH_FAILURE_ACTION",
    "BUS_PUBLISH_SUCCESS_ACTION",
    "BusEmitter",
    "mint_investigation_id",
]
