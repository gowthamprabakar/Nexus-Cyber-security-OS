"""Nexus fabric primitives — subjects, OCSF envelope, correlation_id, streams, client.

Phase-1a slice (per ADR-004 + ADR-012):
- subjects.py: pure subject builders for the six buses (events, findings,
  commands, approvals, audit, claims). No NATS dependency.
- envelope.py: OCSF v1.3 base event + nexus_envelope extension wrap/unwrap.
- correlation.py: ULID-based correlation_id generator + asyncio-task-isolated
  contextvar.
- streams.py: `StreamSpec` declarations for the six fabric buses.
  ADR-012 added `CLAIMS_STREAM` for agent-proposed speculative state.
- client.py: async `JetStreamClient` wrapping `nats-py`'s JetStream API
  (F.7 v0.1 Task 3). `connect()` / `ensure_streams()` / `publish()` /
  `subscribe()` / `close()` plus typed exceptions.

F.7 v0.1 Task 4 will layer `correlation_id`-as-bus-property enforcement
on top of `publish()` (contextvar fallback + header propagation); Task 3
ships the explicit-kwarg baseline.
"""

from shared.fabric.client import (
    CORRELATION_ID_HEADER,
    FabricConnectionError,
    ForbiddenSubscriptionError,
    JetStreamClient,
    MissingCorrelationIdError,
    StreamSpecMismatchError,
)
from shared.fabric.correlation import (
    correlation_scope,
    current_correlation_id,
    new_correlation_id,
)
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf
from shared.fabric.streams import (
    ALL_STREAMS,
    APPROVALS_STREAM,
    AUDIT_STREAM,
    CLAIMS_STREAM,
    COMMANDS_STREAM,
    EVENTS_STREAM,
    FINDINGS_STREAM,
    DiscardPolicy,
    StreamSpec,
)
from shared.fabric.subjects import (
    approvals_subject,
    audit_subject,
    claims_subject,
    commands_subject,
    events_subject,
    findings_subject,
)

__all__ = [
    "ALL_STREAMS",
    "APPROVALS_STREAM",
    "AUDIT_STREAM",
    "CLAIMS_STREAM",
    "COMMANDS_STREAM",
    "CORRELATION_ID_HEADER",
    "EVENTS_STREAM",
    "FINDINGS_STREAM",
    "DiscardPolicy",
    "FabricConnectionError",
    "ForbiddenSubscriptionError",
    "JetStreamClient",
    "MissingCorrelationIdError",
    "NexusEnvelope",
    "StreamSpec",
    "StreamSpecMismatchError",
    "approvals_subject",
    "audit_subject",
    "claims_subject",
    "commands_subject",
    "correlation_scope",
    "current_correlation_id",
    "events_subject",
    "findings_subject",
    "new_correlation_id",
    "unwrap_ocsf",
    "wrap_ocsf",
]
