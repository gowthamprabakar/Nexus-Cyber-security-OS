"""Nexus fabric primitives — subjects, OCSF envelope, correlation_id, streams.

Phase-1a slice (per ADR-004):
- subjects.py: pure subject builders for the five buses (events, findings,
  commands, approvals, audit). No NATS dependency.
- envelope.py: OCSF v1.3 base event + nexus_envelope extension wrap/unwrap.
- correlation.py: ULID-based correlation_id generator + asyncio-task-isolated
  contextvar.
- streams.py: `StreamSpec` declarations for the five ADR-004 buses
  (F.7 v0.1 Task 2). Pure declarations; consumed by `JetStreamClient.
  ensure_streams()` (F.7 v0.1 Task 3).

The NATS JetStream client lands in F.7 v0.1 Task 3 (`client.py`). This
package codifies the schema, the IDs, and the stream declarations so
every agent can attach correlation_id, emit OCSF-shaped findings, and
target a known stream before / independent of the broker connection.
"""

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
    COMMANDS_STREAM,
    EVENTS_STREAM,
    FINDINGS_STREAM,
    DiscardPolicy,
    StreamSpec,
)
from shared.fabric.subjects import (
    approvals_subject,
    audit_subject,
    commands_subject,
    events_subject,
    findings_subject,
)

__all__ = [
    "ALL_STREAMS",
    "APPROVALS_STREAM",
    "AUDIT_STREAM",
    "COMMANDS_STREAM",
    "EVENTS_STREAM",
    "FINDINGS_STREAM",
    "DiscardPolicy",
    "NexusEnvelope",
    "StreamSpec",
    "approvals_subject",
    "audit_subject",
    "commands_subject",
    "correlation_scope",
    "current_correlation_id",
    "events_subject",
    "findings_subject",
    "new_correlation_id",
    "unwrap_ocsf",
    "wrap_ocsf",
]
