"""Nexus fabric primitives — subjects, OCSF envelope, correlation_id.

Phase-1a slice (per ADR-004):
- subjects.py: pure subject builders for the five buses (events, findings,
  commands, approvals, audit). No NATS dependency.
- envelope.py: OCSF v1.3 base event + nexus_envelope extension wrap/unwrap.
- correlation.py: ULID-based correlation_id generator + asyncio-task-isolated
  contextvar.

The actual NATS JetStream client is deferred to E.2 / control-plane consumer.
This package codifies the schema and the IDs now so every agent can attach
correlation_id and emit OCSF-shaped findings before the broker exists.
"""

from shared.fabric.correlation import (
    correlation_scope,
    current_correlation_id,
    new_correlation_id,
)
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf, wrap_ocsf
from shared.fabric.subjects import (
    approvals_subject,
    audit_subject,
    commands_subject,
    events_subject,
    findings_subject,
)

__all__ = [
    "NexusEnvelope",
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
