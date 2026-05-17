"""StreamSpec declarations for the five ADR-004 buses.

Pure declarations — no NATS dependency, no client behaviour. The
`JetStreamClient.ensure_streams()` async method (Task 3 of the F.7 v0.1
plan) consumes these specs to create / verify JetStream streams.

Cross-references:
- ADR-004 §"The five buses": ../../../../../../docs/_meta/decisions/ADR-004-fabric-layer.md
- F.7 v0.1 plan resolved Q2 (ensure_streams idempotent + drift detection)
  and Q5 (OCSF envelope on `findings.>` only; the other four streams
  accept arbitrary bytes).
- Subject builders in `shared.fabric.subjects` realize the per-stream
  ordering granularity ADR-004 prescribes (per-tenant per-asset,
  per-edge, etc.) via subject hierarchy; the stream-config side is
  declared here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

DiscardPolicy = Literal["old", "new"]


@dataclass(frozen=True, slots=True)
class StreamSpec:
    """One JetStream stream declaration matching ADR-004's bus table.

    Frozen because specs are compared against existing NATS streams at
    `ensure_streams()` time; post-construction mutation would diverge
    in-process declarations from broker state and surface as a confusing
    `StreamSpecMismatchError`.

    Fields:
        name: JetStream stream name. Conventionally the bus root without
            wildcards (e.g., `"events"`).
        subjects: Subject patterns this stream catches. Almost always a
            single ADR-004 root pattern such as `("events.>",)`.
        retention_seconds: Time-based retention. Mirrors ADR-004's
            "Retention" column verbatim.
        max_msgs_per_subject: NATS per-subject quota. `-1` = unlimited.
            v0.1 ships unlimited for all five streams; production-tuning
            is deferred per the F.7 v0.1 plan's Defers table.
        discard_policy: Behaviour when the stream is at its limit.
            `"old"` (drop oldest) is correct for all five v0.1 streams;
            `"new"` (refuse publishes) is reserved for F.7 v0.x audit
            hardening.

    Note on ordering. ADR-004's "Ordering" column (per-subject /
    per-tenant per-asset / per-edge / strict per-finding / strict
    per-tenant) describes the FIFO granularity each bus delivers.
    JetStream provides per-subject FIFO unconditionally; the named
    granularity is realized by `shared.fabric.subjects`' subject design,
    not by a stream-config flag.
    """

    name: str
    subjects: tuple[str, ...]
    retention_seconds: int
    max_msgs_per_subject: int
    discard_policy: DiscardPolicy


_SECONDS_PER_DAY = 86_400
_DAYS_PER_YEAR = 365


EVENTS_STREAM: StreamSpec = StreamSpec(
    name="events",
    subjects=("events.>",),
    retention_seconds=7 * _SECONDS_PER_DAY,
    max_msgs_per_subject=-1,
    discard_policy="old",
)

FINDINGS_STREAM: StreamSpec = StreamSpec(
    name="findings",
    subjects=("findings.>",),
    retention_seconds=90 * _SECONDS_PER_DAY,
    max_msgs_per_subject=-1,
    discard_policy="old",
)

COMMANDS_STREAM: StreamSpec = StreamSpec(
    name="commands",
    subjects=("commands.>",),
    retention_seconds=30 * _SECONDS_PER_DAY,
    max_msgs_per_subject=-1,
    discard_policy="old",
)

APPROVALS_STREAM: StreamSpec = StreamSpec(
    name="approvals",
    subjects=("approvals.>",),
    retention_seconds=365 * _SECONDS_PER_DAY,
    max_msgs_per_subject=-1,
    discard_policy="old",
)

AUDIT_STREAM: StreamSpec = StreamSpec(
    name="audit",
    subjects=("audit.>",),
    retention_seconds=7 * _DAYS_PER_YEAR * _SECONDS_PER_DAY,
    max_msgs_per_subject=-1,
    discard_policy="old",
)


ALL_STREAMS: tuple[StreamSpec, ...] = (
    EVENTS_STREAM,
    FINDINGS_STREAM,
    COMMANDS_STREAM,
    APPROVALS_STREAM,
    AUDIT_STREAM,
)
"""All five ADR-004 streams in declaration order.

Order mirrors ADR-004's "The five buses" table top-to-bottom for review
ergonomics. Consumers should not depend on this order semantically.
"""
