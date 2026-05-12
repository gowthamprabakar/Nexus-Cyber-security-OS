"""Timeline reconstruction — deterministic event sorter (D.7 Task 9).

Takes heterogeneous inputs (F.6 `AuditEvent`s, sibling-agent
`RelatedFinding`s, sub-agent-supplied `TimelineEvent`s) and merges
them into a single sorted `Timeline`. The `Timeline` pydantic model
(Task 2) sorts ascending by `emitted_at` at construction, so the
output ordering is stable regardless of input ordering.

Pure function — no I/O, no async, no LLM. Called from the agent
driver's Stage 3 (SYNTHESIZE) after sub-investigations return their
per-flavor evidence.

**Forgiving on bad inputs.** A `RelatedFinding` whose payload lacks
a `time` field can't be placed in the timeline — drop it with a
logged warning rather than fabricating a timestamp. Audit events
always carry `emitted_at` (pydantic-validated upstream).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from audit.schemas import AuditEvent

from investigation.schemas import Timeline, TimelineEvent
from investigation.tools.related_findings import RelatedFinding

_LOG = logging.getLogger(__name__)


def reconstruct_timeline(
    *,
    audit_events: Sequence[AuditEvent],
    related_findings: Sequence[RelatedFinding],
    extra_events: Sequence[TimelineEvent],
) -> Timeline:
    """Merge heterogeneous events into a sorted `Timeline`."""
    converted: list[TimelineEvent] = []

    for ae in audit_events:
        converted.append(_from_audit_event(ae))

    for finding in related_findings:
        event = _from_related_finding(finding)
        if event is not None:
            converted.append(event)

    converted.extend(extra_events)

    return Timeline(events=tuple(converted))


def _from_audit_event(ae: AuditEvent) -> TimelineEvent:
    summary = ae.action
    if ae.payload:
        # Keep description compact — top-level keys are enough.
        keys = ", ".join(sorted(ae.payload.keys()))
        summary = f"{ae.action} ({keys})"
    # SQLite drops tz on TIMESTAMPTZ round-trip; pin to UTC so the
    # Timeline sorter can compare against tz-aware finding events.
    emitted_at = ae.emitted_at
    if emitted_at.tzinfo is None:
        emitted_at = emitted_at.replace(tzinfo=UTC)
    return TimelineEvent(
        emitted_at=emitted_at,
        source="audit",
        actor=ae.agent_id,
        action=ae.action,
        # We don't have a raw audit_event_id in the AuditEvent pydantic
        # shape (it's allocated by AuditStore on ingest). Use the
        # entry_hash truncated as a stable identifier.
        evidence_ref=f"audit_event:{ae.entry_hash[:16]}",
        description=summary,
    )


def _from_related_finding(finding: RelatedFinding) -> TimelineEvent | None:
    payload = finding.payload
    finding_info = payload.get("finding_info", {}) or {}
    uid = str(finding_info.get("uid", ""))
    if not uid:
        # Without a uid we can't reference the finding from the
        # incident report. Skip rather than fabricate.
        return None

    emitted_at = _parse_time_ms(payload.get("time"))
    if emitted_at is None:
        _LOG.warning(
            "skipping related finding %s — payload has no parseable `time` field",
            uid,
        )
        return None

    title = finding_info.get("title")
    if not isinstance(title, str) or not title:
        title = str(payload.get("class_name") or payload.get("class_uid") or "finding")

    return TimelineEvent(
        emitted_at=emitted_at,
        source="finding",
        actor=finding.source_agent,
        action=str(payload.get("class_name", "finding")),
        evidence_ref=f"finding:{uid}",
        description=title,
    )


def _parse_time_ms(value: Any) -> datetime | None:
    """OCSF `time` is milliseconds since epoch. Parse, with tolerance."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value / 1000.0, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    return None


__all__ = ["reconstruct_timeline"]
