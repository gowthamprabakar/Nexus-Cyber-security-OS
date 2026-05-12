"""Tests for `investigation.timeline.reconstruct_timeline` (D.7 Task 9).

Deterministic event-sorter. Takes a heterogeneous input mix
(`AuditEvent`s from F.6, `RelatedFinding`s from sibling agents,
loose `TimelineEvent`s passed in by sub-agents) and produces a single
sorted `Timeline`. The wire shape is stable across ingest orderings
because `Timeline.__post_init__` sorts by `emitted_at` ascending.

Production contract:

- `reconstruct_timeline(audit_events, related_findings, extra_events)`
  is a pure function — no I/O, no async.
- Each `AuditEvent` becomes a `TimelineEvent` with
  `source="audit"`, `actor=audit_event.agent_id`,
  `action=audit_event.action`, `evidence_ref="audit_event:<id>"`,
  `description=audit_event.action + payload summary`.
- Each `RelatedFinding` becomes a `TimelineEvent` with
  `source="finding"`, `actor=finding.source_agent`, derived action
  from the finding payload, `evidence_ref="finding:<uid>"`,
  `description=` the OCSF `finding_info.title` (or class_name).
- `extra_events: Sequence[TimelineEvent]` are passed through and
  merge into the same sorted timeline.
- Tolerates missing `emitted_at` on `RelatedFinding` — drops with a
  logged warning rather than raising.
- Empty input → empty `Timeline`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from audit.schemas import AuditEvent
from investigation.schemas import TimelineEvent
from investigation.timeline import reconstruct_timeline
from investigation.tools.related_findings import RelatedFinding

_TENANT_A = "01HV0T0000000000000000TENA"


def _audit_event(*, seed: int, emitted_at: datetime, action: str = "x") -> AuditEvent:
    h_prev = f"{seed:064x}"
    h_entry = f"{seed + 1:064x}"
    return AuditEvent(
        tenant_id=_TENANT_A,
        correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        agent_id="cloud_posture",
        action=action,
        payload={"seed": seed},
        previous_hash=h_prev,
        entry_hash=h_entry,
        emitted_at=emitted_at,
        source=f"jsonl:fixture/{seed}",
    )


def _related_finding(
    *,
    finding_uid: str,
    emitted_at: datetime,
    title: str = "S3 bucket public",
) -> RelatedFinding:
    return RelatedFinding(
        source_agent="cloud_posture",
        source_run_id="run-001",
        class_uid=2003,
        payload={
            "class_uid": 2003,
            "class_name": "Compliance Finding",
            "finding_info": {"uid": finding_uid, "title": title},
            "time": int(emitted_at.timestamp() * 1000),
        },
    )


_BASE = datetime(2026, 5, 12, tzinfo=UTC)


# ---------------------------- empty input -----------------------------


def test_empty_input_returns_empty_timeline() -> None:
    timeline = reconstruct_timeline(audit_events=(), related_findings=(), extra_events=())
    assert timeline.events == ()


# ---------------------------- audit events ----------------------------


def test_audit_event_becomes_timeline_event() -> None:
    timeline = reconstruct_timeline(
        audit_events=(_audit_event(seed=1, emitted_at=_BASE),),
        related_findings=(),
        extra_events=(),
    )
    assert len(timeline.events) == 1
    e = timeline.events[0]
    assert e.source == "audit"
    assert e.actor == "cloud_posture"
    assert e.evidence_ref.startswith("audit_event:")
    assert e.emitted_at == _BASE


def test_audit_events_carry_action_into_description() -> None:
    timeline = reconstruct_timeline(
        audit_events=(_audit_event(seed=1, emitted_at=_BASE, action="finding.created"),),
        related_findings=(),
        extra_events=(),
    )
    e = timeline.events[0]
    assert "finding.created" in e.description
    assert e.action == "finding.created"


# ---------------------------- related findings -----------------------


def test_related_finding_becomes_timeline_event() -> None:
    timeline = reconstruct_timeline(
        audit_events=(),
        related_findings=(
            _related_finding(finding_uid="F-1", emitted_at=_BASE, title="Public bucket"),
        ),
        extra_events=(),
    )
    assert len(timeline.events) == 1
    e = timeline.events[0]
    assert e.source == "finding"
    assert e.actor == "cloud_posture"
    assert e.evidence_ref == "finding:F-1"
    assert "Public bucket" in e.description


def test_related_finding_missing_timestamp_is_dropped() -> None:
    """`time` field missing from the payload → no timestamp → drop the
    finding from the timeline. Don't raise.
    """
    bad = RelatedFinding(
        source_agent="cloud_posture",
        source_run_id="run-001",
        class_uid=2003,
        payload={
            "class_uid": 2003,
            "finding_info": {"uid": "F-bad", "title": "no time"},
            # No "time" field.
        },
    )
    timeline = reconstruct_timeline(
        audit_events=(),
        related_findings=(bad,),
        extra_events=(),
    )
    assert timeline.events == ()


def test_related_finding_falls_back_to_class_name_when_title_missing() -> None:
    finding = RelatedFinding(
        source_agent="identity",
        source_run_id="run-002",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "finding_info": {"uid": "ID-1"},  # no title
            "time": int(_BASE.timestamp() * 1000),
        },
    )
    timeline = reconstruct_timeline(audit_events=(), related_findings=(finding,), extra_events=())
    assert "Detection Finding" in timeline.events[0].description


# ---------------------------- extra events ----------------------------


def test_extra_timeline_events_pass_through() -> None:
    extra = TimelineEvent(
        emitted_at=_BASE,
        source="sub_agent",
        actor="ioc_pivot",
        action="virustotal_lookup",
        evidence_ref="sub:abc123",
        description="VT confirmed malicious hash",
    )
    timeline = reconstruct_timeline(
        audit_events=(),
        related_findings=(),
        extra_events=(extra,),
    )
    assert timeline.events == (extra,)


# ---------------------------- sorting ---------------------------------


def test_merges_all_sources_sorted_ascending() -> None:
    e1 = _BASE
    e2 = _BASE + timedelta(seconds=30)
    e3 = _BASE + timedelta(minutes=1)
    e4 = _BASE + timedelta(minutes=2)

    timeline = reconstruct_timeline(
        audit_events=(
            _audit_event(seed=1, emitted_at=e3),
            _audit_event(seed=3, emitted_at=e1),
        ),
        related_findings=(_related_finding(finding_uid="F-1", emitted_at=e2),),
        extra_events=(
            TimelineEvent(
                emitted_at=e4,
                source="sub_agent",
                actor="x",
                action="y",
                evidence_ref="sub:1",
                description="z",
            ),
        ),
    )
    assert [ev.emitted_at for ev in timeline.events] == [e1, e2, e3, e4]


def test_sources_are_labelled_correctly_after_merge() -> None:
    timeline = reconstruct_timeline(
        audit_events=(_audit_event(seed=1, emitted_at=_BASE),),
        related_findings=(
            _related_finding(finding_uid="F-1", emitted_at=_BASE + timedelta(seconds=1)),
        ),
        extra_events=(
            TimelineEvent(
                emitted_at=_BASE + timedelta(seconds=2),
                source="sub_agent",
                actor="x",
                action="y",
                evidence_ref="sub:1",
                description="z",
            ),
        ),
    )
    sources = [e.source for e in timeline.events]
    assert sources == ["audit", "finding", "sub_agent"]


# ---------------------------- output type -----------------------------


def test_returns_timeline_pydantic_model() -> None:
    from investigation.schemas import Timeline

    timeline = reconstruct_timeline(audit_events=(), related_findings=(), extra_events=())
    assert isinstance(timeline, Timeline)
