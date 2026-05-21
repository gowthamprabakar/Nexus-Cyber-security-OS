"""Tests for StreamSpec declarations (per ADR-004 + ADR-012 + F.7 v0.1 plan Task 2).

The `ADR_TABLE` constant below is the ADR-004 "The five buses" table +
ADR-012's claims row encoded as test data. Any divergence between the
table and the StreamSpec declarations is a contract violation; updating
either side requires updating the other in the same PR + a doc note in
the relevant ADR if the change is semantic, not just a typo.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
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

ADR_TABLE = {
    "events": {
        "subject_pattern": "events.>",
        "retention_days": 7,
        "ordering": "per-subject",
    },
    "findings": {
        "subject_pattern": "findings.>",
        "retention_days": 90,  # 90 days hot; S3 cold tiering deferred
        "ordering": "per-tenant per-asset",
    },
    "commands": {
        "subject_pattern": "commands.>",
        "retention_days": 30,
        "ordering": "per-edge",
    },
    "approvals": {
        "subject_pattern": "approvals.>",
        "retention_days": 365,
        "ordering": "strict per-finding",
    },
    "audit": {
        "subject_pattern": "audit.>",
        "retention_days": 7 * 365,  # 7 years rendered as 365-day years
        "ordering": "strict per-tenant",
    },
    "claims": {  # ADR-012
        "subject_pattern": "claims.>",
        "retention_days": 30,
        "ordering": "per-tenant per-agent",
    },
}


_NAMED_STREAMS = [
    ("events", EVENTS_STREAM),
    ("findings", FINDINGS_STREAM),
    ("commands", COMMANDS_STREAM),
    ("approvals", APPROVALS_STREAM),
    ("audit", AUDIT_STREAM),
    ("claims", CLAIMS_STREAM),
]


@pytest.fixture(params=_NAMED_STREAMS, ids=[n for n, _ in _NAMED_STREAMS])
def named_stream(request: pytest.FixtureRequest) -> tuple[str, StreamSpec]:
    return request.param  # type: ignore[no-any-return]


def test_streamspec_is_frozen() -> None:
    with pytest.raises(FrozenInstanceError):
        EVENTS_STREAM.name = "mutated"  # type: ignore[misc]


def test_streamspec_is_hashable() -> None:
    bucket = {EVENTS_STREAM, FINDINGS_STREAM, COMMANDS_STREAM}
    assert len(bucket) == 3


def test_name_matches_adr004_root(named_stream: tuple[str, StreamSpec]) -> None:
    name, spec = named_stream
    assert spec.name == name


def test_subject_pattern_matches_adr(named_stream: tuple[str, StreamSpec]) -> None:
    name, spec = named_stream
    expected = ADR_TABLE[name]["subject_pattern"]
    assert spec.subjects == (expected,)


def test_retention_seconds_matches_adr_days(
    named_stream: tuple[str, StreamSpec],
) -> None:
    name, spec = named_stream
    expected_days = ADR_TABLE[name]["retention_days"]
    assert spec.retention_seconds == expected_days * 86_400


def test_all_streams_have_unlimited_messages_per_subject(
    named_stream: tuple[str, StreamSpec],
) -> None:
    _, spec = named_stream
    assert spec.max_msgs_per_subject == -1


def test_all_streams_use_old_discard_policy(
    named_stream: tuple[str, StreamSpec],
) -> None:
    _, spec = named_stream
    assert spec.discard_policy == "old"


def test_all_streams_contains_six_specs() -> None:
    """ADR-004 declared 5; ADR-012 amended to 6 (added claims.>)."""
    assert len(ALL_STREAMS) == 6


def test_all_streams_declaration_order_mirrors_adrs() -> None:
    assert [s.name for s in ALL_STREAMS] == list(ADR_TABLE.keys())


def test_no_duplicate_stream_names() -> None:
    names = [s.name for s in ALL_STREAMS]
    assert len(set(names)) == len(names)


def test_no_overlapping_subject_roots() -> None:
    roots = {subj.split(".", 1)[0] for spec in ALL_STREAMS for subj in spec.subjects}
    assert roots == {"events", "findings", "commands", "approvals", "audit", "claims"}


def test_audit_retention_is_seven_years_in_seconds() -> None:
    assert AUDIT_STREAM.retention_seconds == 7 * 365 * 86_400


def test_findings_retention_is_ninety_days_in_seconds() -> None:
    assert FINDINGS_STREAM.retention_seconds == 90 * 86_400


def test_approvals_retention_is_one_year_in_seconds() -> None:
    assert APPROVALS_STREAM.retention_seconds == 365 * 86_400


def test_commands_retention_is_thirty_days_in_seconds() -> None:
    assert COMMANDS_STREAM.retention_seconds == 30 * 86_400


def test_events_retention_is_seven_days_in_seconds() -> None:
    assert EVENTS_STREAM.retention_seconds == 7 * 86_400


# ADR-012 — CLAIMS_STREAM


def test_claims_retention_is_thirty_days_in_seconds() -> None:
    """Per ADR-012: claims sit between events (7d) and findings (90d)."""
    assert CLAIMS_STREAM.retention_seconds == 30 * 86_400


def test_claims_subject_pattern_is_claims_root() -> None:
    assert CLAIMS_STREAM.subjects == ("claims.>",)


def test_claims_stream_name_is_claims() -> None:
    assert CLAIMS_STREAM.name == "claims"
