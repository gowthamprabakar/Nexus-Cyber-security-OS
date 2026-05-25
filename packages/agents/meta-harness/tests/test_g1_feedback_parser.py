"""G1 feedback parser tests — Task 7 (feedback-axis computation).

15 tests covering read_operator_ratings, compute_feedback_axis, and
FeedbackAxis for the skill feedback axis.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from itertools import count
from pathlib import Path

import pytest
from charter.audit import AuditEntry, AuditLog
from meta_harness.skill_feedback import (
    _operator_ratings_path,
    compute_feedback_axis,
    read_operator_ratings,
)

_NOW = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)
_TS_COUNTER = count()


def _audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", agent="test-agent", run_id="test-run")


def _write_ratings_file(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    lines: list[dict[str, object]],
) -> Path:
    path = _operator_ratings_path(workspace_root, agent_id, skill_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, sort_keys=True) + "\n")
    return path


def _rating_record(
    *,
    skill_id: str = "sk_test",
    agent_id: str = "test-agent",
    tenant_id: str = "default",
    rating: str = "useful",
    rated_by: str = "operator-1",
    rated_at: str | None = None,
    note: str | None = None,
) -> dict[str, object]:
    ts = rated_at or _NOW.replace(microsecond=next(_TS_COUNTER)).isoformat()
    rec: dict[str, object] = {
        "action": "agent.skill.operator_rated",
        "skill_id": skill_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "rating": rating,
        "rated_by": rated_by,
        "rated_at": ts,
    }
    if note is not None:
        rec["note"] = note
    return rec


def _append_audit_chain_rating(
    audit_log: AuditLog,
    *,
    skill_id: str = "sk_test",
    agent_id: str = "test-agent",
    tenant_id: str = "default",
    rating: str = "useful",
    rated_by: str = "operator-1",
    rated_at: str | None = None,
) -> AuditEntry:
    ts = rated_at or _NOW.isoformat()
    payload = {
        "skill_id": skill_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "rating": rating,
        "rated_by": rated_by,
        "rated_at": ts,
    }
    return audit_log.append("agent.skill.operator_rated", payload)


# ---------------------------------------------------------------------------
# Empty / missing ratings
# ---------------------------------------------------------------------------


def test_g1_missing_ratings_returns_empty_metrics(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    metrics = compute_feedback_axis(
        skill_id="sk_nonexistent",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 0
    assert metrics.neutral_count == 0
    assert metrics.harmful_count == 0
    assert metrics.feedback_score is None
    assert metrics.confidence == 0.0


def test_g1_empty_ratings_returns_empty_metrics(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_ratings_file(tmp_path, "test-agent", "sk_empty", [])
    metrics = compute_feedback_axis(
        skill_id="sk_empty",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 0
    assert metrics.feedback_score is None
    assert metrics.confidence == 0.0


# ---------------------------------------------------------------------------
# All-useful / all-harmful / all-neutral / mixed (via sidecar projection)
# ---------------------------------------------------------------------------


def test_g1_all_useful_returns_score_one(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_useful",
        [_rating_record(skill_id="sk_useful", rating="useful") for _ in range(3)],
    )
    metrics = compute_feedback_axis(
        skill_id="sk_useful",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 3
    assert metrics.harmful_count == 0
    assert metrics.neutral_count == 0
    assert metrics.feedback_score == 1.0
    assert metrics.confidence == pytest.approx(0.6)


def test_g1_all_harmful_returns_score_zero(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_harmful",
        [_rating_record(skill_id="sk_harmful", rating="harmful") for _ in range(2)],
    )
    metrics = compute_feedback_axis(
        skill_id="sk_harmful",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.harmful_count == 2
    assert metrics.useful_count == 0
    assert metrics.feedback_score == 0.0


def test_g1_all_neutral_returns_score_half(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_neutral",
        [_rating_record(skill_id="sk_neutral", rating="neutral") for _ in range(4)],
    )
    metrics = compute_feedback_axis(
        skill_id="sk_neutral",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.neutral_count == 4
    assert metrics.feedback_score == 0.5


def test_g1_mixed_ratings_weighted_correctly(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_mixed",
        [
            _rating_record(skill_id="sk_mixed", rating="useful"),
            _rating_record(skill_id="sk_mixed", rating="useful"),
            _rating_record(skill_id="sk_mixed", rating="useful"),
            _rating_record(skill_id="sk_mixed", rating="neutral"),
            _rating_record(skill_id="sk_mixed", rating="harmful"),
        ],
    )
    metrics = compute_feedback_axis(
        skill_id="sk_mixed",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 3
    assert metrics.neutral_count == 1
    assert metrics.harmful_count == 1
    assert metrics.feedback_score == 0.7


# ---------------------------------------------------------------------------
# Confidence growth curve
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rating_count", "expected_confidence"),
    [
        (0, 0.0),
        (1, 0.2),
        (2, 0.4),
        (3, 0.6),
        (5, 1.0),
        (10, 1.0),
    ],
)
def test_g1_confidence_growth_curve(
    tmp_path: Path, rating_count: int, expected_confidence: float
) -> None:
    al = _audit_log(tmp_path)
    events = [_rating_record(skill_id="sk_conf", rating="useful") for _ in range(rating_count)]
    _write_ratings_file(tmp_path, "test-agent", "sk_conf", events)
    metrics = compute_feedback_axis(
        skill_id="sk_conf",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.confidence == pytest.approx(expected_confidence)


# ---------------------------------------------------------------------------
# Tenant filtering
# ---------------------------------------------------------------------------


def test_g1_tenant_filtering(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_tenant",
        [
            _rating_record(skill_id="sk_tenant", rating="useful", tenant_id="acme"),
            _rating_record(skill_id="sk_tenant", rating="harmful", tenant_id="acme"),
            _rating_record(skill_id="sk_tenant", rating="useful", tenant_id="default"),
        ],
    )
    metrics = compute_feedback_axis(
        skill_id="sk_tenant",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
        tenant_id="acme",
    )
    assert metrics.useful_count == 1
    assert metrics.harmful_count == 1
    assert metrics.feedback_score == 0.5


# ---------------------------------------------------------------------------
# Unknown rating value skipped
# ---------------------------------------------------------------------------


def test_g1_unknown_rating_value_skipped(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_unknown",
        [
            _rating_record(skill_id="sk_unknown", rating="bogus_value"),
            _rating_record(skill_id="sk_unknown", rating="useful"),
        ],
    )
    metrics = compute_feedback_axis(
        skill_id="sk_unknown",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 1


# ---------------------------------------------------------------------------
# Malformed JSONL skipped
# ---------------------------------------------------------------------------


def test_g1_malformed_jsonl_skipped(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    path = _operator_ratings_path(tmp_path, "test-agent", "sk_malformed")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        encoding="utf-8",
        data=(
            json.dumps(_rating_record(skill_id="sk_malformed", rating="useful"))
            + "\n"
            + "NOT VALID JSON\n"
            + json.dumps(_rating_record(skill_id="sk_malformed", rating="harmful"))
            + "\n"
        ),
    )
    metrics = compute_feedback_axis(
        skill_id="sk_malformed",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 1
    assert metrics.harmful_count == 1


# ---------------------------------------------------------------------------
# read_operator_ratings — sidecar projection
# ---------------------------------------------------------------------------


def test_g1_read_operator_ratings_yields_from_sidecar(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_read",
        [
            _rating_record(skill_id="sk_read", rating="useful"),
            _rating_record(skill_id="sk_read", rating="harmful"),
        ],
    )
    records = list(
        read_operator_ratings(
            agent_id="test-agent",
            skill_id="sk_read",
            audit_log=al,
            workspace_root=tmp_path,
        )
    )
    assert len(records) == 2
    assert records[0]["rating"] == "useful"
    assert records[1]["rating"] == "harmful"


# ---------------------------------------------------------------------------
# Q8: audit-chain primary read
# ---------------------------------------------------------------------------


def test_g1_audit_chain_ratings_are_readable(tmp_path: Path) -> None:
    """Operator ratings written to audit chain are readable by read_operator_ratings."""
    al = _audit_log(tmp_path)
    _append_audit_chain_rating(
        al,
        skill_id="sk_audit",
        rating="useful",
        rated_by="op-1",
    )
    _append_audit_chain_rating(
        al,
        skill_id="sk_audit",
        rating="harmful",
        rated_by="op-2",
    )

    records = list(
        read_operator_ratings(
            agent_id="test-agent",
            skill_id="sk_audit",
            audit_log=al,
            workspace_root=tmp_path,
        )
    )
    assert len(records) == 2
    ratings = {r["rating"] for r in records}
    assert ratings == {"useful", "harmful"}


def test_g1_audit_chain_ratings_present_no_sidecar_still_readable(tmp_path: Path) -> None:
    """Audit-chain ratings are readable even when sidecar projection is absent."""
    al = _audit_log(tmp_path)
    _append_audit_chain_rating(
        al,
        skill_id="sk_no_proj",
        rating="useful",
        rated_by="op-1",
    )

    records = list(
        read_operator_ratings(
            agent_id="test-agent",
            skill_id="sk_no_proj",
            audit_log=al,
            workspace_root=tmp_path,
        )
    )
    assert len(records) == 1
    assert records[0]["rating"] == "useful"


def test_g1_audit_chain_dedup_prevents_duplicate_projections(tmp_path: Path) -> None:
    """Sidecar projection records already in audit chain are deduplicated."""
    al = _audit_log(tmp_path)
    # Use a shared explicit timestamp so audit-chain and sidecar records
    # for op-1 share the same (rated_by, rated_at) dedup key.
    shared_ts = "2026-05-25T12:00:00+00:00"
    _append_audit_chain_rating(
        al,
        skill_id="sk_dedup",
        rating="useful",
        rated_by="op-1",
        rated_at=shared_ts,
    )
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_dedup",
        [
            _rating_record(
                skill_id="sk_dedup",
                rating="useful",
                rated_by="op-1",
                rated_at=shared_ts,
            ),
            _rating_record(
                skill_id="sk_dedup",
                rating="harmful",
                rated_by="op-2",
            ),
        ],
    )

    records = list(
        read_operator_ratings(
            agent_id="test-agent",
            skill_id="sk_dedup",
            audit_log=al,
            workspace_root=tmp_path,
        )
    )
    # op-1's rating appears in both sources but should only be yielded once.
    # op-2's rating is only in sidecar.
    assert len(records) == 2
    ratings_by_op = {str(r["rated_by"]): r["rating"] for r in records}
    assert ratings_by_op == {"op-1": "useful", "op-2": "harmful"}
