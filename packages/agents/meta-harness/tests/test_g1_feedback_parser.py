"""G1 feedback parser tests — Task 7 (feedback-axis computation).

12 tests covering read_operator_ratings, compute_feedback_axis, and
FeedbackAxis for the skill feedback axis.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from meta_harness.skill_feedback import (
    _operator_ratings_path,
    compute_feedback_axis,
    read_operator_ratings,
)

_NOW = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)


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
    ts = rated_at or _NOW.isoformat()
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


# ---------------------------------------------------------------------------
# Empty / missing ratings file
# ---------------------------------------------------------------------------


def test_g1_missing_ratings_file_returns_empty_metrics(tmp_path: Path) -> None:
    metrics = compute_feedback_axis(
        skill_id="sk_nonexistent",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 0
    assert metrics.neutral_count == 0
    assert metrics.harmful_count == 0
    assert metrics.feedback_score is None
    assert metrics.confidence == 0.0


def test_g1_empty_ratings_file_returns_empty_metrics(tmp_path: Path) -> None:
    _write_ratings_file(tmp_path, "test-agent", "sk_empty", [])
    metrics = compute_feedback_axis(
        skill_id="sk_empty",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 0
    assert metrics.feedback_score is None
    assert metrics.confidence == 0.0


# ---------------------------------------------------------------------------
# All-useful / all-harmful / all-neutral / mixed
# ---------------------------------------------------------------------------


def test_g1_all_useful_returns_score_one(tmp_path: Path) -> None:
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_useful",
        [_rating_record(skill_id="sk_useful", rating="useful") for _ in range(3)],
    )
    metrics = compute_feedback_axis(
        skill_id="sk_useful",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 3
    assert metrics.harmful_count == 0
    assert metrics.neutral_count == 0
    assert metrics.feedback_score == 1.0
    assert metrics.confidence == pytest.approx(0.6)


def test_g1_all_harmful_returns_score_zero(tmp_path: Path) -> None:
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_harmful",
        [_rating_record(skill_id="sk_harmful", rating="harmful") for _ in range(2)],
    )
    metrics = compute_feedback_axis(
        skill_id="sk_harmful",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.harmful_count == 2
    assert metrics.useful_count == 0
    # raw = (0 - 2) / 2 = -1, normalized = (-1 + 1) / 2 = 0.0
    assert metrics.feedback_score == 0.0


def test_g1_all_neutral_returns_score_half(tmp_path: Path) -> None:
    _write_ratings_file(
        tmp_path,
        "test-agent",
        "sk_neutral",
        [_rating_record(skill_id="sk_neutral", rating="neutral") for _ in range(4)],
    )
    metrics = compute_feedback_axis(
        skill_id="sk_neutral",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.neutral_count == 4
    # raw = (0 - 0) / 4 = 0, normalized = (0 + 1) / 2 = 0.5
    assert metrics.feedback_score == 0.5


def test_g1_mixed_ratings_weighted_correctly(tmp_path: Path) -> None:
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
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 3
    assert metrics.neutral_count == 1
    assert metrics.harmful_count == 1
    # raw = (3 - 1) / 5 = 0.4, normalized = (0.4 + 1) / 2 = 0.7
    assert metrics.feedback_score == 0.7


# ---------------------------------------------------------------------------
# Confidence growth curve (ramps faster — /5 instead of /10)
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
    events = [_rating_record(skill_id="sk_conf", rating="useful") for _ in range(rating_count)]
    _write_ratings_file(tmp_path, "test-agent", "sk_conf", events)
    metrics = compute_feedback_axis(
        skill_id="sk_conf",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.confidence == pytest.approx(expected_confidence)


# ---------------------------------------------------------------------------
# Tenant filtering
# ---------------------------------------------------------------------------


def test_g1_tenant_filtering(tmp_path: Path) -> None:
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
        workspace_root=tmp_path,
        tenant_id="acme",
    )
    assert metrics.useful_count == 1
    assert metrics.harmful_count == 1
    # raw = (1 - 1) / 2 = 0, normalized = 0.5
    assert metrics.feedback_score == 0.5


# ---------------------------------------------------------------------------
# Unknown rating value skipped
# ---------------------------------------------------------------------------


def test_g1_unknown_rating_value_skipped(tmp_path: Path) -> None:
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
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 1


# ---------------------------------------------------------------------------
# Malformed JSONL skipped
# ---------------------------------------------------------------------------


def test_g1_malformed_jsonl_skipped(tmp_path: Path) -> None:
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
        workspace_root=tmp_path,
    )
    assert metrics.useful_count == 1
    assert metrics.harmful_count == 1


# ---------------------------------------------------------------------------
# read_operator_ratings generator
# ---------------------------------------------------------------------------


def test_g1_read_operator_ratings_yields_all_records(tmp_path: Path) -> None:
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
            workspace_root=tmp_path,
        )
    )
    assert len(records) == 2
    assert records[0]["rating"] == "useful"
    assert records[1]["rating"] == "harmful"
