"""G1 adoption tracker tests — Task 5 (adoption-axis computation).

12 tests covering read_run_events, compute_adoption_metrics, and
AdoptionMetrics for the skill adoption axis.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from meta_harness.skill_adoption import (
    _sidecar_path,
    compute_adoption_metrics,
    read_run_events,
)

_NOW = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)


def _write_sidecar(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    lines: list[dict[str, object]],
) -> Path:
    """Helper: write a sidecar run-events.jsonl and return the path."""
    path = _sidecar_path(workspace_root, agent_id, skill_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line, sort_keys=True) + "\n")
    return path


def _loaded_event(
    *,
    skill_id: str = "sk_test",
    agent_id: str = "test-agent",
    run_id: str = "run_001",
    tenant_id: str = "default",
    loaded_at: str | None = None,
) -> dict[str, object]:
    ts = loaded_at or _NOW.isoformat()
    return {
        "action": "agent.skill.loaded",
        "skill_id": skill_id,
        "agent_id": agent_id,
        "run_id": run_id,
        "tenant_id": tenant_id,
        "loaded_at": ts,
        "contributed_at": None,
    }


# ---------------------------------------------------------------------------
# Empty / missing sidecar
# ---------------------------------------------------------------------------


def test_g1_missing_sidecar_returns_empty_metrics(tmp_path: Path) -> None:
    """No sidecar file → AdoptionMetrics with load_count=0, confidence=0.0."""
    metrics = compute_adoption_metrics(
        skill_id="sk_nonexistent",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.load_count == 0
    assert metrics.confidence == 0.0
    assert metrics.unique_runs == 0
    assert metrics.unique_agents == 0
    assert metrics.first_loaded_at is None
    assert metrics.last_loaded_at is None


def test_g1_empty_sidecar_returns_empty_metrics(tmp_path: Path) -> None:
    """Empty run-events.jsonl → AdoptionMetrics with load_count=0."""
    _write_sidecar(tmp_path, "test-agent", "sk_empty", [])
    metrics = compute_adoption_metrics(
        skill_id="sk_empty",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.load_count == 0
    assert metrics.confidence == 0.0


# ---------------------------------------------------------------------------
# Single-load sidecar
# ---------------------------------------------------------------------------


def test_g1_single_load_metrics(tmp_path: Path) -> None:
    """One loaded event → load_count=1, unique_runs=1, unique_agents=1."""
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_single",
        [_loaded_event(skill_id="sk_single", agent_id="test-agent", run_id="run_001")],
    )
    metrics = compute_adoption_metrics(
        skill_id="sk_single",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.load_count == 1
    assert metrics.unique_runs == 1
    assert metrics.unique_agents == 1
    assert metrics.first_loaded_at is not None
    assert metrics.last_loaded_at is not None


# ---------------------------------------------------------------------------
# Multi-load multi-run sidecar
# ---------------------------------------------------------------------------


def test_g1_multi_load_multi_run_metrics(tmp_path: Path) -> None:
    """Multiple loaded events across runs → correct aggregation."""
    events = [
        _loaded_event(skill_id="sk_multi", run_id="run_001"),
        _loaded_event(skill_id="sk_multi", run_id="run_002"),
        _loaded_event(skill_id="sk_multi", run_id="run_002"),  # same run, second load
        _loaded_event(skill_id="sk_multi", run_id="run_003"),
    ]
    _write_sidecar(tmp_path, "test-agent", "sk_multi", events)
    metrics = compute_adoption_metrics(
        skill_id="sk_multi",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.load_count == 4
    assert metrics.unique_runs == 3  # run_001, run_002, run_003
    assert metrics.unique_agents == 1


# ---------------------------------------------------------------------------
# Confidence growth curve
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("load_count", "expected_confidence"),
    [
        (0, 0.0),
        (1, 0.1),
        (3, 0.3),
        (5, 0.5),
        (10, 1.0),
        (20, 1.0),  # capped at 1.0
    ],
)
def test_g1_confidence_growth_curve(
    tmp_path: Path, load_count: int, expected_confidence: float
) -> None:
    """Confidence = min(1.0, load_count / 10.0)."""
    events = [_loaded_event(skill_id="sk_conf", run_id=f"run_{i}") for i in range(load_count)]
    _write_sidecar(tmp_path, "test-agent", "sk_conf", events)
    metrics = compute_adoption_metrics(
        skill_id="sk_conf",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.load_count == load_count
    assert metrics.confidence == pytest.approx(expected_confidence)


# ---------------------------------------------------------------------------
# Malformed JSONL → graceful skip
# ---------------------------------------------------------------------------


def test_g1_malformed_jsonl_skipped(tmp_path: Path) -> None:
    """Malformed lines are skipped without crashing."""
    path = _sidecar_path(tmp_path, "test-agent", "sk_malformed")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        encoding="utf-8",
        data=(
            json.dumps(_loaded_event(skill_id="sk_malformed", run_id="run_001"))
            + "\n"
            + "NOT VALID JSON\n"
            + json.dumps(_loaded_event(skill_id="sk_malformed", run_id="run_002"))
            + "\n"
            + "ALSO NOT JSON\n"
        ),
    )
    metrics = compute_adoption_metrics(
        skill_id="sk_malformed",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    # Only the two valid lines are counted.
    assert metrics.load_count == 2
    assert metrics.unique_runs == 2


# ---------------------------------------------------------------------------
# Contributed events are filtered out
# ---------------------------------------------------------------------------


def test_g1_contributed_events_not_counted(tmp_path: Path) -> None:
    """Only agent.skill.loaded events count toward adoption metrics."""
    contributed = {
        "action": "agent.skill.contributed",
        "skill_id": "sk_filter",
        "agent_id": "test-agent",
        "run_id": "run_c",
        "tenant_id": "default",
        "loaded_at": None,
        "contributed_at": _NOW.isoformat(),
    }
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_filter",
        [
            _loaded_event(skill_id="sk_filter", run_id="run_001"),
            contributed,
            _loaded_event(skill_id="sk_filter", run_id="run_002"),
        ],
    )
    metrics = compute_adoption_metrics(
        skill_id="sk_filter",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.load_count == 2  # only the loaded events


# ---------------------------------------------------------------------------
# Tenant filtering
# ---------------------------------------------------------------------------


def test_g1_tenant_filtering(tmp_path: Path) -> None:
    """Events for other tenants are excluded."""
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_tenant",
        [
            _loaded_event(skill_id="sk_tenant", run_id="run_a", tenant_id="acme"),
            _loaded_event(skill_id="sk_tenant", run_id="run_b", tenant_id="acme"),
            _loaded_event(skill_id="sk_tenant", run_id="run_c", tenant_id="default"),
        ],
    )
    metrics = compute_adoption_metrics(
        skill_id="sk_tenant",
        agent_id="test-agent",
        workspace_root=tmp_path,
        tenant_id="acme",
    )
    assert metrics.load_count == 2  # only acme events
    assert metrics.unique_runs == 2


# ---------------------------------------------------------------------------
# Timestamp ordering
# ---------------------------------------------------------------------------


def test_g1_first_and_last_loaded_at_are_correct(tmp_path: Path) -> None:
    """first_loaded_at and last_loaded_at reflect chronological order."""
    early = "2026-01-01T00:00:00+00:00"
    mid = "2026-03-15T12:00:00+00:00"
    late = "2026-06-01T00:00:00+00:00"
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_time",
        [
            _loaded_event(skill_id="sk_time", run_id="run_mid", loaded_at=mid),
            _loaded_event(skill_id="sk_time", run_id="run_late", loaded_at=late),
            _loaded_event(skill_id="sk_time", run_id="run_early", loaded_at=early),
        ],
    )
    metrics = compute_adoption_metrics(
        skill_id="sk_time",
        agent_id="test-agent",
        workspace_root=tmp_path,
    )
    assert metrics.first_loaded_at == datetime.fromisoformat(early)
    assert metrics.last_loaded_at == datetime.fromisoformat(late)


# ---------------------------------------------------------------------------
# read_run_events generator
# ---------------------------------------------------------------------------


def test_g1_read_run_events_yields_all_records(tmp_path: Path) -> None:
    """read_run_events yields every valid record from the sidecar."""
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_read",
        [
            _loaded_event(skill_id="sk_read", run_id="run_001"),
            _loaded_event(skill_id="sk_read", run_id="run_002"),
        ],
    )
    records = list(
        read_run_events(
            agent_id="test-agent",
            skill_id="sk_read",
            workspace_root=tmp_path,
        )
    )
    assert len(records) == 2
    assert records[0]["run_id"] == "run_001"
    assert records[1]["run_id"] == "run_002"
