"""G1 adoption tracker tests — Task 5 (adoption-axis computation).

13 tests covering read_run_events, compute_adoption_metrics, and
AdoptionMetrics for the skill adoption axis.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from charter.audit import AuditLog
from meta_harness.skill_adoption import (
    _sidecar_path,
    compute_adoption_metrics,
    read_run_events,
)

_NOW = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)


def _audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", agent="test-agent", run_id="test-run")


def _write_sidecar(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    lines: list[dict[str, object]],
) -> Path:
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
        "agent_id": agent_id,
        "contributed_at": None,
        "loaded_at": ts,
        "run_id": run_id,
        "skill_id": skill_id,
        "tenant_id": tenant_id,
    }


# ---------------------------------------------------------------------------
# Empty / missing sidecar
# ---------------------------------------------------------------------------


def test_g1_missing_sidecar_returns_empty_metrics(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    metrics = compute_adoption_metrics(
        skill_id="sk_nonexistent",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.load_count == 0
    assert metrics.confidence == 0.0
    assert metrics.unique_runs == 0
    assert metrics.unique_agents == 0
    assert metrics.first_loaded_at is None
    assert metrics.last_loaded_at is None


def test_g1_empty_sidecar_returns_empty_metrics(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_sidecar(tmp_path, "test-agent", "sk_empty", [])
    metrics = compute_adoption_metrics(
        skill_id="sk_empty",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.load_count == 0
    assert metrics.confidence == 0.0


# ---------------------------------------------------------------------------
# Single-load sidecar
# ---------------------------------------------------------------------------


def test_g1_single_load_metrics(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_single",
        [_loaded_event(skill_id="sk_single", agent_id="test-agent", run_id="run_001")],
    )
    metrics = compute_adoption_metrics(
        skill_id="sk_single",
        agent_id="test-agent",
        audit_log=al,
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
    al = _audit_log(tmp_path)
    events = [
        _loaded_event(skill_id="sk_multi", run_id="run_001"),
        _loaded_event(skill_id="sk_multi", run_id="run_002"),
        _loaded_event(skill_id="sk_multi", run_id="run_002"),
        _loaded_event(skill_id="sk_multi", run_id="run_003"),
    ]
    _write_sidecar(tmp_path, "test-agent", "sk_multi", events)
    metrics = compute_adoption_metrics(
        skill_id="sk_multi",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.load_count == 4
    assert metrics.unique_runs == 3
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
        (20, 1.0),
    ],
)
def test_g1_confidence_growth_curve(
    tmp_path: Path, load_count: int, expected_confidence: float
) -> None:
    al = _audit_log(tmp_path)
    events = [_loaded_event(skill_id="sk_conf", run_id=f"run_{i}") for i in range(load_count)]
    _write_sidecar(tmp_path, "test-agent", "sk_conf", events)
    metrics = compute_adoption_metrics(
        skill_id="sk_conf",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.load_count == load_count
    assert metrics.confidence == pytest.approx(expected_confidence)


# ---------------------------------------------------------------------------
# Malformed JSONL → effectiveness_error (CF #2)
# ---------------------------------------------------------------------------


def test_g1_malformed_jsonl_skipped_and_emits_error(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
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
        audit_log=al,
        workspace_root=tmp_path,
    )
    # Only the two valid lines are counted.
    assert metrics.load_count == 2
    assert metrics.unique_runs == 2

    # CF #2: malformed lines emitted as effectiveness_error in audit chain.
    audit_text = al.path.read_text(encoding="utf-8")
    assert "meta_harness.skill.effectiveness_error" in audit_text
    assert "malformed_sidecar_line" in audit_text
    assert "sk_malformed" in audit_text


# ---------------------------------------------------------------------------
# Contributed events are filtered out
# ---------------------------------------------------------------------------


def test_g1_contributed_events_not_counted(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    contributed = {
        "action": "agent.skill.contributed",
        "agent_id": "test-agent",
        "contributed_at": _NOW.isoformat(),
        "loaded_at": None,
        "run_id": "run_c",
        "skill_id": "sk_filter",
        "tenant_id": "default",
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
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.load_count == 2


# ---------------------------------------------------------------------------
# Tenant filtering
# ---------------------------------------------------------------------------


def test_g1_tenant_filtering(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
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
        audit_log=al,
        workspace_root=tmp_path,
        tenant_id="acme",
    )
    assert metrics.load_count == 2
    assert metrics.unique_runs == 2


# ---------------------------------------------------------------------------
# Timestamp ordering
# ---------------------------------------------------------------------------


def test_g1_first_and_last_loaded_at_are_correct(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
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
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.first_loaded_at == datetime.fromisoformat(early)
    assert metrics.last_loaded_at == datetime.fromisoformat(late)


# ---------------------------------------------------------------------------
# read_run_events generator
# ---------------------------------------------------------------------------


def test_g1_read_run_events_yields_all_records(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
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
            audit_log=al,
            workspace_root=tmp_path,
        )
    )
    assert len(records) == 2
    assert records[0]["run_id"] == "run_001"
    assert records[1]["run_id"] == "run_002"
