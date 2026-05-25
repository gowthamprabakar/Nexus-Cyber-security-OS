"""G1 outcome correlator tests — Task 6 (outcome-axis computation).

15 tests covering read_outcome_events, compute_outcome_correlation, and
OutcomeCorrelation for the skill outcome axis.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from charter.audit import AuditLog
from meta_harness.skill_adoption import _sidecar_path
from meta_harness.skill_outcome import (
    compute_outcome_correlation,
    read_outcome_events,
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


def _contributed_event(
    *,
    skill_id: str = "sk_test",
    agent_id: str = "test-agent",
    run_id: str = "run_001",
    tenant_id: str = "default",
    outcome: str = "success",
    contributed_at: str | None = None,
) -> dict[str, object]:
    ts = contributed_at or _NOW.isoformat()
    return {
        "action": "agent.skill.contributed",
        "agent_id": agent_id,
        "contributed_at": ts,
        "loaded_at": None,
        "outcome": outcome,
        "run_id": run_id,
        "skill_id": skill_id,
        "tenant_id": tenant_id,
    }


# ---------------------------------------------------------------------------
# Empty / missing sidecar
# ---------------------------------------------------------------------------


def test_g1_missing_sidecar_returns_empty_metrics(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    metrics = compute_outcome_correlation(
        skill_id="sk_nonexistent",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.success_count == 0
    assert metrics.failure_count == 0
    assert metrics.partial_count == 0
    assert metrics.correlation_score is None
    assert metrics.confidence == 0.0


def test_g1_empty_sidecar_returns_empty_metrics(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_sidecar(tmp_path, "test-agent", "sk_empty", [])
    metrics = compute_outcome_correlation(
        skill_id="sk_empty",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.success_count == 0
    assert metrics.correlation_score is None
    assert metrics.confidence == 0.0


# ---------------------------------------------------------------------------
# All-success / all-failure / all-partial / mixed
# ---------------------------------------------------------------------------


def test_g1_all_success_returns_score_one(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_success",
        [
            _contributed_event(skill_id="sk_success", run_id="r1", outcome="success"),
            _contributed_event(skill_id="sk_success", run_id="r2", outcome="success"),
            _contributed_event(skill_id="sk_success", run_id="r3", outcome="success"),
        ],
    )
    metrics = compute_outcome_correlation(
        skill_id="sk_success",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.success_count == 3
    assert metrics.failure_count == 0
    assert metrics.partial_count == 0
    assert metrics.correlation_score == 1.0
    assert metrics.confidence == pytest.approx(0.3)


def test_g1_all_failure_returns_score_zero(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_fail",
        [
            _contributed_event(skill_id="sk_fail", run_id="r1", outcome="failure"),
            _contributed_event(skill_id="sk_fail", run_id="r2", outcome="failure"),
        ],
    )
    metrics = compute_outcome_correlation(
        skill_id="sk_fail",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.success_count == 0
    assert metrics.failure_count == 2
    assert metrics.correlation_score == 0.0


def test_g1_all_partial_returns_score_half(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_partial",
        [
            _contributed_event(skill_id="sk_partial", run_id="r1", outcome="partial"),
            _contributed_event(skill_id="sk_partial", run_id="r2", outcome="partial"),
        ],
    )
    metrics = compute_outcome_correlation(
        skill_id="sk_partial",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.partial_count == 2
    assert metrics.correlation_score == 0.5


def test_g1_mixed_outcomes_weighted_correctly(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_mixed",
        [
            _contributed_event(skill_id="sk_mixed", run_id="r1", outcome="success"),
            _contributed_event(skill_id="sk_mixed", run_id="r2", outcome="success"),
            _contributed_event(skill_id="sk_mixed", run_id="r3", outcome="success"),
            _contributed_event(skill_id="sk_mixed", run_id="r4", outcome="failure"),
            _contributed_event(skill_id="sk_mixed", run_id="r5", outcome="failure"),
            _contributed_event(skill_id="sk_mixed", run_id="r6", outcome="partial"),
        ],
    )
    metrics = compute_outcome_correlation(
        skill_id="sk_mixed",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.success_count == 3
    assert metrics.failure_count == 2
    assert metrics.partial_count == 1
    assert metrics.correlation_score == pytest.approx(0.58333, abs=0.001)
    assert metrics.confidence == pytest.approx(0.6)


# ---------------------------------------------------------------------------
# Confidence growth curve
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("contribution_count", "expected_confidence"),
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
    tmp_path: Path, contribution_count: int, expected_confidence: float
) -> None:
    al = _audit_log(tmp_path)
    events = [
        _contributed_event(skill_id="sk_conf", run_id=f"run_{i}", outcome="success")
        for i in range(contribution_count)
    ]
    _write_sidecar(tmp_path, "test-agent", "sk_conf", events)
    metrics = compute_outcome_correlation(
        skill_id="sk_conf",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    if contribution_count == 0:
        assert metrics.correlation_score is None
    else:
        assert metrics.correlation_score == 1.0
    assert metrics.confidence == pytest.approx(expected_confidence)


# ---------------------------------------------------------------------------
# Loaded events are filtered out
# ---------------------------------------------------------------------------


def test_g1_loaded_events_not_counted(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    loaded = {
        "action": "agent.skill.loaded",
        "skill_id": "sk_filter",
        "agent_id": "test-agent",
        "run_id": "run_loaded",
        "tenant_id": "default",
        "loaded_at": _NOW.isoformat(),
        "contributed_at": None,
        "outcome": "success",
    }
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_filter",
        [
            loaded,
            _contributed_event(skill_id="sk_filter", run_id="r1", outcome="success"),
        ],
    )
    metrics = compute_outcome_correlation(
        skill_id="sk_filter",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.success_count == 1


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
            _contributed_event(
                skill_id="sk_tenant", run_id="ra", outcome="success", tenant_id="acme"
            ),
            _contributed_event(
                skill_id="sk_tenant", run_id="rb", outcome="failure", tenant_id="acme"
            ),
            _contributed_event(
                skill_id="sk_tenant", run_id="rc", outcome="success", tenant_id="default"
            ),
        ],
    )
    metrics = compute_outcome_correlation(
        skill_id="sk_tenant",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
        tenant_id="acme",
    )
    assert metrics.success_count == 1
    assert metrics.failure_count == 1
    assert metrics.correlation_score == 0.5


# ---------------------------------------------------------------------------
# Missing / unknown outcome field → effectiveness_error (CF #2)
# ---------------------------------------------------------------------------


def test_g1_missing_outcome_field_emits_error_and_skips(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    contributed_no_outcome = {
        "action": "agent.skill.contributed",
        "skill_id": "sk_missing",
        "agent_id": "test-agent",
        "run_id": "run_no_out",
        "tenant_id": "default",
        "loaded_at": None,
        "contributed_at": _NOW.isoformat(),
    }
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_missing",
        [
            contributed_no_outcome,
            _contributed_event(skill_id="sk_missing", run_id="r1", outcome="success"),
        ],
    )
    metrics = compute_outcome_correlation(
        skill_id="sk_missing",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.success_count == 1
    assert metrics.correlation_score == 1.0

    # CF #2: missing outcome emitted as effectiveness_error in audit chain.
    audit_text = al.path.read_text(encoding="utf-8")
    assert "meta_harness.skill.effectiveness_error" in audit_text
    assert "unknown_outcome_value" in audit_text
    assert "sk_missing" in audit_text


def test_g1_unknown_outcome_value_emits_error_and_skips(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_unknown",
        [
            _contributed_event(skill_id="sk_unknown", run_id="r1", outcome="unknown_bogus"),
            _contributed_event(skill_id="sk_unknown", run_id="r2", outcome="success"),
        ],
    )
    metrics = compute_outcome_correlation(
        skill_id="sk_unknown",
        agent_id="test-agent",
        audit_log=al,
        workspace_root=tmp_path,
    )
    assert metrics.success_count == 1

    # CF #2: unknown outcome emitted as effectiveness_error in audit chain.
    audit_text = al.path.read_text(encoding="utf-8")
    assert "meta_harness.skill.effectiveness_error" in audit_text
    assert "unknown_outcome_value" in audit_text
    assert "sk_unknown" in audit_text


# ---------------------------------------------------------------------------
# read_outcome_events generator
# ---------------------------------------------------------------------------


def test_g1_read_outcome_events_yields_only_contributed(tmp_path: Path) -> None:
    al = _audit_log(tmp_path)
    loaded = {
        "action": "agent.skill.loaded",
        "skill_id": "sk_read",
        "agent_id": "test-agent",
        "run_id": "run_load",
        "tenant_id": "default",
        "loaded_at": _NOW.isoformat(),
        "contributed_at": None,
    }
    _write_sidecar(
        tmp_path,
        "test-agent",
        "sk_read",
        [
            loaded,
            _contributed_event(skill_id="sk_read", run_id="r1", outcome="success"),
            _contributed_event(skill_id="sk_read", run_id="r2", outcome="failure"),
        ],
    )
    records = list(
        read_outcome_events(
            agent_id="test-agent",
            skill_id="sk_read",
            audit_log=al,
            workspace_root=tmp_path,
        )
    )
    assert len(records) == 2
    assert all(r["action"] == "agent.skill.contributed" for r in records)
