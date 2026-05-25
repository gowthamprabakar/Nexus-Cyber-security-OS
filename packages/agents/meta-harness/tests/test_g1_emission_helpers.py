"""G1 emission helper tests — Task 4 (agent-side opt-in surface).

12 tests covering the 3 new G1 emission functions + context manager
added to ``meta_harness.audit_emit``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from charter.audit import AuditLog
from meta_harness.audit_emit import (
    SkillRunOutcome,
    emit_skill_contributed,
    emit_skill_loaded,
    skill_telemetry_context,
)

# ---------------------------------------------------------------------------
# SkillRunOutcome enum
# ---------------------------------------------------------------------------


def test_g1_skill_run_outcome_values() -> None:
    """SkillRunOutcome has exactly the 3 expected values."""
    assert set(SkillRunOutcome) == {
        SkillRunOutcome.SUCCESS,
        SkillRunOutcome.FAILURE,
        SkillRunOutcome.PARTIAL,
    }
    assert SkillRunOutcome.SUCCESS.value == "success"
    assert SkillRunOutcome.FAILURE.value == "failure"
    assert SkillRunOutcome.PARTIAL.value == "partial"


# ---------------------------------------------------------------------------
# emit_skill_loaded — smoke + idempotency
# ---------------------------------------------------------------------------


def test_g1_emit_skill_loaded_writes_sidecar_jsonl(tmp_path: Path) -> None:
    """emit_skill_loaded appends a loaded event to run-events.jsonl."""
    path = emit_skill_loaded(
        agent_id="test-agent",
        skill_id="sk_loaded_001",
        run_id="run_001",
        workspace_root=tmp_path,
    )
    assert path is not None
    assert path.is_file()
    assert path.name == "run-events.jsonl"
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["action"] == "agent.skill.loaded"
    assert record["skill_id"] == "sk_loaded_001"
    assert record["agent_id"] == "test-agent"
    assert record["loaded_at"] is not None
    assert record["contributed_at"] is None


def test_g1_emit_skill_loaded_is_idempotent(tmp_path: Path) -> None:
    """Same (skill_id, run_id) pair produces only one sidecar entry."""
    emit_skill_loaded(
        agent_id="test-agent",
        skill_id="sk_idem",
        run_id="run_001",
        workspace_root=tmp_path,
    )
    # Second call with same pair — returns None.
    result = emit_skill_loaded(
        agent_id="test-agent",
        skill_id="sk_idem",
        run_id="run_001",
        workspace_root=tmp_path,
    )
    assert result is None

    # Sidecar still has exactly one line.
    path = tmp_path / ".nexus" / "deployed-skills" / "test-agent" / "sk_idem" / "run-events.jsonl"
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1


# ---------------------------------------------------------------------------
# emit_skill_contributed — smoke
# ---------------------------------------------------------------------------


def test_g1_emit_skill_contributed_writes_sidecar_jsonl(tmp_path: Path) -> None:
    """emit_skill_contributed appends a contributed event with outcome."""
    path = emit_skill_contributed(
        agent_id="test-agent",
        skill_id="sk_contrib_001",
        run_id="run_001",
        outcome=SkillRunOutcome.SUCCESS,
        workspace_root=tmp_path,
    )
    assert path is not None
    assert path.is_file()
    record = json.loads(path.read_text(encoding="utf-8").strip())
    assert record["action"] == "agent.skill.contributed"
    assert record["skill_id"] == "sk_contrib_001"
    assert record["contributed_at"] is not None
    assert record["loaded_at"] is None


def test_g1_emit_skill_contributed_with_partial_outcome(tmp_path: Path) -> None:
    """Outcome PARTIAL is accepted for contributed events."""
    path = emit_skill_contributed(
        agent_id="test-agent",
        skill_id="sk_partial",
        run_id="run_p",
        outcome=SkillRunOutcome.PARTIAL,
        workspace_root=tmp_path,
    )
    assert path.is_file()


# ---------------------------------------------------------------------------
# skill_telemetry_context — happy path
# ---------------------------------------------------------------------------


def test_g1_context_manager_emits_contributed_on_exit(tmp_path: Path) -> None:
    """Skills loaded inside context get contributed on exit."""
    audit_log = AuditLog(tmp_path / "audit.jsonl", agent="test-agent", run_id="run_ctx")

    with skill_telemetry_context(
        agent_id="test-agent",
        run_id="run_ctx",
        workspace_root=tmp_path,
        audit_log=audit_log,
    ):
        emit_skill_loaded(
            agent_id="test-agent",
            skill_id="sk_ctx_001",
            run_id="run_ctx",
            workspace_root=tmp_path,
        )

    # After context exit, contributed event was emitted.
    contrib_path = (
        tmp_path / ".nexus" / "deployed-skills" / "test-agent" / "sk_ctx_001" / "run-events.jsonl"
    )
    assert contrib_path.is_file()
    lines = contrib_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2  # loaded + contributed
    loaded = json.loads(lines[0])
    contributed = json.loads(lines[1])
    assert loaded["action"] == "agent.skill.loaded"
    assert contributed["action"] == "agent.skill.contributed"


def test_g1_context_manager_empty_no_contributed(tmp_path: Path) -> None:
    """Context with no loaded skills emits no contributed events."""
    audit_log = AuditLog(tmp_path / "audit.jsonl", agent="test-agent", run_id="run_empty")

    with skill_telemetry_context(
        agent_id="test-agent",
        run_id="run_empty",
        workspace_root=tmp_path,
        audit_log=audit_log,
    ):
        pass  # Nothing loaded.

    # No sidecar files created.
    deployed_dir = tmp_path / ".nexus" / "deployed-skills"
    assert not deployed_dir.exists() or not any(deployed_dir.rglob("*.jsonl"))


def test_g1_context_manager_failure_propagates_outcome(tmp_path: Path) -> None:
    """Exception in context sets outcome=FAILURE and propagates."""
    audit_log = AuditLog(tmp_path / "audit.jsonl", agent="test-agent", run_id="run_fail")

    class _TestException(Exception):
        pass

    with (
        pytest.raises(_TestException),
        skill_telemetry_context(
            agent_id="test-agent",
            run_id="run_fail",
            workspace_root=tmp_path,
            audit_log=audit_log,
        ),
    ):
        emit_skill_loaded(
            agent_id="test-agent",
            skill_id="sk_fail",
            run_id="run_fail",
            workspace_root=tmp_path,
        )
        raise _TestException("simulated failure")

    # Contributed event was still emitted on exit.
    contrib_path = (
        tmp_path / ".nexus" / "deployed-skills" / "test-agent" / "sk_fail" / "run-events.jsonl"
    )
    assert contrib_path.is_file()
    lines = contrib_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2  # loaded + contributed


# ---------------------------------------------------------------------------
# Backwards-compat — graceful no-op when workspace_root is None
# ---------------------------------------------------------------------------


def test_g1_emit_skill_loaded_no_workspace_returns_none() -> None:
    """workspace_root=None → no-op, returns None, does not crash."""
    result = emit_skill_loaded(
        agent_id="test-agent",
        skill_id="sk_no_ws",
        run_id="run_nows",
        workspace_root=None,
    )
    assert result is None


def test_g1_emit_skill_contributed_no_workspace_returns_none() -> None:
    """workspace_root=None → no-op, returns None, does not crash."""
    result = emit_skill_contributed(
        agent_id="test-agent",
        skill_id="sk_no_ws",
        run_id="run_nows",
        outcome=SkillRunOutcome.SUCCESS,
        workspace_root=None,
    )
    assert result is None


# ---------------------------------------------------------------------------
# CF #2 silent-swallow fix — sidecar write failure → audit chain error
# ---------------------------------------------------------------------------


def test_g1_sidecar_write_failure_emits_effectiveness_error(tmp_path: Path) -> None:
    """When sidecar write fails, effectiveness_error is emitted to audit chain."""
    audit_log = AuditLog(tmp_path / "audit.jsonl", agent="test-agent", run_id="run_err")

    # Create the parent directory tree up to test-agent, then place a FILE
    # named "sk_err" where the sidecar helper would try to create the
    # skill directory.  ``mkdir(parents=True, exist_ok=True)`` fails when a
    # file (not a directory) exists at the target path.
    agent_dir = tmp_path / ".nexus" / "deployed-skills" / "test-agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "sk_err").write_text("blocker")

    with pytest.raises(FileExistsError):
        emit_skill_loaded(
            agent_id="test-agent",
            skill_id="sk_err",
            run_id="run_err",
            workspace_root=tmp_path,
            audit_log=audit_log,
        )

    # Audit chain should contain the effectiveness_error entry.
    audit_text = audit_log.path.read_text(encoding="utf-8")
    assert "meta_harness.skill.effectiveness_error" in audit_text
    assert "sidecar_write_failure" in audit_text
    assert "sk_err" in audit_text


def test_g1_sidecar_write_failure_without_audit_log_raises(tmp_path: Path) -> None:
    """Without audit_log, sidecar write failures propagate normally."""
    agent_dir = tmp_path / ".nexus" / "deployed-skills" / "test-agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "sk_noaudit").write_text("blocker")

    with pytest.raises(FileExistsError):
        emit_skill_loaded(
            agent_id="test-agent",
            skill_id="sk_noaudit",
            run_id="run_noaudit",
            workspace_root=tmp_path,
            audit_log=None,
        )
