"""G1 audit-action vocabulary tests — Task 3 (SAFETY-CRITICAL).

14 tests covering the 6 new effectiveness action constants, hash-chain
routing configuration, and agent-side telemetry helpers in
``shared.skill_telemetry``.
"""

from __future__ import annotations

import json
from pathlib import Path

from shared.skill_telemetry import (
    ACTION_AGENT_SKILL_CONTRIBUTED,
    ACTION_AGENT_SKILL_LOADED,
    ACTION_AGENT_SKILL_OPERATOR_RATED,
    ACTION_AGENT_SKILL_OUTCOME_CORRELATED,
    ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR,
    ACTION_META_HARNESS_SKILL_EFFECTIVENESS_UPDATED,
    ALL_EFFECTIVENESS_ACTIONS,
    emit_agent_skill_contributed,
    emit_agent_skill_loaded,
    is_audit_chain_action,
    is_sidecar_only_action,
)

# ---------------------------------------------------------------------------
# Action constant identity
# ---------------------------------------------------------------------------


def test_g1_action_constants_match_plan_doc() -> None:
    """All 6 action strings match the G1 plan doc vocabulary."""
    assert ACTION_AGENT_SKILL_LOADED == "agent.skill.loaded"
    assert ACTION_AGENT_SKILL_CONTRIBUTED == "agent.skill.contributed"
    assert ACTION_AGENT_SKILL_OUTCOME_CORRELATED == "agent.skill.outcome_correlated"
    assert ACTION_AGENT_SKILL_OPERATOR_RATED == "agent.skill.operator_rated"
    assert (
        ACTION_META_HARNESS_SKILL_EFFECTIVENESS_UPDATED
        == "meta_harness.skill.effectiveness_updated"
    )
    assert ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR == "meta_harness.skill.effectiveness_error"


def test_g1_all_effectiveness_actions_has_exactly_6() -> None:
    """ALL_EFFECTIVENESS_ACTIONS contains exactly the 6 declared actions."""
    assert len(ALL_EFFECTIVENESS_ACTIONS) == 6
    assert ACTION_AGENT_SKILL_LOADED in ALL_EFFECTIVENESS_ACTIONS
    assert ACTION_AGENT_SKILL_CONTRIBUTED in ALL_EFFECTIVENESS_ACTIONS
    assert ACTION_AGENT_SKILL_OUTCOME_CORRELATED in ALL_EFFECTIVENESS_ACTIONS
    assert ACTION_AGENT_SKILL_OPERATOR_RATED in ALL_EFFECTIVENESS_ACTIONS
    assert ACTION_META_HARNESS_SKILL_EFFECTIVENESS_UPDATED in ALL_EFFECTIVENESS_ACTIONS
    assert ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR in ALL_EFFECTIVENESS_ACTIONS


# ---------------------------------------------------------------------------
# Hash-chain routing configuration
# ---------------------------------------------------------------------------


def test_g1_sidecar_only_actions_are_2() -> None:
    """Only agent.skill.loaded and agent.skill.contributed are sidecar-only."""
    assert is_sidecar_only_action(ACTION_AGENT_SKILL_LOADED)
    assert is_sidecar_only_action(ACTION_AGENT_SKILL_CONTRIBUTED)
    # Count: exactly these 2 are sidecar-only.
    sidecar_count = sum(1 for a in ALL_EFFECTIVENESS_ACTIONS if is_sidecar_only_action(a))
    assert sidecar_count == 2


def test_g1_audit_chain_actions_are_4() -> None:
    """The 4 A.4-emitted actions go to audit chain."""
    assert is_audit_chain_action(ACTION_AGENT_SKILL_OUTCOME_CORRELATED)
    assert is_audit_chain_action(ACTION_AGENT_SKILL_OPERATOR_RATED)
    assert is_audit_chain_action(ACTION_META_HARNESS_SKILL_EFFECTIVENESS_UPDATED)
    assert is_audit_chain_action(ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR)
    chain_count = sum(1 for a in ALL_EFFECTIVENESS_ACTIONS if is_audit_chain_action(a))
    assert chain_count == 4


def test_g1_no_action_is_both_sidecar_and_audit_chain() -> None:
    """Every action is either sidecar-only OR audit-chain, never both."""
    for action in ALL_EFFECTIVENESS_ACTIONS:
        is_sidecar = is_sidecar_only_action(action)
        is_chain = is_audit_chain_action(action)
        assert is_sidecar != is_chain, (
            f"{action!r} must be sidecar-only XOR audit-chain; got "
            f"sidecar={is_sidecar}, chain={is_chain}"
        )


def test_g1_unknown_action_is_neither() -> None:
    """An action not in the vocabulary is neither sidecar-only nor audit-chain."""
    assert not is_sidecar_only_action("unknown.action")
    assert not is_audit_chain_action("unknown.action")


# ---------------------------------------------------------------------------
# Agent-side telemetry helpers — sidecar JSONL emission
# ---------------------------------------------------------------------------


def test_g1_emit_skill_loaded_writes_jsonl(tmp_path: Path) -> None:
    """emit_agent_skill_loaded appends a JSON line to the correct sidecar path."""
    path = emit_agent_skill_loaded(
        workspace_root=tmp_path,
        skill_id="sk_test_001",
        agent_id="cloud-posture",
        run_id="run_abc_001",
    )
    assert path.is_file()
    assert path.name == "run-events.jsonl"
    assert ".nexus" in str(path)
    assert "deployed-skills" in str(path)
    assert "cloud-posture" in str(path.parent.parent.name)
    assert "sk_test_001" in str(path.parent.name)

    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["action"] == "agent.skill.loaded"
    assert record["skill_id"] == "sk_test_001"
    assert record["agent_id"] == "cloud-posture"
    assert record["run_id"] == "run_abc_001"
    assert record["tenant_id"] == "default"
    assert record["contributed_at"] is None
    assert record["loaded_at"] is not None


def test_g1_emit_skill_contributed_writes_jsonl(tmp_path: Path) -> None:
    """emit_agent_skill_contributed appends a JSON line to the correct sidecar path."""
    path = emit_agent_skill_contributed(
        workspace_root=tmp_path,
        skill_id="sk_test_001",
        agent_id="cloud-posture",
        run_id="run_abc_001",
    )
    assert path.is_file()
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["action"] == "agent.skill.contributed"
    assert record["skill_id"] == "sk_test_001"
    assert record["loaded_at"] is None
    assert record["contributed_at"] is not None


def test_g1_loaded_and_contributed_append_to_same_file(tmp_path: Path) -> None:
    """Both emissions to the same (agent_id, skill_id) append to one file."""
    emit_agent_skill_loaded(
        workspace_root=tmp_path,
        skill_id="sk_shared",
        agent_id="cloud-posture",
        run_id="run_001",
    )
    emit_agent_skill_contributed(
        workspace_root=tmp_path,
        skill_id="sk_shared",
        agent_id="cloud-posture",
        run_id="run_001",
    )
    path = (
        tmp_path / ".nexus" / "deployed-skills" / "cloud-posture" / "sk_shared" / "run-events.jsonl"
    )
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    loaded = json.loads(lines[0])
    contributed = json.loads(lines[1])
    assert loaded["action"] == "agent.skill.loaded"
    assert contributed["action"] == "agent.skill.contributed"


def test_g1_emit_uses_default_tenant_id(tmp_path: Path) -> None:
    """tenant_id defaults to 'default' when not specified."""
    path = emit_agent_skill_loaded(
        workspace_root=tmp_path,
        skill_id="sk_t",
        agent_id="test-agent",
        run_id="run_t",
    )
    record = json.loads(path.read_text(encoding="utf-8").strip())
    assert record["tenant_id"] == "default"


def test_g1_emit_respects_explicit_tenant_id(tmp_path: Path) -> None:
    """tenant_id is honored when explicitly set."""
    path = emit_agent_skill_loaded(
        workspace_root=tmp_path,
        skill_id="sk_t",
        agent_id="test-agent",
        run_id="run_t",
        tenant_id="acme-tenant",
    )
    record = json.loads(path.read_text(encoding="utf-8").strip())
    assert record["tenant_id"] == "acme-tenant"


def test_g1_emit_creates_parent_directories(tmp_path: Path) -> None:
    """Emission creates the full sidecar directory tree if it doesn't exist."""
    deep_workspace = tmp_path / "deep" / "nested" / "workspace"
    path = emit_agent_skill_loaded(
        workspace_root=deep_workspace,
        skill_id="sk_deep",
        agent_id="test-agent",
        run_id="run_d",
    )
    assert path.is_file()


# ---------------------------------------------------------------------------
# Cross-check: action constants are importable by non-meta-harness package
# ---------------------------------------------------------------------------


def test_g1_actions_importable_without_meta_harness_dependency() -> None:
    """Any agent can import the action constants without depending on
    meta_harness.  This is the whole reason they live in shared/."""
    import importlib

    mod = importlib.import_module("shared.skill_telemetry")
    assert hasattr(mod, "ACTION_AGENT_SKILL_LOADED")
    assert hasattr(mod, "ACTION_AGENT_SKILL_CONTRIBUTED")
    # Verify no meta_harness import leaked into the module.
    assert "meta_harness" not in dir(mod)


# ---------------------------------------------------------------------------
# Cross-check: plan doc names match
# ---------------------------------------------------------------------------


def test_g1_action_constant_strings_match_plan_doc_vocabulary() -> None:
    """The 6 action strings exactly match the G1 plan doc §1 action names."""
    expected = {
        "agent.skill.loaded",
        "agent.skill.contributed",
        "agent.skill.outcome_correlated",
        "agent.skill.operator_rated",
        "meta_harness.skill.effectiveness_updated",
        "meta_harness.skill.effectiveness_error",
    }
    assert set(ALL_EFFECTIVENESS_ACTIONS) == expected
