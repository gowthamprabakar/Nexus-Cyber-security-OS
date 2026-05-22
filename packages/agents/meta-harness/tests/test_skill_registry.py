"""Tests — `meta_harness.skill_registry` (Task 9).

10 tests covering the persistent skill-class registry:

1.  ``compute_registry_path`` returns ``<workspace>/.nexus/skill-class-registry.json``.
2.  ``load_skill_class_registry`` returns an empty registry when the
    JSON file does not exist (v0.2 first-run state).
3.  ``save_skill_class_registry`` + ``load_skill_class_registry``
    round-trip preserves entries.
4.  ``load_skill_class_registry`` raises ``SkillRegistryError`` on
    malformed JSON.
5.  ``is_class_registered`` is False for unknown classes; True after
    ``register_class``.
6.  ``register_class`` pins ``first_approved_at`` + ``first_skill_id``
    + seeds ``deployed_skill_ids`` / ``deployed_tool_sequence_hashes``.
7.  ``register_class`` is idempotent — re-registering the same
    ``(agent_id, category)`` preserves the original first-approval.
8.  ``record_deployment`` adds a refinement skill + hash to an
    existing class entry.
9.  ``record_deployment`` raises ``SkillRegistryError`` when the class
    isn't registered yet.
10. ``deployed_tool_sequence_hashes`` returns all hashes; filter by
    ``agent_id`` returns only that agent's hashes (Task 6 input shape).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from meta_harness.skill_registry import (
    SkillClassRegistry,
    SkillClassRegistryEntry,
    SkillRegistryError,
    compute_registry_path,
    load_skill_class_registry,
    record_deployment,
    register_class,
    save_skill_class_registry,
)

_APPROVED_AT = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)
_LATER_AT = datetime(2026, 5, 22, 13, 0, 0, tzinfo=UTC)


def test_compute_registry_path_layout(tmp_path: Path) -> None:
    assert compute_registry_path(tmp_path) == tmp_path / ".nexus" / "skill-class-registry.json"


def test_load_empty_when_file_missing(tmp_path: Path) -> None:
    registry = load_skill_class_registry(tmp_path)
    assert isinstance(registry, SkillClassRegistry)
    assert registry.entries == ()


def test_save_load_round_trip(tmp_path: Path) -> None:
    registry = register_class(
        SkillClassRegistry(),
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/role-chain",
        tool_sequence_hash="hash_a",
        approved_at=_APPROVED_AT,
    )
    save_skill_class_registry(registry, workspace_root=tmp_path)
    loaded = load_skill_class_registry(tmp_path)
    assert loaded == registry


def test_load_malformed_json_raises(tmp_path: Path) -> None:
    path = compute_registry_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('{"entries": "not-a-tuple"}', encoding="utf-8")
    with pytest.raises(SkillRegistryError, match="malformed registry"):
        load_skill_class_registry(tmp_path)


def test_is_class_registered_false_then_true_after_register() -> None:
    registry = SkillClassRegistry()
    assert registry.is_class_registered("investigation", "iam-privesc") is False
    registry = register_class(
        registry,
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/role-chain",
        tool_sequence_hash="hash_a",
        approved_at=_APPROVED_AT,
    )
    assert registry.is_class_registered("investigation", "iam-privesc") is True


def test_register_class_pins_first_approval_metadata() -> None:
    registry = register_class(
        SkillClassRegistry(),
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/role-chain",
        tool_sequence_hash="hash_a",
        approved_at=_APPROVED_AT,
    )
    entry = registry.entry_for("investigation", "iam-privesc")
    assert isinstance(entry, SkillClassRegistryEntry)
    assert entry.first_approved_at == _APPROVED_AT
    assert entry.first_skill_id == "iam-privesc/role-chain"
    assert entry.deployed_skill_ids == ("iam-privesc/role-chain",)
    assert entry.deployed_tool_sequence_hashes == ("hash_a",)


def test_register_class_idempotent_preserves_first_approval() -> None:
    once = register_class(
        SkillClassRegistry(),
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/role-chain",
        tool_sequence_hash="hash_a",
        approved_at=_APPROVED_AT,
    )
    twice = register_class(
        once,
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/different-skill",  # ignored
        tool_sequence_hash="hash_b",  # ignored
        approved_at=_LATER_AT,  # ignored
    )
    assert twice == once
    entry = twice.entry_for("investigation", "iam-privesc")
    assert entry is not None
    assert entry.first_approved_at == _APPROVED_AT
    assert entry.first_skill_id == "iam-privesc/role-chain"


def test_record_deployment_adds_refinement_to_existing_class() -> None:
    registry = register_class(
        SkillClassRegistry(),
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/role-chain",
        tool_sequence_hash="hash_a",
        approved_at=_APPROVED_AT,
    )
    registry = record_deployment(
        registry,
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/role-chain-v2",
        tool_sequence_hash="hash_b",
    )
    entry = registry.entry_for("investigation", "iam-privesc")
    assert entry is not None
    assert entry.deployed_skill_ids == ("iam-privesc/role-chain", "iam-privesc/role-chain-v2")
    assert entry.deployed_tool_sequence_hashes == ("hash_a", "hash_b")
    # first-approval metadata unchanged
    assert entry.first_skill_id == "iam-privesc/role-chain"


def test_record_deployment_unregistered_class_raises() -> None:
    with pytest.raises(SkillRegistryError, match="unregistered class"):
        record_deployment(
            SkillClassRegistry(),
            agent_id="investigation",
            category="iam-privesc",
            skill_id="iam-privesc/role-chain",
            tool_sequence_hash="hash_a",
        )


def test_deployed_tool_sequence_hashes_all_and_filtered() -> None:
    registry = SkillClassRegistry()
    registry = register_class(
        registry,
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/role-chain",
        tool_sequence_hash="hash_inv",
        approved_at=_APPROVED_AT,
    )
    registry = register_class(
        registry,
        agent_id="data_security",
        category="pii-leak",
        skill_id="pii-leak/s3-public",
        tool_sequence_hash="hash_ds",
        approved_at=_APPROVED_AT,
    )
    # All hashes (no filter)
    assert registry.deployed_tool_sequence_hashes() == frozenset({"hash_inv", "hash_ds"})
    # Filtered by agent_id — Task 6 input shape
    assert registry.deployed_tool_sequence_hashes("investigation") == frozenset({"hash_inv"})
    assert registry.deployed_tool_sequence_hashes("data_security") == frozenset({"hash_ds"})
    assert registry.deployed_tool_sequence_hashes("unknown_agent") == frozenset()
