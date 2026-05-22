"""Tests — `meta_harness.skill_discovery` (Task 5).

12 tests covering per-agent skill discovery + cross-agent walking:

1.  Empty registry when the agent has no nlah dir.
2.  Empty registry when nlah exists but skills/ subdir is missing.
3.  Empty registry when skills/ exists but no SKILL.md files inside.
4.  Single bundled skill discovered with ``source="bundled"``.
5.  Multiple bundled skills returned in skill_id lex order.
6.  Overlay-only skill discovered with ``source="overlay"``.
7.  Overlay + bundled — overlay masks the shared skill_id; the
    bundled-only skill stays visible.
8.  ``discover_all_agent_skills`` walks every entry-point name.
9.  ``discover_all_agent_skills`` honors ``agent_filter``.
10. ``discover_all_agent_skills`` returns empty registry for v0.1
    agents with no skills dir (backwards-compat regression probe).
11. ``default_shadow_skills_dir`` returns ``<workspace>/.nexus/candidate-skills/<agent_id>``.
12. Malformed frontmatter raises ``SkillLoaderError`` (charter
    exception propagates unchanged).
"""

from __future__ import annotations

from importlib.metadata import EntryPoint
from pathlib import Path

import pytest
from charter.nlah_loader import SkillLoaderError
from meta_harness import skill_discovery as skill_discovery_module
from meta_harness.skill_discovery import (
    AgentSkillRegistry,
    default_bundled_nlah_dir,
    default_shadow_skills_dir,
    discover_agent_skills,
    discover_all_agent_skills,
)

_MINIMAL_SKILL_MD = """---
name: aws_iam_privesc_via_assumed_role
description: Detect IAM privilege escalation via cross-account role chain.
version: 0.1.0
platforms:
  - nexus
target_agent: investigation
category: iam-privesc
created_by: meta_harness@v0.2.0
provenance:
  - [audit/r_eval.jsonl, deadbeefcafebabe]
eval_gate_status: not_run
deployment_status: candidate
---

When you see cross-account AssumeRole chains, follow the chain head-first.
"""


def _write_bundled_skill(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    content: str = _MINIMAL_SKILL_MD,
) -> Path:
    nlah_dir = default_bundled_nlah_dir(workspace_root, agent_id)
    skill_dir = nlah_dir / "skills" / skill_id
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_path = skill_dir / "SKILL.md"
    skill_path.write_text(content, encoding="utf-8")
    return skill_path


def _write_overlay_skill(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    content: str = _MINIMAL_SKILL_MD,
) -> Path:
    overlay_dir = default_shadow_skills_dir(workspace_root, agent_id) / skill_id
    overlay_dir.mkdir(parents=True, exist_ok=True)
    skill_path = overlay_dir / "SKILL.md"
    skill_path.write_text(content, encoding="utf-8")
    return skill_path


def _fake_entry_point(name: str) -> EntryPoint:
    return EntryPoint(name=name, value="x:y", group="nexus_eval_runners")


# ---------------------------- discover_agent_skills ----------------------------


def test_empty_registry_when_no_nlah_dir(tmp_path: Path) -> None:
    reg = discover_agent_skills("investigation", workspace_root=tmp_path)
    assert isinstance(reg, AgentSkillRegistry)
    assert reg.entries == ()
    assert reg.skills_overlay is None
    assert reg.bundled_entries == ()
    assert reg.overlay_entries == ()
    assert reg.categories == ()


def test_empty_registry_when_nlah_exists_but_no_skills_subdir(tmp_path: Path) -> None:
    nlah_dir = default_bundled_nlah_dir(tmp_path, "investigation")
    nlah_dir.mkdir(parents=True)
    (nlah_dir / "README.md").write_text("# Persona\n", encoding="utf-8")
    reg = discover_agent_skills("investigation", workspace_root=tmp_path)
    assert reg.entries == ()


def test_empty_registry_when_skills_subdir_empty(tmp_path: Path) -> None:
    skills_dir = default_bundled_nlah_dir(tmp_path, "investigation") / "skills"
    skills_dir.mkdir(parents=True)
    reg = discover_agent_skills("investigation", workspace_root=tmp_path)
    assert reg.entries == ()


def test_single_bundled_skill_discovered(tmp_path: Path) -> None:
    _write_bundled_skill(tmp_path, "investigation", "iam-privesc/role-chain")
    reg = discover_agent_skills("investigation", workspace_root=tmp_path)
    assert len(reg.entries) == 1
    entry = reg.entries[0]
    assert entry.skill_id == "iam-privesc/role-chain"
    assert entry.source == "bundled"
    assert entry.target_agent == "investigation"
    assert entry.category == "iam-privesc"
    assert reg.bundled_entries == reg.entries
    assert reg.overlay_entries == ()
    assert reg.categories == ("iam-privesc",)


def test_multiple_bundled_skills_sorted_by_skill_id(tmp_path: Path) -> None:
    _write_bundled_skill(tmp_path, "investigation", "zeta/last")
    _write_bundled_skill(tmp_path, "investigation", "alpha/first")
    reg = discover_agent_skills("investigation", workspace_root=tmp_path)
    assert [e.skill_id for e in reg.entries] == ["alpha/first", "zeta/last"]


def test_overlay_only_skill_discovered(tmp_path: Path) -> None:
    _write_overlay_skill(tmp_path, "investigation", "iam/x")
    reg = discover_agent_skills("investigation", workspace_root=tmp_path)
    assert len(reg.entries) == 1
    assert reg.entries[0].source == "overlay"
    assert reg.overlay_entries == reg.entries
    assert reg.bundled_entries == ()
    assert reg.skills_overlay is not None
    assert reg.skills_overlay.is_dir()


def test_overlay_masks_same_id_bundled_unmasked_still_visible(tmp_path: Path) -> None:
    _write_bundled_skill(
        tmp_path,
        "investigation",
        "iam/shared",
        content=_MINIMAL_SKILL_MD.replace("0.1.0", "0.1.0-bundled"),
    )
    _write_bundled_skill(tmp_path, "investigation", "iam/bundled-only")
    _write_overlay_skill(
        tmp_path,
        "investigation",
        "iam/shared",
        content=_MINIMAL_SKILL_MD.replace("0.1.0", "0.1.0-overlay"),
    )
    reg = discover_agent_skills("investigation", workspace_root=tmp_path)
    by_id = {e.skill_id: e for e in reg.entries}
    assert by_id["iam/shared"].source == "overlay"
    assert by_id["iam/shared"].version == "0.1.0-overlay"
    assert by_id["iam/bundled-only"].source == "bundled"


# ---------------------------- discover_all_agent_skills ----------------------------


def test_discover_all_walks_every_entry_point(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_bundled_skill(tmp_path, "investigation", "iam/x")
    _write_bundled_skill(tmp_path, "data_security", "pii/y")
    monkeypatch.setattr(
        skill_discovery_module,
        "entry_points",
        lambda *, group: [
            _fake_entry_point("investigation"),
            _fake_entry_point("data_security"),
        ],
    )
    registries = discover_all_agent_skills(workspace_root=tmp_path)
    assert set(registries.keys()) == {"investigation", "data_security"}
    assert len(registries["investigation"].entries) == 1
    assert len(registries["data_security"].entries) == 1
    # Lex-ordered iteration in the entry-point walk
    assert list(registries.keys()) == ["data_security", "investigation"]


def test_discover_all_honors_agent_filter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_bundled_skill(tmp_path, "investigation", "iam/x")
    _write_bundled_skill(tmp_path, "data_security", "pii/y")
    monkeypatch.setattr(
        skill_discovery_module,
        "entry_points",
        lambda *, group: [
            _fake_entry_point("investigation"),
            _fake_entry_point("data_security"),
        ],
    )
    registries = discover_all_agent_skills(
        workspace_root=tmp_path,
        agent_filter={"investigation"},
    )
    assert set(registries.keys()) == {"investigation"}


def test_discover_all_empty_registry_for_v0_1_agents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Two agents registered; only ``investigation`` has a skills dir on
    # disk. The other (v0.1 with no skills dir) must produce an empty
    # registry without raising — drift #5 backwards-compat probe.
    _write_bundled_skill(tmp_path, "investigation", "iam/x")
    monkeypatch.setattr(
        skill_discovery_module,
        "entry_points",
        lambda *, group: [
            _fake_entry_point("investigation"),
            _fake_entry_point("vulnerability"),
        ],
    )
    registries = discover_all_agent_skills(workspace_root=tmp_path)
    assert registries["investigation"].entries != ()
    assert registries["vulnerability"].entries == ()


# ---------------------------- helpers + error path ----------------------------


def test_default_shadow_skills_dir_layout(tmp_path: Path) -> None:
    assert (
        default_shadow_skills_dir(tmp_path, "investigation")
        == tmp_path / ".nexus" / "candidate-skills" / "investigation"
    )


def test_malformed_frontmatter_raises_skill_loader_error(tmp_path: Path) -> None:
    skills_dir = default_bundled_nlah_dir(tmp_path, "investigation") / "skills" / "bad/here"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("# No frontmatter at all.\n", encoding="utf-8")
    with pytest.raises(SkillLoaderError, match="missing YAML frontmatter"):
        discover_agent_skills("investigation", workspace_root=tmp_path)
