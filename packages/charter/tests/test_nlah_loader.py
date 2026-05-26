"""Tests for `charter.nlah_loader` — the canonical NLAH loader (ADR-007 v1.2)."""

from __future__ import annotations

from pathlib import Path

import pytest
from charter.nlah_loader import default_nlah_dir, load_system_prompt

# ---------------------------- default_nlah_dir ---------------------------


def test_default_nlah_dir_resolves_adjacent_to_package_file(tmp_path: Path) -> None:
    """Pass any file path and get `<that file's parent>/nlah/` back."""
    pkg_file = tmp_path / "module.py"
    pkg_file.write_text("")
    assert default_nlah_dir(pkg_file) == tmp_path / "nlah"


def test_default_nlah_dir_accepts_string_or_path(tmp_path: Path) -> None:
    pkg_file = tmp_path / "module.py"
    pkg_file.write_text("")
    assert default_nlah_dir(str(pkg_file)) == default_nlah_dir(pkg_file)


# ---------------------------- load_system_prompt -------------------------


def test_loader_with_readme_only(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Solo")
    assert load_system_prompt(tmp_path) == "# Solo"


def test_loader_concatenates_tools_section(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Header")
    (tmp_path / "tools.md").write_text("# Tool A\n\nDescription")

    out = load_system_prompt(tmp_path)
    assert "Header" in out
    assert "Tools reference" in out
    assert "Tool A" in out


def test_loader_concatenates_examples_in_lex_order(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Header")
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "001-first.md").write_text("# Example 1")
    (examples / "002-second.md").write_text("# Example 2")

    out = load_system_prompt(tmp_path)
    assert "Few-shot examples" in out
    assert out.find("Example 1") < out.find("Example 2")


def test_loader_omits_optional_sections_when_missing(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Solo")
    out = load_system_prompt(tmp_path)
    assert "Tools reference" not in out
    assert "Few-shot examples" not in out


def test_loader_handles_empty_examples_dir(tmp_path: Path) -> None:
    """An empty `examples/` directory must not emit the header."""
    (tmp_path / "README.md").write_text("# Solo")
    (tmp_path / "examples").mkdir()
    out = load_system_prompt(tmp_path)
    assert "Few-shot examples" not in out


# ---------------------------- error paths --------------------------------


def test_missing_dir_raises_clearly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="NLAH directory missing"):
        load_system_prompt(tmp_path / "does-not-exist")


def test_missing_readme_raises_clearly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match=r"README\.md"):
        load_system_prompt(tmp_path)


def test_loader_accepts_string_path(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Solo")
    assert load_system_prompt(str(tmp_path)) == "# Solo"


# ---------------------------------------------------------------------------
# ADR-007 v1.4 — progressive-disclosure skill loader (additive surface)
# ---------------------------------------------------------------------------


from charter.nlah_loader import (  # noqa: E402  (additive imports below v1.2 tests)
    SkillLoaderError,
    SkillMetadataEntry,
    default_skills_dir,
    load_skill,
    load_skill_metadata_index,
    load_skill_reference,
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


def _write_skill(skills_root: Path, skill_id: str, content: str = _MINIMAL_SKILL_MD) -> Path:
    skill_dir = skills_root / skill_id
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_path = skill_dir / "SKILL.md"
    skill_path.write_text(content, encoding="utf-8")
    return skill_path


def test_default_skills_dir_returns_sibling_of_nlah(tmp_path: Path) -> None:
    """``default_skills_dir(file)`` -> ``<file_parent>/nlah/skills``."""
    fake_module = tmp_path / "src" / "agent_x" / "__init__.py"
    fake_module.parent.mkdir(parents=True, exist_ok=True)
    fake_module.touch()
    assert default_skills_dir(fake_module) == tmp_path / "src" / "agent_x" / "nlah" / "skills"


def test_metadata_index_empty_when_skills_dir_missing(tmp_path: Path) -> None:
    """Backwards-compat — agent ships no skills dir -> empty tuple."""
    # tmp_path has NO skills/ subdir.
    result = load_skill_metadata_index(tmp_path)
    assert result == ()


def test_metadata_index_returns_entries_for_each_skill(tmp_path: Path) -> None:
    skills_root = tmp_path / "skills"
    _write_skill(skills_root, "iam-privesc/aws-assumed-role-chain")
    result = load_skill_metadata_index(tmp_path)
    assert len(result) == 1
    entry = result[0]
    assert isinstance(entry, SkillMetadataEntry)
    assert entry.skill_id == "iam-privesc/aws-assumed-role-chain"
    assert entry.name == "aws_iam_privesc_via_assumed_role"
    assert entry.category == "iam-privesc"
    assert entry.target_agent == "investigation"
    assert entry.source == "bundled"


def test_metadata_index_sorted_by_skill_id(tmp_path: Path) -> None:
    skills_root = tmp_path / "skills"
    _write_skill(skills_root, "zeta/last")
    _write_skill(skills_root, "alpha/first")
    result = load_skill_metadata_index(tmp_path)
    assert [e.skill_id for e in result] == ["alpha/first", "zeta/last"]


def test_metadata_index_overlay_takes_precedence(tmp_path: Path) -> None:
    """Overlay-supplied skill with the same skill_id masks the
    bundled version (per the eval-gate's candidate workflow)."""
    bundled_root = tmp_path / "skills"
    overlay_root = tmp_path / "candidates"
    _write_skill(bundled_root, "iam-privesc/role-chain")  # bundled
    _write_skill(overlay_root, "iam-privesc/role-chain")  # overlay shadow

    result = load_skill_metadata_index(tmp_path, skills_overlay=overlay_root)
    assert len(result) == 1
    assert result[0].source == "overlay"


def test_metadata_index_missing_frontmatter_raises(tmp_path: Path) -> None:
    skills_root = tmp_path / "skills" / "x" / "y"
    skills_root.mkdir(parents=True)
    (skills_root / "SKILL.md").write_text("# No frontmatter here.\n", encoding="utf-8")
    with pytest.raises(SkillLoaderError, match="missing YAML frontmatter"):
        load_skill_metadata_index(tmp_path)


def test_metadata_index_missing_required_key_raises(tmp_path: Path) -> None:
    skills_root = tmp_path / "skills"
    bad = """---
name: x
description: y
version: 0.1.0
platforms:
  - nexus
target_agent: investigation
---
body
"""
    # missing `category`
    _write_skill(skills_root, "noop/bad", content=bad)
    with pytest.raises(SkillLoaderError, match="category"):
        load_skill_metadata_index(tmp_path)


def test_load_skill_returns_full_text(tmp_path: Path) -> None:
    skills_root = tmp_path / "skills"
    _write_skill(skills_root, "iam-privesc/role-chain")
    text = load_skill(tmp_path, "iam-privesc/role-chain")
    assert "aws_iam_privesc_via_assumed_role" in text
    assert "cross-account AssumeRole" in text


def test_load_skill_overlay_first(tmp_path: Path) -> None:
    bundled_root = tmp_path / "skills"
    overlay_root = tmp_path / "candidates"
    _write_skill(bundled_root, "iam/x", content=_MINIMAL_SKILL_MD.replace("0.1.0", "0.1.0-bundled"))
    _write_skill(overlay_root, "iam/x", content=_MINIMAL_SKILL_MD.replace("0.1.0", "0.1.0-overlay"))
    text = load_skill(tmp_path, "iam/x", skills_overlay=overlay_root)
    assert "0.1.0-overlay" in text
    assert "0.1.0-bundled" not in text


def test_load_skill_missing_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="iam-privesc/ghost"):
        load_skill(tmp_path, "iam-privesc/ghost")


def test_load_skill_reference_returns_referenced_file(tmp_path: Path) -> None:
    skills_root = tmp_path / "skills"
    skill_path = _write_skill(skills_root, "iam/x")
    references = skill_path.parent / "references"
    references.mkdir()
    (references / "note.md").write_text("# Helper note\n", encoding="utf-8")
    text = load_skill_reference(tmp_path, "iam/x", "note.md")
    assert "Helper note" in text


def test_load_skill_reference_missing_raises(tmp_path: Path) -> None:
    skills_root = tmp_path / "skills"
    _write_skill(skills_root, "iam/x")
    with pytest.raises(FileNotFoundError, match=r"references/missing\.md"):
        load_skill_reference(tmp_path, "iam/x", "missing.md")


def test_v1_2_surface_unchanged_after_v1_4_extension(tmp_path: Path) -> None:
    """**v1.2 backwards-compat regression probe.** The existing
    ``default_nlah_dir`` + ``load_system_prompt`` surface MUST be
    untouched by the v1.4 amendment. Agents on v0.1 shim continue
    to work identically."""
    nlah = tmp_path / "nlah"
    nlah.mkdir()
    (nlah / "README.md").write_text("# v1.2 still works\n", encoding="utf-8")
    text = load_system_prompt(nlah)
    assert "# v1.2 still works" in text


def test_metadata_index_skill_with_no_skills_overlay_is_bundled_source(tmp_path: Path) -> None:
    """When no overlay is provided, all entries must report
    ``source='bundled'``."""
    skills_root = tmp_path / "skills"
    _write_skill(skills_root, "alpha/one")
    _write_skill(skills_root, "beta/two")
    result = load_skill_metadata_index(tmp_path)
    assert {entry.source for entry in result} == {"bundled"}


# ---------------------------------------------------------------------------
# G2 Task 4 — SkillMetadataEntry effectiveness fields
# ---------------------------------------------------------------------------


def test_skill_metadata_entry_effectiveness_fields_default_to_none() -> None:
    """Backwards-compat — constructing without effectiveness fields
    defaults all three to None."""
    entry = SkillMetadataEntry(
        skill_id="test/x",
        name="test-skill",
        description="A test skill.",
        version="0.1.0",
        category="test",
        target_agent="test-agent",
        platforms=("nexus",),
        source="bundled",
    )
    assert entry.effectiveness_score is None
    assert entry.effectiveness_confidence is None
    assert entry.effectiveness_last_updated is None


def test_skill_metadata_entry_accepts_effectiveness_values() -> None:
    """All three effectiveness fields accept valid values."""
    entry = SkillMetadataEntry(
        skill_id="test/x",
        name="test-skill",
        description="A test skill.",
        version="0.1.0",
        category="test",
        target_agent="test-agent",
        platforms=("nexus",),
        source="bundled",
        effectiveness_score=0.85,
        effectiveness_confidence=0.92,
        effectiveness_last_updated="2026-05-26T12:00:00Z",
    )
    assert entry.effectiveness_score == 0.85
    assert entry.effectiveness_confidence == 0.92
    assert entry.effectiveness_last_updated == "2026-05-26T12:00:00Z"


def test_skill_metadata_entry_boundary_values() -> None:
    """Effectiveness scores and confidence accept boundary float values."""
    for val in (0.0, 0.5, 1.0):
        entry = SkillMetadataEntry(
            skill_id="test/x",
            name="t",
            description="d",
            version="0.1.0",
            category="c",
            target_agent="a",
            platforms=("nexus",),
            source="bundled",
            effectiveness_score=val,
            effectiveness_confidence=val,
        )
        assert entry.effectiveness_score == val
        assert entry.effectiveness_confidence == val


def test_metadata_index_entries_have_none_effectiveness_by_default(tmp_path: Path) -> None:
    """Integration — existing YAML without effectiveness fields produces
    entries with None for all three G2 fields."""
    skills_root = tmp_path / "skills"
    _write_skill(skills_root, "alpha/one")
    result = load_skill_metadata_index(tmp_path)
    assert len(result) == 1
    entry = result[0]
    assert entry.effectiveness_score is None
    assert entry.effectiveness_confidence is None
    assert entry.effectiveness_last_updated is None


def test_skill_metadata_entry_effectiveness_partial_population() -> None:
    """Each effectiveness field is independently optional — one can be
    set while others remain None."""
    entry = SkillMetadataEntry(
        skill_id="test/x",
        name="t",
        description="d",
        version="0.1.0",
        category="c",
        target_agent="a",
        platforms=("nexus",),
        source="bundled",
        effectiveness_score=0.75,
    )
    assert entry.effectiveness_score == 0.75
    assert entry.effectiveness_confidence is None
    assert entry.effectiveness_last_updated is None
