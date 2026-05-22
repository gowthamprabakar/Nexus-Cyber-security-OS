"""Tests — `meta_harness.skill_format` (Task 3).

12 tests covering the agentskills.io YAML-frontmatter parser +
writer:

1.  Minimal valid SKILL.md parses cleanly.
2.  Missing frontmatter fences -> SkillFormatError.
3.  Malformed YAML frontmatter -> SkillFormatError.
4.  Frontmatter not a mapping -> SkillFormatError.
5.  Missing required key (e.g. ``target_agent``) -> SkillFormatError
    with the missing-keys list.
6.  ``platforms`` must be a list.
7.  ``provenance`` entries must be 2-item lists.
8.  Unknown ``eval_gate_status`` value -> SkillFormatError.
9.  Unknown ``deployment_status`` value -> SkillFormatError.
10. ``serialize_skill_md`` round-trips through ``parse_skill_md_content``
    (frontmatter + body preserved).
11. ``write_skill_md`` creates parent dirs + writes file; the file
    round-trips back to the original Skill.
12. ``parse_skill_md`` raises on missing file path.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from meta_harness.schemas import Skill, SkillDeploymentStatus, SkillEvalGateStatus
from meta_harness.skill_format import (
    SkillFormatError,
    parse_skill_md,
    parse_skill_md_content,
    serialize_skill_md,
    write_skill_md,
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


def test_minimal_skill_md_parses_cleanly() -> None:
    skill = parse_skill_md_content(_MINIMAL_SKILL_MD)
    assert isinstance(skill, Skill)
    assert skill.name == "aws_iam_privesc_via_assumed_role"
    assert skill.target_agent == "investigation"
    assert skill.category == "iam-privesc"
    assert skill.platforms == ("nexus",)
    assert skill.provenance == (("audit/r_eval.jsonl", "deadbeefcafebabe"),)
    assert skill.deployment_status == SkillDeploymentStatus.CANDIDATE
    assert skill.eval_gate_status == SkillEvalGateStatus.NOT_RUN
    assert "cross-account AssumeRole" in skill.body


def test_missing_frontmatter_fences_raises() -> None:
    with pytest.raises(SkillFormatError, match="missing YAML frontmatter"):
        parse_skill_md_content("# Just a markdown body, no fences.\n")


def test_malformed_yaml_frontmatter_raises() -> None:
    text = "---\nname: x\n  bad indent: [\n---\nbody\n"
    with pytest.raises(SkillFormatError, match="malformed YAML"):
        parse_skill_md_content(text)


def test_frontmatter_must_be_mapping() -> None:
    text = "---\n- not_a_mapping\n- entries\n---\n"
    with pytest.raises(SkillFormatError, match="must be a YAML mapping"):
        parse_skill_md_content(text)


def test_missing_required_key_raises_with_keys_listed() -> None:
    text = """---
name: x
description: y
version: 0.1.0
platforms:
  - nexus
category: c
created_by: meta_harness@v0.2.0
---
body
"""
    with pytest.raises(SkillFormatError, match="target_agent"):
        parse_skill_md_content(text)


def test_platforms_must_be_a_list() -> None:
    text = """---
name: x
description: y
version: 0.1.0
platforms: not_a_list
target_agent: investigation
category: c
created_by: meta_harness@v0.2.0
---
body
"""
    with pytest.raises(SkillFormatError, match="'platforms' must be a list"):
        parse_skill_md_content(text)


def test_provenance_entries_must_be_pairs() -> None:
    text = """---
name: x
description: y
version: 0.1.0
platforms:
  - nexus
target_agent: investigation
category: c
created_by: meta_harness@v0.2.0
provenance:
  - [single_element]
---
body
"""
    with pytest.raises(SkillFormatError, match="must be a 2-item list"):
        parse_skill_md_content(text)


def test_unknown_eval_gate_status_raises() -> None:
    text = """---
name: x
description: y
version: 0.1.0
platforms:
  - nexus
target_agent: investigation
category: c
created_by: meta_harness@v0.2.0
eval_gate_status: ferment
---
body
"""
    with pytest.raises(SkillFormatError, match="eval_gate_status"):
        parse_skill_md_content(text)


def test_unknown_deployment_status_raises() -> None:
    text = """---
name: x
description: y
version: 0.1.0
platforms:
  - nexus
target_agent: investigation
category: c
created_by: meta_harness@v0.2.0
deployment_status: stowed
---
body
"""
    with pytest.raises(SkillFormatError, match="deployment_status"):
        parse_skill_md_content(text)


def test_serialize_round_trips_through_parse() -> None:
    """serialize_skill_md(parse(...)) is structurally equivalent."""
    skill = parse_skill_md_content(_MINIMAL_SKILL_MD)
    re_serialised = serialize_skill_md(skill)
    skill_again = parse_skill_md_content(re_serialised)
    # Frontmatter fields preserved.
    assert skill_again.name == skill.name
    assert skill_again.description == skill.description
    assert skill_again.target_agent == skill.target_agent
    assert skill_again.category == skill.category
    assert skill_again.platforms == skill.platforms
    assert skill_again.provenance == skill.provenance
    assert skill_again.eval_gate_status == skill.eval_gate_status
    assert skill_again.deployment_status == skill.deployment_status
    # Body preserved (trailing newline is normalised on serialise).
    assert skill_again.body.strip() == skill.body.strip()


def test_write_skill_md_creates_parent_dirs_and_round_trips(tmp_path: Path) -> None:
    skill = parse_skill_md_content(_MINIMAL_SKILL_MD)
    target = tmp_path / "deep" / "nested" / "path" / "SKILL.md"
    written_path = write_skill_md(skill, target)
    assert written_path.is_file()
    assert written_path == target
    # Round-trip via parse_skill_md (file-based).
    skill_again = parse_skill_md(target)
    assert skill_again.name == skill.name
    assert skill_again.target_agent == skill.target_agent
    assert skill_again.body.strip() == skill.body.strip()


def test_parse_skill_md_raises_on_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SkillFormatError, match="not found"):
        parse_skill_md(tmp_path / "nope.md")
