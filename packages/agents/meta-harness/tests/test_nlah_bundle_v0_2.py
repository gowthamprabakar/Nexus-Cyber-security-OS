"""Tests — NLAH bundle v0.2 persona + tools + new example (Task 14).

17 tests covering the NLAH bundle's v0.2 surface. The bundle is what
A.4 itself loads at runtime, so its content is part of the
configuration contract — these tests lock the v0.2 phrasing in place
so future edits surface as deliberate diffs.

README.md (8 tests):
1.  Mentions v0.2 explicitly.
2.  Pipeline section names 8 stages, not 6.
3.  Stage 6 SKILL_TRIGGER described.
4.  Stage 7 SKILL_CREATE described.
5.  References ADR-007 v1.4 (progressive-disclosure loader).
6.  References ADR-012 v1.1 (third forbidden subscriber).
7.  "What you do NOT do" section explicitly mentions DSPy+GEPA v0.2.5
    forward-carry.
8.  Shadow path layout documented verbatim.

tools.md (5 tests):
9.   v0.2 audit-action vocabulary lists 4 new entries.
10.  Total audit-action count documented as 8 in v0.2.
11.  Skill-lifecycle helpers section names all 6 modules (Tasks 5-10).
12.  References the deployed_tool_sequence_hashes registry input.
13.  References Q-ARCH-1 fence enforcement.

examples/04-skill-curation.md (4 tests):
14. File exists.
15. Lists three routing paths (reject / operator approval / auto-deploy).
16. Names ``meta-harness approve-skill`` / ``reject-skill`` CLI invocations.
17. Documents Q4 mandatory eval-gate (no --force).
"""

from __future__ import annotations

from pathlib import Path

import pytest

NLAH_DIR = Path(__file__).resolve().parent.parent / "src" / "meta_harness" / "nlah"


@pytest.fixture(scope="module")
def readme_text() -> str:
    return (NLAH_DIR / "README.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def tools_text() -> str:
    return (NLAH_DIR / "tools.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def example_04_text() -> str:
    return (NLAH_DIR / "examples" / "04-skill-curation.md").read_text(encoding="utf-8")


# ---------------------------- README.md ----------------------------


def test_readme_mentions_v0_2_explicitly(readme_text: str) -> None:
    assert "v0.2" in readme_text


def test_readme_pipeline_section_names_8_stages(readme_text: str) -> None:
    assert "8 stages" in readme_text or "Pipeline (8 stages" in readme_text


def test_readme_describes_stage_6_skill_trigger(readme_text: str) -> None:
    assert "SKILL_TRIGGER" in readme_text


def test_readme_describes_stage_7_skill_create(readme_text: str) -> None:
    assert "SKILL_CREATE" in readme_text


def test_readme_references_adr_007_v1_4(readme_text: str) -> None:
    assert "ADR-007 v1.4" in readme_text


def test_readme_references_adr_012_v1_1(readme_text: str) -> None:
    assert "ADR-012 §v1.1" in readme_text or "ADR-012 v1.1" in readme_text


def test_readme_forward_carries_dspy_gepa_to_v0_2_5(readme_text: str) -> None:
    """The persona MUST point future maintainers at the DSPy+GEPA brief."""
    assert "v0.2.5" in readme_text
    assert "DSPy" in readme_text or "dspy-gepa" in readme_text


def test_readme_documents_shadow_path_layout(readme_text: str) -> None:
    assert ".nexus/candidate-skills/" in readme_text


# ---------------------------- tools.md ----------------------------


def test_tools_lists_v0_2_audit_actions(tools_text: str) -> None:
    for action in (
        "meta_harness.skill.candidate_emitted",
        "meta_harness.skill.eval_gate_completed",
        "meta_harness.skill.deployed",
        "meta_harness.skill.rejected",
    ):
        assert action in tools_text


def test_tools_documents_total_action_count_eight_in_v0_2(tools_text: str) -> None:
    assert "total 8" in tools_text or ("Total" in tools_text and "8" in tools_text)


def test_tools_names_all_six_skill_lifecycle_modules(tools_text: str) -> None:
    for module in (
        "skill_discovery",
        "skill_triggers",
        "skill_writer",
        "skill_eval_gate",
        "skill_registry",
        "skill_approval",
    ):
        assert module in tools_text


def test_tools_references_deployed_tool_sequence_hashes_input(tools_text: str) -> None:
    assert "deployed_tool_sequence_hashes" in tools_text


def test_tools_references_q_arch_1_fence(tools_text: str) -> None:
    assert "ADR-012" in tools_text and (
        "v1.1" in tools_text or "Q-ARCH-1" in tools_text or "forbidden-subscriber" in tools_text
    )


# ---------------------------- examples/04-skill-curation.md ----------------------------


def test_example_04_file_exists() -> None:
    path = NLAH_DIR / "examples" / "04-skill-curation.md"
    assert path.is_file()


def test_example_04_lists_three_routing_paths(example_04_text: str) -> None:
    # The three Path A / B / C sections are the explicit walkthrough.
    assert "Path A" in example_04_text
    assert "Path B" in example_04_text
    assert "Path C" in example_04_text


def test_example_04_names_cli_commands(example_04_text: str) -> None:
    assert "meta-harness approve-skill" in example_04_text
    assert "meta-harness reject-skill" in example_04_text


def test_example_04_documents_mandatory_eval_gate_no_force(example_04_text: str) -> None:
    assert "mandatory" in example_04_text
    assert "--force" in example_04_text
