"""Tests — NLAH bundle v0.2.5 persona + tools + G1 example (Task 14).

25 tests covering the NLAH bundle's v0.2 + v0.2.5 surface. The bundle is what
A.4 itself loads at runtime, so its content is part of the
configuration contract — these tests lock the v0.2 / v0.2.5 phrasing in place
so future edits surface as deliberate diffs.

README.md (10 tests):
1.  Mentions v0.2 explicitly.
2.  Pipeline section names 8 stages, not 6.
3.  Stage 6 SKILL_TRIGGER described.
4.  Stage 7 SKILL_CREATE described.
5.  References ADR-007 v1.4 (progressive-disclosure loader).
6.  References ADR-012 v1.1 (third forbidden subscriber).
7.  "What you do NOT do" section explicitly mentions DSPy+GEPA v0.2.5
    forward-carry.
8.  Shadow path layout documented verbatim.
9.  Persona enumerates G1 effectiveness-scoring capability.
10. References ADR-007 v1.5 (G1 canonical patterns).

tools.md (9 tests):
9.  (reindexed) v0.2 audit-action vocabulary lists 4 new entries.
10. Total audit-action count documented as 8 in v0.2.
11. Skill-lifecycle helpers section names all 6 modules (Tasks 5-10).
12. References the deployed_tool_sequence_hashes registry input.
13. References Q-ARCH-1 fence enforcement.
14. Documents G1 CLI commands (score-effectiveness, rate-skill).
15. Documents 6 G1 audit actions (agent.skill.* + meta_harness.skill.*).
16. Documents G1 Python API surface (compute_effectiveness_score,
    get_effectiveness_score, write_effectiveness_score,
    apply_backwards_compat_reason).

examples/05-effectiveness-scoring.md (5 tests):
17. File exists.
18. Describes full scoring lifecycle (deploy → emit → score → rate → GEPA).
19. Names CLI commands verbatim.
20. Documents audit-chain trace.
21. References backwards-compat path for Wave 0 agents.

examples/ count (1 test):
22. Examples dir now has 5 files (was 4 in v0.2 — 05 added in v0.2.5).
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


# ---------------------------- README.md G1 additions ----------------------------


def test_readme_enumerates_g1_effectiveness_scoring(readme_text: str) -> None:
    """v0.2.5 persona must state A.4 measures skill effectiveness."""
    assert "effectiveness" in readme_text.lower()
    assert "G1" in readme_text or "composite" in readme_text
    assert "adoption" in readme_text
    assert "outcome correlation" in readme_text or "outcome" in readme_text
    assert "operator feedback" in readme_text or "feedback" in readme_text


def test_readme_references_adr_007_v1_5(readme_text: str) -> None:
    """The persona should point maintainers at the G1 canonical patterns amendment."""
    assert "ADR-007 v1.5" in readme_text


# ---------------------------- tools.md G1 additions ----------------------------


def test_tools_documents_g1_cli_commands(tools_text: str) -> None:
    """tools.md must document score-effectiveness and rate-skill CLI commands."""
    assert "score-effectiveness" in tools_text
    assert "rate-skill" in tools_text
    assert "--rating" in tools_text
    assert "useful|neutral|harmful" in tools_text or "{useful" in tools_text
    assert "--agent" in tools_text


def test_tools_documents_g1_audit_actions(tools_text: str) -> None:
    """tools.md must name all 6 G1 effectiveness audit actions."""
    for action in (
        "agent.skill.loaded",
        "agent.skill.contributed",
        "agent.skill.outcome_correlated",
        "agent.skill.operator_rated",
        "meta_harness.skill.effectiveness_updated",
        "meta_harness.skill.effectiveness_error",
    ):
        assert action in tools_text


def test_tools_documents_g1_python_api(tools_text: str) -> None:
    """tools.md must document the G1 Python API surface."""
    for api in (
        "compute_effectiveness_score",
        "get_effectiveness_score",
        "write_effectiveness_score",
        "apply_backwards_compat_reason",
        "emit_skill_loaded",
        "emit_skill_contributed",
    ):
        assert api in tools_text


# ---------------------------- examples/05-effectiveness-scoring.md ----------------------------


@pytest.fixture(scope="module")
def example_05_text() -> str:
    return (NLAH_DIR / "examples" / "05-effectiveness-scoring.md").read_text(encoding="utf-8")


def test_example_05_file_exists() -> None:
    path = NLAH_DIR / "examples" / "05-effectiveness-scoring.md"
    assert path.is_file()


def test_example_05_describes_full_scoring_lifecycle(example_05_text: str) -> None:
    """The example must walk through deploy → emit → score → rate → GEPA."""
    assert "Step 1" in example_05_text
    assert "Step 2" in example_05_text
    assert "Step 3" in example_05_text
    assert "Step 4" in example_05_text
    assert "Step 5" in example_05_text
    assert "emit_skill_loaded" in example_05_text
    assert "emit_skill_contributed" in example_05_text
    assert "score-effectiveness" in example_05_text
    assert "rate-skill" in example_05_text
    assert "GEPA" in example_05_text


def test_example_05_documents_audit_chain_trace(example_05_text: str) -> None:
    """The example must show the full audit-chain trace after scoring."""
    assert "audit chain" in example_05_text
    assert "outcome_correlated" in example_05_text
    assert "effectiveness_updated" in example_05_text
    assert "operator_rated" in example_05_text


def test_example_05_references_backwards_compat(example_05_text: str) -> None:
    """The example must mention the backwards-compat path for Wave 0 agents."""
    assert "backwards-compat" in example_05_text or "Wave 0" in example_05_text
    assert "agent_not_emitting_events" in example_05_text


# ---------------------------- examples/ count ----------------------------


def test_examples_dir_has_five_files() -> None:
    """v0.2.5 adds 05-effectiveness-scoring.md (was 4 in v0.2)."""
    examples_dir = NLAH_DIR / "examples"
    md_files = sorted(examples_dir.glob("*.md"))
    assert len(md_files) == 5, (
        f"expected 5 examples, got {len(md_files)}: {[f.name for f in md_files]}"
    )
