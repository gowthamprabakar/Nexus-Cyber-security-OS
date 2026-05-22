"""Tests — ``meta_harness.cli`` (Tasks 13 + 15).

20 tests covering the CLI subcommands via Click's CliRunner:

v0.1 diagnostic:
1.  ``--help`` lists subcommands.
2.  ``--version`` prints the package version.
3.  ``eval`` against bundled cases exits 0 (15/15 PASS).
4.  ``eval <bad-dir>`` exits 2.
5.  ``eval <empty-dir>`` exits 0 with "0/0 passed".
6.  ``run`` writes meta_harness_report.md.
7.  ``run`` prints the agent/regression digest.
8.  ``run --workspace-root`` honors the dir.
9.  ``ab-compare`` happy path prints byte_equal flag.
10. ``ab-compare`` --variant-a missing → error.
11. ``ab-compare`` --variant-b missing → error.
12. ``ab-compare`` unknown agent → error.
13. ``eval`` failing case → exits 1 + prints FAIL.
14. ``run`` rejects missing --customer-id.

v0.2 skill-curation (Task 15):
15. ``approve-skill`` promotes a candidate out of the shadow tree.
16. ``approve-skill`` on nonexistent skill_id → exits 1.
17. ``reject-skill`` removes candidate + cleans up.
18. ``reject-skill`` missing --reason → error.
19. ``list-skills`` prints pending candidates.
20. ``list-skills`` prints "no pending candidates" when empty.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from meta_harness import __version__
from meta_harness.cli import main
from meta_harness.eval import batch as batch_module
from meta_harness.schemas import (
    Skill,
    SkillCandidate,
    SkillDeploymentStatus,
    SkillEvalGateStatus,
)
from meta_harness.skill_candidate_store import write_candidate_meta
from meta_harness.tools import ab_compare as ab_module


@pytest.fixture
def cli() -> CliRunner:
    return CliRunner()


def test_help_lists_subcommands(cli: CliRunner) -> None:
    result = cli.invoke(main, ["--help"])
    assert result.exit_code == 0
    for sub in ("eval", "run", "ab-compare"):
        assert sub in result.output


def test_version_prints_package_version(cli: CliRunner) -> None:
    result = cli.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_eval_bundled_cases_pass(cli: CliRunner) -> None:
    result = cli.invoke(main, ["eval"])
    assert result.exit_code == 0, result.output
    assert "15/15 passed" in result.output


def test_eval_bad_dir_exits_2(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(main, ["eval", str(tmp_path / "nope")])
    assert result.exit_code != 0  # Click validates the path exists


def test_eval_empty_dir_exits_0(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(main, ["eval", str(tmp_path)])
    assert result.exit_code == 0
    assert "0/0 passed" in result.output


def test_run_writes_report_markdown(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(batch_module, "entry_points", lambda *, group: [])
    monkeypatch.setattr(ab_module, "entry_points", lambda *, group: [])

    result = cli.invoke(
        main,
        [
            "run",
            "--customer-id",
            "acme",
            "--run-id",
            "r1",
            "--workspace-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "meta_harness_report.md").is_file()


def test_run_prints_digest(cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(batch_module, "entry_points", lambda *, group: [])
    monkeypatch.setattr(ab_module, "entry_points", lambda *, group: [])

    result = cli.invoke(
        main,
        [
            "run",
            "--customer-id",
            "acme",
            "--run-id",
            "r1",
            "--workspace-root",
            str(tmp_path),
        ],
    )
    assert "evaluated 0 agent(s)" in result.output
    assert "0 regression(s) flagged" in result.output


def test_run_honors_workspace_root(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(batch_module, "entry_points", lambda *, group: [])
    monkeypatch.setattr(ab_module, "entry_points", lambda *, group: [])

    target = tmp_path / "custom_ws"
    result = cli.invoke(
        main,
        [
            "run",
            "--customer-id",
            "acme",
            "--run-id",
            "r1",
            "--workspace-root",
            str(target),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (target / "meta_harness_report.md").is_file()


def _stub_entry_point_for(agent_id: str) -> Any:
    from dataclasses import dataclass

    class _Runner:
        @property
        def agent_name(self) -> str:
            return agent_id

        async def run(
            self,
            case: Any,
            *,
            workspace: Any,
            llm_provider: Any | None = None,
        ) -> Any:
            del case, workspace, llm_provider
            return True, None, {"k": "v"}, None

    @dataclass(frozen=True)
    class _EP:
        name: str
        group: str

        def load(self) -> Any:
            return _Runner

    return _EP(name=agent_id, group="nexus_eval_runners")


def _make_nlah_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "README.md").write_text("# X\n\nA test variant.\n", encoding="utf-8")
    return path


def _make_cases_dir(path: Path, case_id: str = "c1") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / f"{case_id}.yaml").write_text(
        f"case_id: {case_id}\ndescription: t\nfixture: {{}}\nexpected: {{}}\n",
        encoding="utf-8",
    )
    return path


def test_ab_compare_happy_path(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ep = _stub_entry_point_for("agent_x")
    monkeypatch.setattr(batch_module, "entry_points", lambda *, group: [ep])
    monkeypatch.setattr(ab_module, "entry_points", lambda *, group: [ep])

    workspace = tmp_path / "ws"
    # The default cases_root resolver maps agent_id -> workspace/packages/agents/<kebab>/eval/cases.
    _make_cases_dir(
        workspace / "packages" / "agents" / "agent-x" / "eval" / "cases",
        case_id="cx",
    )
    nlah_a = _make_nlah_dir(tmp_path / "nlah_a")
    nlah_b = _make_nlah_dir(tmp_path / "nlah_b")

    result = cli.invoke(
        main,
        [
            "ab-compare",
            "agent_x",
            "--variant-a",
            str(nlah_a),
            "--variant-b",
            str(nlah_b),
            "--workspace-root",
            str(workspace),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "agent_id=agent_x" in result.output
    assert "byte_equal=" in result.output


def test_ab_compare_missing_variant_a_fails(cli: CliRunner, tmp_path: Path) -> None:
    nlah_b = _make_nlah_dir(tmp_path / "b")
    result = cli.invoke(
        main,
        ["ab-compare", "x", "--variant-b", str(nlah_b)],
    )
    assert result.exit_code != 0
    assert "variant-a" in result.output.lower() or "variant-b" in result.output.lower()


def test_ab_compare_missing_variant_b_fails(cli: CliRunner, tmp_path: Path) -> None:
    nlah_a = _make_nlah_dir(tmp_path / "a")
    result = cli.invoke(
        main,
        ["ab-compare", "x", "--variant-a", str(nlah_a)],
    )
    assert result.exit_code != 0


def test_ab_compare_unknown_agent_errors(
    cli: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(batch_module, "entry_points", lambda *, group: [])
    monkeypatch.setattr(ab_module, "entry_points", lambda *, group: [])

    nlah_a = _make_nlah_dir(tmp_path / "a")
    nlah_b = _make_nlah_dir(tmp_path / "b")

    result = cli.invoke(
        main,
        [
            "ab-compare",
            "ghost",
            "--variant-a",
            str(nlah_a),
            "--variant-b",
            str(nlah_b),
            "--workspace-root",
            str(tmp_path / "ws"),
        ],
    )
    assert result.exit_code != 0


def test_eval_failing_case_exits_1(cli: CliRunner, tmp_path: Path) -> None:
    """Synthetic eval case whose expected counts don't match actuals."""
    cases_dir = tmp_path / "cases"
    cases_dir.mkdir()
    (cases_dir / "bad.yaml").write_text(
        "case_id: bad\n"
        "description: synthetic-failure case\n"
        "fixture:\n"
        "  agents: []\n"
        "expected:\n"
        "  total_agents_evaluated: 99\n",  # impossible
        encoding="utf-8",
    )
    result = cli.invoke(main, ["eval", str(cases_dir)])
    assert result.exit_code == 1
    assert "FAIL bad" in result.output


def test_run_rejects_missing_customer_id(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(main, ["run", "--run-id", "r1", "--workspace-root", str(tmp_path)])
    assert result.exit_code != 0
    assert "customer-id" in result.output.lower()


# ---------------------- v0.2 skill-curation CLI tests (Task 15) ------------


_EMITTED_AT = datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC)


def _seed_candidate(
    workspace: Path,
    *,
    agent_id: str = "investigation",
    skill_id: str = "iam-privesc/test-skill",
    tool_sequence_hash: str = "abc123",
) -> SkillCandidate:
    category, name = skill_id.split("/", 1)
    skill = Skill(
        name=name,
        description="A test skill.",
        version="0.1.0",
        platforms=("nexus",),
        target_agent=agent_id,
        category=category,
        created_by="meta_harness@v0.2.0",
        provenance=(),
        eval_gate_status=SkillEvalGateStatus.PASSED,
        deployment_status=SkillDeploymentStatus.CANDIDATE,
        body="Test body.",
    )
    candidate = SkillCandidate(
        skill_id=skill_id,
        skill=skill,
        shadow_path=str(
            workspace / ".nexus" / "candidate-skills" / agent_id / skill_id / "SKILL.md"
        ),
        tool_sequence_hash=tool_sequence_hash,
        emitted_at=_EMITTED_AT,
    )
    # Write shadow SKILL.md + sidecar.
    from meta_harness.skill_format import write_skill_md

    Path(candidate.shadow_path).parent.mkdir(parents=True, exist_ok=True)
    write_skill_md(skill, Path(candidate.shadow_path))
    write_candidate_meta(candidate, workspace_root=workspace)
    return candidate


def test_help_lists_skill_curation_subcommands(cli: CliRunner) -> None:
    result = cli.invoke(main, ["--help"])
    assert result.exit_code == 0
    for sub in ("approve-skill", "reject-skill", "list-skills"):
        assert sub in result.output


def test_approve_skill_promotes_candidate(cli: CliRunner, tmp_path: Path) -> None:
    skill_id = "iam-privesc/test-skill"
    _seed_candidate(tmp_path, skill_id=skill_id)

    result = cli.invoke(
        main,
        ["approve-skill", skill_id, "--workspace-root", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    assert f"approved {skill_id}" in result.output
    # Canonical SKILL.md should exist.
    canonical = (
        tmp_path
        / "packages"
        / "agents"
        / "investigation"
        / "src"
        / "investigation"
        / "nlah"
        / "skills"
        / skill_id
        / "SKILL.md"
    )
    assert canonical.is_file()
    # Shadow should be gone.
    shadow = tmp_path / ".nexus" / "candidate-skills" / "investigation" / skill_id / "SKILL.md"
    assert not shadow.is_file()
    # Sidecar should be gone.
    meta = (
        tmp_path
        / ".nexus"
        / "candidate-skills"
        / "investigation"
        / skill_id
        / "candidate_meta.json"
    )
    assert not meta.is_file()
    # Registry should exist.
    assert (tmp_path / ".nexus" / "skill-class-registry.json").is_file()


def test_approve_skill_missing_skill_id_fails(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        ["approve-skill", "nonexistent/skill", "--workspace-root", str(tmp_path)],
    )
    assert result.exit_code != 0


def test_reject_skill_removes_candidate(cli: CliRunner, tmp_path: Path) -> None:
    skill_id = "iam-privesc/test-skill"
    _seed_candidate(tmp_path, skill_id=skill_id)

    result = cli.invoke(
        main,
        [
            "reject-skill",
            skill_id,
            "--reason",
            "not production quality",
            "--workspace-root",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert f"rejected {skill_id}" in result.output
    # Shadow should be gone.
    shadow = tmp_path / ".nexus" / "candidate-skills" / "investigation" / skill_id / "SKILL.md"
    assert not shadow.is_file()
    # Sidecar should be gone.
    meta = (
        tmp_path
        / ".nexus"
        / "candidate-skills"
        / "investigation"
        / skill_id
        / "candidate_meta.json"
    )
    assert not meta.is_file()


def test_reject_skill_missing_reason_fails(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(
        main,
        ["reject-skill", "x/y", "--workspace-root", str(tmp_path)],
    )
    assert result.exit_code != 0


def test_list_skills_prints_pending(cli: CliRunner, tmp_path: Path) -> None:
    _seed_candidate(tmp_path, agent_id="agent_a", skill_id="cat/skill_a")
    _seed_candidate(tmp_path, agent_id="agent_b", skill_id="cat/skill_b")

    result = cli.invoke(main, ["list-skills", "--workspace-root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "skill_a" in result.output
    assert "skill_b" in result.output
    assert "agent=agent_a" in result.output
    assert "agent=agent_b" in result.output


def test_list_skills_empty(cli: CliRunner, tmp_path: Path) -> None:
    result = cli.invoke(main, ["list-skills", "--workspace-root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "no pending candidates" in result.output
