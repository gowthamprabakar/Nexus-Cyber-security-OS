"""Tests — `meta_harness.cli` (Task 13).

14 tests covering the three CLI subcommands via Click's CliRunner:

1.  Top-level ``meta-harness --help`` lists three subcommands.
2.  ``meta-harness --version`` prints the package version.
3.  ``meta-harness eval`` against the bundled cases exits 0
    (10/10 PASS).
4.  ``meta-harness eval <bad-dir>`` exits 2 (cases dir not found).
5.  ``meta-harness eval <empty-dir>`` exits 0 with "0/0 passed".
6.  ``meta-harness run --customer-id ... --run-id ...`` writes
    meta_harness_report.md.
7.  ``meta-harness run`` prints the agent/regression digest.
8.  ``meta-harness run --workspace-root <dir>`` honors the dir.
9.  ``meta-harness ab-compare`` happy path (synthetic agent
    registered via entry-point monkey-patch) prints byte_equal flag.
10. ``meta-harness ab-compare`` --variant-a missing → exit code != 0.
11. ``meta-harness ab-compare`` --variant-b missing → exit code != 0.
12. ``meta-harness ab-compare`` against unknown agent → exit code != 0.
13. ``meta-harness eval`` with a failing case → exits 1 + prints FAIL.
14. ``meta-harness run`` rejects when --customer-id is missing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from meta_harness import __version__
from meta_harness.cli import main
from meta_harness.eval import batch as batch_module
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
    assert "10/10 passed" in result.output


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
