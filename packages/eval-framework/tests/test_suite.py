"""Tests for `run_suite` — async orchestration of an `EvalRunner` over cases."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, ModelTier, TokenUsage
from eval_framework.cases import EvalCase
from eval_framework.results import SuiteResult
from eval_framework.runner import FakeRunner
from eval_framework.suite import run_suite


def _case(case_id: str, *, timeout_sec: float = 60.0) -> EvalCase:
    return EvalCase(
        case_id=case_id,
        description=f"case {case_id}",
        fixture={},
        expected={},
        timeout_sec=timeout_sec,
    )


def _llm() -> FakeLLMProvider:
    return FakeLLMProvider(
        responses=[
            LLMResponse(
                text="ok",
                usage=TokenUsage(0, 0),
                stop_reason="end_turn",
                model_pin="claude-3-7-test",
                provider_id="fake",
            )
        ],
        provider_id="fake-anthropic",
        model_class=ModelTier.WORKHORSE,
    )


# ---------------------------- Happy path ----------------------------------


@pytest.mark.asyncio
async def test_run_suite_returns_suite_result(tmp_path: Path) -> None:
    cases = [_case("001"), _case("002"), _case("003")]
    runner = FakeRunner(agent_name="cloud_posture")

    result = await run_suite(cases, runner, workspace_root=tmp_path)

    assert isinstance(result, SuiteResult)
    assert result.runner == "cloud_posture"
    assert result.total == 3
    assert result.passed == 3
    assert result.pass_rate == 1.0
    assert result.completed_at >= result.started_at


@pytest.mark.asyncio
async def test_run_suite_preserves_case_order(tmp_path: Path) -> None:
    cases = [_case("003"), _case("001"), _case("002")]
    runner = FakeRunner()

    result = await run_suite(cases, runner, workspace_root=tmp_path)

    assert [c.case_id for c in result.cases] == ["003", "001", "002"]


@pytest.mark.asyncio
async def test_run_suite_propagates_runner_name(tmp_path: Path) -> None:
    runner = FakeRunner(agent_name="cloud_posture")
    result = await run_suite([_case("001")], runner, workspace_root=tmp_path)

    assert result.runner == "cloud_posture"
    assert result.cases[0].runner == "cloud_posture"


# ---------------------------- Mixed pass/fail -----------------------------


@pytest.mark.asyncio
async def test_run_suite_with_mixed_outcomes(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.queue("002", passed=False, failure_reason="boom", actuals={"x": 1})

    result = await run_suite(
        [_case("001"), _case("002"), _case("003")], runner, workspace_root=tmp_path
    )

    assert result.total == 3
    assert result.passed == 2
    assert pytest.approx(result.pass_rate, rel=1e-9) == 2 / 3
    by_id: dict[str, Any] = {c.case_id: c for c in result.cases}
    assert by_id["002"].passed is False
    assert by_id["002"].failure_reason == "boom"
    assert by_id["002"].actuals == {"x": 1}


# ---------------------------- Empty suite ---------------------------------


@pytest.mark.asyncio
async def test_run_suite_empty_cases(tmp_path: Path) -> None:
    runner = FakeRunner()
    result = await run_suite([], runner, workspace_root=tmp_path)

    assert result.total == 0
    assert result.passed == 0
    assert result.pass_rate == 1.0  # vacuously true


# ---------------------------- Duration --------------------------------------


@pytest.mark.asyncio
async def test_run_suite_records_per_case_duration(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.queue("001", passed=True, delay_sec=0.05)

    result = await run_suite([_case("001")], runner, workspace_root=tmp_path)

    assert result.cases[0].duration_sec >= 0.04


# ---------------------------- Suite ID --------------------------------------


@pytest.mark.asyncio
async def test_run_suite_mints_ulid_when_not_provided(tmp_path: Path) -> None:
    result = await run_suite([_case("001")], FakeRunner(), workspace_root=tmp_path)
    # Crockford base32 ULID is 26 chars, all uppercase alphanumeric (no I/L/O/U).
    assert len(result.suite_id) == 26
    assert result.suite_id.isalnum()


@pytest.mark.asyncio
async def test_run_suite_uses_caller_supplied_suite_id(tmp_path: Path) -> None:
    result = await run_suite(
        [_case("001")], FakeRunner(), workspace_root=tmp_path, suite_id="my-suite-1"
    )
    assert result.suite_id == "my-suite-1"


# ---------------------------- Per-case workspace ---------------------------


@pytest.mark.asyncio
async def test_run_suite_creates_per_case_workspace(tmp_path: Path) -> None:
    """Each case gets its own subdirectory under workspace_root/suite_id/."""
    captured: list[Path] = []

    class CapturingRunner(FakeRunner):
        async def run(  # type: ignore[override]
            self,
            case: EvalCase,
            *,
            workspace: Path,
            llm_provider: Any = None,
        ) -> Any:
            captured.append(workspace)
            return await super().run(case, workspace=workspace, llm_provider=llm_provider)

    runner = CapturingRunner()
    suite_id = "test-suite"
    await run_suite(
        [_case("001"), _case("002")],
        runner,
        workspace_root=tmp_path,
        suite_id=suite_id,
    )

    assert len(captured) == 2
    for ws, expected_id in zip(captured, ["001", "002"], strict=True):
        assert ws.is_dir()
        assert ws.parent == tmp_path / suite_id
        # Workspace dir name starts with the case_id and has a unique suffix.
        assert ws.name.startswith(f"{expected_id}-")
        assert ws != tmp_path / suite_id / expected_id  # uuid suffix is appended


@pytest.mark.asyncio
async def test_run_suite_workspaces_are_unique(tmp_path: Path) -> None:
    """Re-running the same case_id under the same suite_id gives distinct dirs."""
    captured: list[Path] = []

    class CapturingRunner(FakeRunner):
        async def run(  # type: ignore[override]
            self,
            case: EvalCase,
            *,
            workspace: Path,
            llm_provider: Any = None,
        ) -> Any:
            captured.append(workspace)
            return await super().run(case, workspace=workspace, llm_provider=llm_provider)

    runner = CapturingRunner()
    await run_suite(
        [_case("001"), _case("001")],  # duplicate ids; workspaces must still differ
        runner,
        workspace_root=tmp_path,
        suite_id="s",
    )

    assert captured[0] != captured[1]


@pytest.mark.asyncio
async def test_run_suite_default_workspace_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When workspace_root is None, the suite picks a system tmp dir."""
    monkeypatch.chdir(tmp_path)
    result = await run_suite([_case("001")], FakeRunner())
    assert result.passed == 1


# ---------------------------- Timeout --------------------------------------


@pytest.mark.asyncio
async def test_run_suite_marks_case_failed_on_timeout(tmp_path: Path) -> None:
    runner = FakeRunner()
    runner.queue("slow", passed=True, delay_sec=0.5)

    result = await run_suite([_case("slow", timeout_sec=0.05)], runner, workspace_root=tmp_path)

    assert result.passed == 0
    res = result.cases[0]
    assert res.passed is False
    assert res.failure_reason is not None
    assert "timeout" in res.failure_reason.lower()


# ---------------------------- Metadata + provider info ---------------------


@pytest.mark.asyncio
async def test_run_suite_propagates_metadata(tmp_path: Path) -> None:
    result = await run_suite(
        [_case("001")],
        FakeRunner(),
        workspace_root=tmp_path,
        metadata={"branch": "main", "commit": "abc123"},
    )
    assert result.metadata == {"branch": "main", "commit": "abc123"}


@pytest.mark.asyncio
async def test_run_suite_extracts_provider_id_from_llm(tmp_path: Path) -> None:
    result = await run_suite(
        [_case("001")],
        FakeRunner(),
        llm_provider=_llm(),
        workspace_root=tmp_path,
    )
    assert result.provider_id == "fake-anthropic"


@pytest.mark.asyncio
async def test_run_suite_provider_id_none_when_no_llm(tmp_path: Path) -> None:
    result = await run_suite([_case("001")], FakeRunner(), workspace_root=tmp_path)
    assert result.provider_id is None
    assert result.model_pin is None


@pytest.mark.asyncio
async def test_run_suite_threads_llm_to_runner(tmp_path: Path) -> None:
    """The runner sees the same llm_provider that was passed to run_suite."""
    seen: list[Any] = []

    class CapturingRunner(FakeRunner):
        async def run(  # type: ignore[override]
            self,
            case: EvalCase,
            *,
            workspace: Path,
            llm_provider: Any = None,
        ) -> Any:
            seen.append(llm_provider)
            return await super().run(case, workspace=workspace, llm_provider=llm_provider)

    llm = _llm()
    await run_suite([_case("001")], CapturingRunner(), llm_provider=llm, workspace_root=tmp_path)
    assert seen == [llm]


# ---------------------------- Trace ----------------------------------------


@pytest.mark.asyncio
async def test_run_suite_attaches_audit_log_path_to_trace(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text("{}\n")

    runner = FakeRunner()
    runner.queue("001", passed=True, audit_log_path=audit)

    result = await run_suite([_case("001")], runner, workspace_root=tmp_path)
    assert result.cases[0].trace.audit_log_path == str(audit)


@pytest.mark.asyncio
async def test_run_suite_trace_audit_log_none_when_runner_returns_none(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    result = await run_suite([_case("001")], runner, workspace_root=tmp_path)
    assert result.cases[0].trace.audit_log_path is None
