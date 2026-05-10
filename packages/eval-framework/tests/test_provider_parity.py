"""Tests for `run_across_providers` — multi-provider eval parity per ADR-003."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, ModelTier, TokenUsage
from eval_framework.cases import EvalCase
from eval_framework.compare import diff_results
from eval_framework.results import SuiteResult
from eval_framework.runner import FakeRunner
from eval_framework.suite import run_across_providers


def _case(case_id: str) -> EvalCase:
    return EvalCase(case_id=case_id, description=f"case {case_id}")


def _llm(provider_id: str) -> FakeLLMProvider:
    return FakeLLMProvider(
        responses=[
            LLMResponse(
                text="ok",
                usage=TokenUsage(0, 0),
                stop_reason="end_turn",
                model_pin=f"{provider_id}-model",
                provider_id=provider_id,
            )
        ],
        provider_id=provider_id,
        model_class=ModelTier.WORKHORSE,
    )


# ---------------------------- Happy path ---------------------------------


@pytest.mark.asyncio
async def test_runs_one_suite_per_provider(tmp_path: Path) -> None:
    cases = [_case("001"), _case("002")]
    providers = {
        "anthropic": _llm("anthropic"),
        "ollama": _llm("ollama"),
        "openai": _llm("openai"),
    }

    results = await run_across_providers(cases, FakeRunner(), providers, workspace_root=tmp_path)

    assert isinstance(results, dict)
    assert set(results.keys()) == {"anthropic", "ollama", "openai"}
    for label, suite in results.items():
        assert isinstance(suite, SuiteResult)
        assert suite.provider_id == label
        assert suite.total == 2


@pytest.mark.asyncio
async def test_identical_providers_yield_zero_drift(tmp_path: Path) -> None:
    """diff_results across two parity-suite runs reports zero regressions."""
    runner = FakeRunner()
    providers = {"a": _llm("a"), "b": _llm("b")}

    results = await run_across_providers(
        [_case("001"), _case("002"), _case("003")],
        runner,
        providers,
        workspace_root=tmp_path,
    )

    diff = diff_results(results["a"], results["b"])
    assert diff.summary.regressions_count == 0
    assert diff.summary.improvements_count == 0


# ---------------------------- Drift detection ----------------------------


@pytest.mark.asyncio
async def test_drifting_provider_shows_up_in_diff(tmp_path: Path) -> None:
    """Inject a runner that fails one case for one provider; diff catches it."""

    class ProviderAwareRunner(FakeRunner):
        async def run(  # type: ignore[override]
            self,
            case: EvalCase,
            *,
            workspace: Path,
            llm_provider: Any = None,
        ) -> Any:
            # Fail case 002 only when running against the "drifty" provider.
            if (
                llm_provider is not None
                and getattr(llm_provider, "provider_id", "") == "drifty"
                and case.case_id == "002"
            ):
                return False, "provider-specific failure", {}, None
            return await super().run(case, workspace=workspace, llm_provider=llm_provider)

    cases = [_case("001"), _case("002"), _case("003")]
    providers = {"baseline": _llm("baseline"), "drifty": _llm("drifty")}

    results = await run_across_providers(
        cases, ProviderAwareRunner(), providers, workspace_root=tmp_path
    )

    diff = diff_results(results["baseline"], results["drifty"])
    assert diff.summary.regressions_count == 1
    regressed = [d for d in diff.case_diffs if d.status == "newly_failing"]
    assert len(regressed) == 1
    assert regressed[0].case_id == "002"


# ---------------------------- Empty inputs -------------------------------


@pytest.mark.asyncio
async def test_empty_providers_returns_empty_dict(tmp_path: Path) -> None:
    result = await run_across_providers([_case("001")], FakeRunner(), {}, workspace_root=tmp_path)
    assert result == {}


@pytest.mark.asyncio
async def test_empty_cases_runs_each_provider_with_zero_cases(tmp_path: Path) -> None:
    providers = {"a": _llm("a"), "b": _llm("b")}
    result = await run_across_providers([], FakeRunner(), providers, workspace_root=tmp_path)
    assert set(result.keys()) == {"a", "b"}
    assert all(s.total == 0 for s in result.values())


# ---------------------------- Metadata propagation -----------------------


@pytest.mark.asyncio
async def test_metadata_propagated_to_each_suite(tmp_path: Path) -> None:
    providers = {"a": _llm("a"), "b": _llm("b")}
    result = await run_across_providers(
        [_case("001")],
        FakeRunner(),
        providers,
        workspace_root=tmp_path,
        metadata={"branch": "main", "commit": "abc"},
    )
    for suite in result.values():
        assert suite.metadata == {"branch": "main", "commit": "abc"}


@pytest.mark.asyncio
async def test_each_provider_gets_distinct_workspace(tmp_path: Path) -> None:
    """Two providers running the same suite must not share per-case workspaces."""
    providers = {"a": _llm("a"), "b": _llm("b")}
    result = await run_across_providers(
        [_case("001")], FakeRunner(), providers, workspace_root=tmp_path
    )
    assert result["a"].suite_id != result["b"].suite_id
