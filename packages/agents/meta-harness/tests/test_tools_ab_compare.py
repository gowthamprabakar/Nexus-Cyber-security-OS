"""Tests — `meta_harness.tools.ab_compare` (Task 5).

13 tests covering:

1.  ``compare_results`` returns empty for two empty SuiteResults.
2.  Identical SuiteResults -> byte-equal per-case + overall.
3.  Divergent pass/fail flips ``byte_equal`` to False.
4.  A-only case appears in output; missing B marked byte-equal=False.
5.  B-only case appears in output; missing A marked byte-equal=False.
6.  ``nlah_override`` swaps ``default_nlah_dir`` inside the block.
7.  ``nlah_override`` restores the original on exit (incl. exception).
8.  ``nlah_override`` rejects non-existent target dir.
9.  ``ab_compare`` rejects identical variant paths.
10. ``ab_compare`` rejects unknown agent_id.
11. ``ab_compare`` happy path: stub runner + identical responses ->
    byte_equal=True.
12. ``ab_compare`` divergent stubs (variant_b runner reports failure)
    -> byte_equal=False.
13. ``_canonical_bytes`` is stable across reruns for identical actuals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from eval_framework.cases import EvalCase
from eval_framework.results import EvalResult, SuiteResult
from eval_framework.trace import EvalTrace
from meta_harness.tools import ab_compare as ab_module
from meta_harness.tools.ab_compare import (
    ABCompareError,
    ABCompareRequest,
    _canonical_bytes,
    ab_compare,
    compare_results,
    nlah_override,
)

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _eval_result(
    case_id: str,
    *,
    passed: bool = True,
    failure_reason: str | None = None,
    actuals: dict[str, Any] | None = None,
    runner: str = "fake",
) -> EvalResult:
    return EvalResult(
        case_id=case_id,
        runner=runner,
        passed=passed,
        failure_reason=failure_reason,
        actuals=actuals or {},
        duration_sec=0.0,
        trace=EvalTrace(),
    )


def _suite(results: list[EvalResult], *, runner_name: str = "fake") -> SuiteResult:
    return SuiteResult(
        suite_id="s1",
        runner=runner_name,
        started_at=_NOW,
        completed_at=_NOW,
        cases=results,
        provider_id=None,
        model_pin=None,
        metadata={},
    )


def _nlah_dir(tmp_path: Path, name: str) -> Path:
    """Create a minimal valid NLAH dir under tmp_path."""
    d = tmp_path / name
    d.mkdir(parents=True)
    (d / "README.md").write_text("# Test NLAH\n\nA test persona.\n", encoding="utf-8")
    return d


def _write_case(dir_: Path, case_id: str) -> None:
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / f"{case_id}.yaml").write_text(
        f"case_id: {case_id}\ndescription: test\nfixture: {{}}\nexpected: {{}}\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Pure-function diff tests
# ---------------------------------------------------------------------------


def test_compare_results_two_empty_suites() -> None:
    deltas = compare_results(_suite([]), _suite([]))
    assert deltas == ()


def test_compare_results_identical_suites() -> None:
    a = _suite([_eval_result("c1"), _eval_result("c2")])
    b = _suite([_eval_result("c1"), _eval_result("c2")])
    deltas = compare_results(a, b)
    assert len(deltas) == 2
    assert all(d.byte_equal for d in deltas)
    assert [d.case_id for d in deltas] == ["c1", "c2"]


def test_compare_results_divergent_pass_flag() -> None:
    a = _suite([_eval_result("c1", passed=True)])
    b = _suite([_eval_result("c1", passed=False, failure_reason="boom")])
    deltas = compare_results(a, b)
    assert deltas[0].variant_a_passed is True
    assert deltas[0].variant_b_passed is False
    assert deltas[0].byte_equal is False


def test_compare_results_a_only_case() -> None:
    a = _suite([_eval_result("c1"), _eval_result("c_only_a")])
    b = _suite([_eval_result("c1")])
    deltas = compare_results(a, b)
    by_id = {d.case_id: d for d in deltas}
    assert "c_only_a" in by_id
    assert by_id["c_only_a"].variant_b_passed is False
    assert by_id["c_only_a"].byte_equal is False


def test_compare_results_b_only_case() -> None:
    a = _suite([_eval_result("c1")])
    b = _suite([_eval_result("c1"), _eval_result("c_only_b")])
    deltas = compare_results(a, b)
    by_id = {d.case_id: d for d in deltas}
    assert "c_only_b" in by_id
    assert by_id["c_only_b"].variant_a_passed is False
    assert by_id["c_only_b"].byte_equal is False


def test_canonical_bytes_stable_across_reruns() -> None:
    r1 = _eval_result("c1", actuals={"k": "v", "n": 42})
    r2 = _eval_result("c1", actuals={"k": "v", "n": 42})
    assert _canonical_bytes(r1) == _canonical_bytes(r2)


# ---------------------------------------------------------------------------
# nlah_override context manager
# ---------------------------------------------------------------------------


def test_nlah_override_swaps_default_dir_inside_block(tmp_path: Path) -> None:
    from charter import nlah_loader

    original_fn = nlah_loader.default_nlah_dir
    override_target = _nlah_dir(tmp_path, "override")
    with nlah_override(override_target):
        assert nlah_loader.default_nlah_dir("any/path") == override_target
    # restored
    assert nlah_loader.default_nlah_dir is original_fn


def test_nlah_override_restores_on_exception(tmp_path: Path) -> None:
    from charter import nlah_loader

    original = nlah_loader.default_nlah_dir
    target = _nlah_dir(tmp_path, "x")
    with pytest.raises(RuntimeError, match="boom"), nlah_override(target):
        raise RuntimeError("boom")
    assert nlah_loader.default_nlah_dir is original


def test_nlah_override_rejects_missing_target(tmp_path: Path) -> None:
    with pytest.raises(ABCompareError, match="not a directory"), nlah_override(tmp_path / "nope"):
        pass


# ---------------------------------------------------------------------------
# ab_compare end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ab_compare_rejects_identical_paths(tmp_path: Path) -> None:
    target = _nlah_dir(tmp_path, "x")
    request = ABCompareRequest(
        customer_id="acme",
        run_id="r1",
        agent_id="cloud_posture",
        variant_a_path=target,
        variant_b_path=target,
    )
    with pytest.raises(ABCompareError, match="must differ"):
        await ab_compare(request, cases_resolver=lambda _aid: tmp_path / "cases")


@pytest.mark.asyncio
async def test_ab_compare_rejects_unknown_agent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ab_module, "entry_points", lambda *, group: [])
    a_dir = _nlah_dir(tmp_path, "a")
    b_dir = _nlah_dir(tmp_path, "b")
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")

    request = ABCompareRequest(
        customer_id="acme",
        run_id="r1",
        agent_id="ghost",
        variant_a_path=a_dir,
        variant_b_path=b_dir,
    )
    with pytest.raises(ABCompareError, match="no nexus_eval_runners entry point"):
        await ab_compare(request, cases_resolver=lambda _aid: cases_dir)


# Synthetic agent with NLAH-aware behavior.
@dataclass
class _AwareRunner:
    """Runner whose pass/fail flips depending on the NLAH dir it sees.

    Reads the active ``default_nlah_dir`` via the patched function;
    when the override is in effect, the runner's behavior is keyed
    off the override target's directory name. This lets the test
    drive A/B divergence deterministically.
    """

    fail_on_variant: str = ""
    calls: list[str] = field(default_factory=list)

    @property
    def agent_name(self) -> str:
        return "synthetic"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: Any | None = None,
    ) -> tuple[bool, str | None, dict[str, Any], Path | None]:
        del workspace, llm_provider
        from charter import nlah_loader

        nlah_dir = nlah_loader.default_nlah_dir("ignored")
        variant_label = nlah_dir.name
        self.calls.append(variant_label)
        if variant_label == self.fail_on_variant:
            return False, "variant flag", {"variant": variant_label}, None
        return True, None, {"variant": variant_label}, None


@dataclass
class _FakeEntryPoint:
    name: str
    group: str
    _target: object

    def load(self) -> object:
        return self._target


@pytest.mark.asyncio
async def test_ab_compare_identical_responses_byte_equal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a_dir = _nlah_dir(tmp_path, "variant_a")
    b_dir = _nlah_dir(tmp_path, "variant_b")
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    _write_case(cases_dir, "c2")

    # Both variants must produce identical pass outcomes for
    # byte-equality. The runner records the variant label in
    # actuals — but since "variant" key is keyed off the active
    # NLAH dir's basename, A and B will produce DIFFERENT actuals.
    # We need a runner whose output is independent of variant
    # to demonstrate byte-equal=True. Use one that returns
    # constant actuals.
    class _ConstRunner:
        @property
        def agent_name(self) -> str:
            return "synthetic"

        async def run(
            self,
            case: EvalCase,
            *,
            workspace: Path,
            llm_provider: Any | None = None,
        ) -> tuple[bool, str | None, dict[str, Any], Path | None]:
            del workspace, llm_provider, case
            return True, None, {"k": "v"}, None

    monkeypatch.setattr(
        ab_module,
        "entry_points",
        lambda *, group: [
            _FakeEntryPoint(name="synthetic", group=group, _target=_ConstRunner),
        ],
    )

    request = ABCompareRequest(
        customer_id="acme",
        run_id="r1",
        agent_id="synthetic",
        variant_a_path=a_dir,
        variant_b_path=b_dir,
    )
    result = await ab_compare(request, cases_resolver=lambda _aid: cases_dir)

    assert result.byte_equal is True
    assert result.variant_a_pass_rate == 1.0
    assert result.variant_b_pass_rate == 1.0
    assert len(result.per_case_deltas) == 2
    assert all(d.byte_equal for d in result.per_case_deltas)


@pytest.mark.asyncio
async def test_ab_compare_divergent_byte_equal_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a_dir = _nlah_dir(tmp_path, "variant_a")
    b_dir = _nlah_dir(tmp_path, "variant_b")
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")

    runner_factory = lambda: _AwareRunner(fail_on_variant="variant_b")  # noqa: E731
    monkeypatch.setattr(
        ab_module,
        "entry_points",
        lambda *, group: [
            _FakeEntryPoint(name="synthetic", group=group, _target=runner_factory),
        ],
    )

    request = ABCompareRequest(
        customer_id="acme",
        run_id="r1",
        agent_id="synthetic",
        variant_a_path=a_dir,
        variant_b_path=b_dir,
    )
    result = await ab_compare(request, cases_resolver=lambda _aid: cases_dir)

    assert result.byte_equal is False
    assert result.variant_a_pass_rate == 1.0
    assert result.variant_b_pass_rate == 0.0
    assert result.per_case_deltas[0].variant_a_passed is True
    assert result.per_case_deltas[0].variant_b_passed is False
