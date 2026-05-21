"""Tests — `meta_harness.eval.batch` (Task 4).

14 tests covering:

1.  No registered entry points -> empty scorecards.
2.  Single-agent all-pass.
3.  Single-agent mixed pass/fail; pass_rate computed correctly.
4.  Two-agent happy-path.
5.  Per-agent runner load failure tolerated; other agents still run.
6.  Missing cases dir tolerated as Scorecard(error=...).
7.  Empty cases dir tolerated as Scorecard(total_cases=0, pass_rate=1.0).
8.  Mid-suite raise tolerated as Scorecard(error=...).
9.  ``agent_filter`` restricts the batch to the selected agents.
10. ``customer_id`` and ``run_id`` propagate to every Scorecard.
11. ``evaluated_at`` is populated with a recent UTC datetime.
12. Stable ordering — entry points sorted lexicographically by name.
13. ``default_cases_root`` resolves snake-case agent_id to
    kebab-case workspace dir.
14. ``_agent_dirname`` helper round-trips ``a_b_c`` -> ``a-b-c``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib.metadata import EntryPoint
from pathlib import Path
from typing import Any

import pytest
from eval_framework.cases import EvalCase
from eval_framework.runner import EvalRunner
from meta_harness.eval import batch as batch_module
from meta_harness.eval.batch import (
    BatchEvalConfig,
    BatchEvalRunner,
    default_cases_root,
)

# ---------------------------------------------------------------------------
# Fixtures + fake runners
# ---------------------------------------------------------------------------


@dataclass
class _FakeRunner:
    agent_name: str = "fake"
    queued: dict[str, bool] | None = None
    default_passed: bool = True
    raise_on_first: bool = False

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: Any | None = None,
    ) -> tuple[bool, str | None, dict[str, Any], Path | None]:
        del workspace, llm_provider
        if self.raise_on_first:
            raise RuntimeError("boom")
        if self.queued and case.case_id in self.queued:
            ok = self.queued[case.case_id]
            return ok, None if ok else "queued fail", {}, None
        return self.default_passed, None if self.default_passed else "stock fail", {}, None


def _make_runner_factory(**kwargs: Any) -> type:
    """Create a class whose `__init__` returns a _FakeRunner with kwargs."""

    runner_kwargs = kwargs

    class _Wrapper:
        def __init__(self) -> None:
            self._inner = _FakeRunner(**runner_kwargs)

        @property
        def agent_name(self) -> str:
            return self._inner.agent_name

        async def run(
            self,
            case: EvalCase,
            *,
            workspace: Path,
            llm_provider: Any | None = None,
        ) -> tuple[bool, str | None, dict[str, Any], Path | None]:
            return await self._inner.run(case, workspace=workspace, llm_provider=llm_provider)

    return _Wrapper


@dataclass
class _FakeEntryPoint:
    """Duck-typed substitute for ``importlib.metadata.EntryPoint``.

    Batch code only reads ``ep.name`` and calls ``ep.load()``; the
    EntryPoint type hint is satisfied at runtime by anything that
    quacks the same way. Using a fake avoids the brittle dotted-path
    resolution real EntryPoints require.
    """

    name: str
    group: str
    _target: object

    def load(self) -> object:
        if isinstance(self._target, BaseException):
            raise self._target
        return self._target


def _make_ep(name: str, target: object) -> EntryPoint:
    return _FakeEntryPoint(name=name, group="nexus_eval_runners", _target=target)  # type: ignore[return-value]


def _write_case(dir_: Path, case_id: str) -> None:
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / f"{case_id}.yaml").write_text(
        f"case_id: {case_id}\ndescription: test\nfixture: {{}}\nexpected: {{}}\n",
        encoding="utf-8",
    )


@pytest.fixture
def patched_entry_points(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Patch ``entry_points`` to return whatever a test queues."""
    queued: list[EntryPoint] = []

    def fake_entry_points(*, group: str) -> list[EntryPoint]:
        assert group == "nexus_eval_runners"
        return list(queued)

    monkeypatch.setattr(batch_module, "entry_points", fake_entry_points)
    return queued


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_entry_points_returns_empty(
    patched_entry_points: list[EntryPoint], tmp_path: Path
) -> None:
    runner = BatchEvalRunner(cases_root=lambda _aid: tmp_path / "missing")
    sc = await runner.run_batch(customer_id="acme", run_id="r1")
    assert sc == []


@pytest.mark.asyncio
async def test_single_agent_all_pass(
    patched_entry_points: list[EntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cp" / "cases"
    _write_case(cases_dir, "c1")
    _write_case(cases_dir, "c2")

    target = _make_runner_factory(agent_name="cloud_posture", default_passed=True)
    patched_entry_points.append(_make_ep("cloud_posture", target))

    runner = BatchEvalRunner(
        cases_root=lambda aid: cases_dir if aid == "cloud_posture" else tmp_path
    )
    sc = await runner.run_batch(customer_id="acme", run_id="r1")

    assert len(sc) == 1
    assert sc[0].agent_id == "cloud_posture"
    assert sc[0].total_cases == 2
    assert sc[0].passed == 2
    assert sc[0].failed == 0
    assert sc[0].pass_rate == 1.0
    assert sc[0].error is None


@pytest.mark.asyncio
async def test_single_agent_mixed_pass_fail(
    patched_entry_points: list[EntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cp" / "cases"
    _write_case(cases_dir, "c1")
    _write_case(cases_dir, "c2")
    _write_case(cases_dir, "c3")

    target = _make_runner_factory(
        agent_name="cloud_posture",
        queued={"c1": True, "c2": False, "c3": True},
    )
    patched_entry_points.append(_make_ep("cloud_posture", target))

    runner = BatchEvalRunner(cases_root=lambda _aid: cases_dir)
    sc = await runner.run_batch(customer_id="acme", run_id="r1")

    assert sc[0].passed == 2
    assert sc[0].failed == 1
    assert sc[0].pass_rate == pytest.approx(2 / 3)


@pytest.mark.asyncio
async def test_two_agents_happy(patched_entry_points: list[EntryPoint], tmp_path: Path) -> None:
    a_dir = tmp_path / "a" / "cases"
    b_dir = tmp_path / "b" / "cases"
    _write_case(a_dir, "a1")
    _write_case(b_dir, "b1")

    patched_entry_points.append(_make_ep("agent_a", _make_runner_factory(agent_name="agent_a")))
    patched_entry_points.append(_make_ep("agent_b", _make_runner_factory(agent_name="agent_b")))

    runner = BatchEvalRunner(
        cases_root=lambda aid: a_dir if aid == "agent_a" else b_dir,
    )
    sc = await runner.run_batch(customer_id="acme", run_id="r1")

    assert [s.agent_id for s in sc] == ["agent_a", "agent_b"]
    assert all(s.pass_rate == 1.0 for s in sc)


@pytest.mark.asyncio
async def test_runner_load_failure_does_not_poison_batch(
    patched_entry_points: list[EntryPoint], tmp_path: Path
) -> None:
    good_dir = tmp_path / "good" / "cases"
    _write_case(good_dir, "g1")

    # The bad entry point raises ImportError when load() is called.
    bad_ep = _FakeEntryPoint(
        name="broken",
        group="nexus_eval_runners",
        _target=ImportError("module not found"),
    )
    patched_entry_points.append(bad_ep)  # type: ignore[arg-type]
    patched_entry_points.append(_make_ep("ok", _make_runner_factory(agent_name="ok")))

    runner = BatchEvalRunner(
        cases_root=lambda aid: good_dir if aid == "ok" else tmp_path / "nope",
    )
    sc = await runner.run_batch(customer_id="acme", run_id="r1")

    by_name = {s.agent_id: s for s in sc}
    assert by_name["broken"].error is not None
    assert by_name["broken"].pass_rate is None
    assert by_name["ok"].pass_rate == 1.0


@pytest.mark.asyncio
async def test_missing_cases_dir_surfaces_as_error(
    patched_entry_points: list[EntryPoint], tmp_path: Path
) -> None:
    patched_entry_points.append(
        _make_ep("missing_cases", _make_runner_factory(agent_name="missing_cases"))
    )
    runner = BatchEvalRunner(cases_root=lambda _aid: tmp_path / "does_not_exist")
    sc = await runner.run_batch(customer_id="acme", run_id="r1")

    assert len(sc) == 1
    assert sc[0].pass_rate is None
    assert sc[0].error is not None
    assert "not found" in sc[0].error.lower()


@pytest.mark.asyncio
async def test_empty_cases_dir_treated_as_zero_cases(
    patched_entry_points: list[EntryPoint], tmp_path: Path
) -> None:
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    patched_entry_points.append(
        _make_ep("empty_cases", _make_runner_factory(agent_name="empty_cases"))
    )
    runner = BatchEvalRunner(cases_root=lambda _aid: empty_dir)
    sc = await runner.run_batch(customer_id="acme", run_id="r1")

    assert len(sc) == 1
    assert sc[0].total_cases == 0
    assert sc[0].pass_rate == 1.0
    assert sc[0].error is None


@pytest.mark.asyncio
async def test_runner_raises_during_suite_run(
    patched_entry_points: list[EntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "c" / "cases"
    _write_case(cases_dir, "c1")

    target = _make_runner_factory(agent_name="boom", raise_on_first=True)
    patched_entry_points.append(_make_ep("boom", target))

    runner = BatchEvalRunner(cases_root=lambda _aid: cases_dir)
    sc = await runner.run_batch(customer_id="acme", run_id="r1")

    # An EvalRunner that raises inside ``run`` (a non-TimeoutError)
    # cascades through ``run_suite`` and gets caught at the batch
    # level — surfaces as Scorecard(error=...). The batch must not
    # let one agent's bad runner kill the whole batch.
    assert sc[0].pass_rate is None
    assert sc[0].error is not None
    assert "boom" in sc[0].error


@pytest.mark.asyncio
async def test_agent_filter_restricts_batch(
    patched_entry_points: list[EntryPoint], tmp_path: Path
) -> None:
    a_dir = tmp_path / "a" / "cases"
    b_dir = tmp_path / "b" / "cases"
    _write_case(a_dir, "a1")
    _write_case(b_dir, "b1")

    patched_entry_points.append(_make_ep("agent_a", _make_runner_factory(agent_name="agent_a")))
    patched_entry_points.append(_make_ep("agent_b", _make_runner_factory(agent_name="agent_b")))

    runner = BatchEvalRunner(
        cases_root=lambda aid: a_dir if aid == "agent_a" else b_dir,
        config=BatchEvalConfig(agent_filter=frozenset({"agent_a"})),
    )
    sc = await runner.run_batch(customer_id="acme", run_id="r1")
    assert [s.agent_id for s in sc] == ["agent_a"]


@pytest.mark.asyncio
async def test_customer_and_run_id_propagate(
    patched_entry_points: list[EntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "c"
    _write_case(cases_dir, "c1")
    patched_entry_points.append(_make_ep("x", _make_runner_factory(agent_name="x")))

    runner = BatchEvalRunner(cases_root=lambda _aid: cases_dir)
    sc = await runner.run_batch(customer_id="contoso", run_id="r42")

    assert sc[0].customer_id == "contoso"
    assert sc[0].run_id == "r42"


@pytest.mark.asyncio
async def test_evaluated_at_is_recent_utc(
    patched_entry_points: list[EntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "c"
    _write_case(cases_dir, "c1")
    patched_entry_points.append(_make_ep("x", _make_runner_factory(agent_name="x")))

    before = datetime.now(UTC)
    runner = BatchEvalRunner(cases_root=lambda _aid: cases_dir)
    sc = await runner.run_batch(customer_id="acme", run_id="r1")
    after = datetime.now(UTC)

    assert before <= sc[0].evaluated_at <= after + timedelta(seconds=1)


@pytest.mark.asyncio
async def test_stable_ordering_by_entry_point_name(
    patched_entry_points: list[EntryPoint], tmp_path: Path
) -> None:
    for name in ("z_agent", "m_agent", "a_agent"):
        cases_dir = tmp_path / name
        _write_case(cases_dir, "c1")
        patched_entry_points.append(_make_ep(name, _make_runner_factory(agent_name=name)))

    runner = BatchEvalRunner(cases_root=lambda aid: tmp_path / aid)
    sc = await runner.run_batch(customer_id="acme", run_id="r1")
    assert [s.agent_id for s in sc] == ["a_agent", "m_agent", "z_agent"]


def test_default_cases_root_resolves_kebab_case(tmp_path: Path) -> None:
    resolver = default_cases_root(tmp_path)
    path = resolver("cloud_posture")
    assert path == tmp_path / "packages" / "agents" / "cloud-posture" / "eval" / "cases"


def test_default_cases_root_handles_multi_underscore(tmp_path: Path) -> None:
    resolver = default_cases_root(tmp_path)
    path = resolver("multi_cloud_posture")
    assert path.parts[-3] == "multi-cloud-posture"


def test_eval_runner_protocol_satisfied() -> None:
    """Sanity: the wrapper class we generate in tests satisfies EvalRunner."""
    wrapper_cls = _make_runner_factory(agent_name="x")
    instance = wrapper_cls()
    assert isinstance(instance, EvalRunner)
