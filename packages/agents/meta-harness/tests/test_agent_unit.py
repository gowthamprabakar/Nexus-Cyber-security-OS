"""Tests — `meta_harness.agent` (Task 10 — 6-stage driver).

15 tests covering the integrated pipeline:

1.  Happy path — customer_id / run_id propagate to scorecards
    + report.
2.  Empty entry points -> empty scorecards / manifests / report
    fields.
3.  ``semantic_store=None`` -> all deltas are first-run (no
    previous fetch).
4.  ``semantic_store`` provided + prior entity -> delta computed.
5.  Driver writes meta_harness_report.md to workspace_root.
6.  Driver persists agent_scorecard entities when store provided.
7.  Driver no-op-with-log on store=None for KG persistence.
8.  A/B compare end-to-end: all three inputs -> ABComparison
    present in report.
9.  A/B compare partial inputs -> ValueError.
10. A/B compare result persisted as ab_comparison_result entity.
11. INTROSPECT skip on NlahParseError doesn't kill the run.
12. INTROSPECT happy path -> AgentManifest in report.manifests.
13. agent_filter restricts batch.
14. Regressions surface in report.regressions_flagged when prev
    pass_rate drops by ≥5%.
15. scan_started_at + scan_completed_at populated (recent UTC).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from charter.memory.semantic import EntityRow, SemanticStore
from eval_framework.cases import EvalCase
from meta_harness import agent as agent_module
from meta_harness.agent import default_nlah_dir_resolver, run
from meta_harness.eval import batch as batch_module
from meta_harness.tools import ab_compare as ab_module

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


@dataclass
class _FakeEntryPoint:
    name: str
    group: str
    _target: object

    def load(self) -> object:
        return self._target


def _make_runner_class(agent_name: str, default_passed: bool = True) -> type:
    class _Runner:
        def __init__(self) -> None:
            pass

        @property
        def agent_name(self) -> str:
            return agent_name

        async def run(
            self,
            case: EvalCase,
            *,
            workspace: Path,
            llm_provider: Any | None = None,
        ) -> tuple[bool, str | None, dict[str, Any], Path | None]:
            del workspace, llm_provider, case
            return default_passed, None if default_passed else "fail", {}, None

    return _Runner


def _write_case(dir_: Path, case_id: str) -> None:
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / f"{case_id}.yaml").write_text(
        f"case_id: {case_id}\ndescription: test\nfixture: {{}}\nexpected: {{}}\n",
        encoding="utf-8",
    )


def _write_nlah(dir_: Path, persona: str = "A test agent.") -> None:
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / "README.md").write_text(f"# X\n\n{persona}\n", encoding="utf-8")


@pytest.fixture
def patched_entry_points(monkeypatch: pytest.MonkeyPatch) -> Any:
    queued: list[_FakeEntryPoint] = []

    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        assert group == "nexus_eval_runners"
        return list(queued)

    monkeypatch.setattr(batch_module, "entry_points", fake_entry_points)
    monkeypatch.setattr(ab_module, "entry_points", fake_entry_points)
    return queued


def _semantic_store_with_prior_scorecards(prior_rows: list[EntityRow]) -> SemanticStore:
    store = AsyncMock(spec=SemanticStore)
    store.list_entities_by_type.return_value = prior_rows
    store.upsert_entity.return_value = "ent_id"
    return store  # type: ignore[no-any-return]


def _prior_scorecard_row(
    agent_id: str,
    *,
    pass_rate: float,
    created_at: datetime,
    run_id: str = "r0",
) -> EntityRow:
    return EntityRow(
        entity_id=f"ent_{agent_id}",
        tenant_id="acme",
        entity_type="agent_scorecard",
        external_id=f"acme:{run_id}:{agent_id}",
        properties={
            "customer_id": "acme",
            "run_id": run_id,
            "agent_id": agent_id,
            "total_cases": 10,
            "passed": int(pass_rate * 10),
            "failed": 10 - int(pass_rate * 10),
            "pass_rate": pass_rate,
            "error": None,
            "evaluated_at": created_at.isoformat(),
        },
        created_at=created_at,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_propagates_customer_and_run_id(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    _write_nlah(tmp_path / "packages/agents/cloud-posture/src/cloud_posture/nlah")
    patched_entry_points.append(
        _FakeEntryPoint(
            name="cloud_posture",
            group="nexus_eval_runners",
            _target=_make_runner_class("cloud_posture"),
        )
    )

    report = await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: cases_dir,
    )

    assert report.customer_id == "acme"
    assert report.run_id == "r1"
    assert report.total_agents_evaluated == 1
    assert report.scorecards[0].agent_id == "cloud_posture"


@pytest.mark.asyncio
async def test_empty_entry_points_empty_report(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    report = await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: tmp_path / "nope",
    )
    assert report.total_agents_evaluated == 0
    assert report.manifests == ()
    assert report.regressions_flagged == ()


@pytest.mark.asyncio
async def test_semantic_store_none_yields_first_run_deltas(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    patched_entry_points.append(
        _FakeEntryPoint(
            name="x",
            group="nexus_eval_runners",
            _target=_make_runner_class("x"),
        )
    )

    report = await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: cases_dir,
        semantic_store=None,
    )
    assert all(d.is_first_run for d in report.scorecard_deltas)


@pytest.mark.asyncio
async def test_semantic_store_with_prior_yields_delta(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    patched_entry_points.append(
        _FakeEntryPoint(
            name="x",
            group="nexus_eval_runners",
            _target=_make_runner_class("x", default_passed=True),
        )
    )

    prior_row = _prior_scorecard_row(
        "x",
        pass_rate=0.5,
        created_at=_NOW - timedelta(days=1),
        run_id="r0",
    )
    store = _semantic_store_with_prior_scorecards([prior_row])

    report = await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: cases_dir,
        semantic_store=store,
    )
    assert report.scorecard_deltas[0].is_first_run is False
    assert report.scorecard_deltas[0].previous_pass_rate == 0.5
    assert report.scorecard_deltas[0].current_pass_rate == 1.0
    assert report.scorecard_deltas[0].delta_pct == pytest.approx(50.0)


@pytest.mark.asyncio
async def test_writes_report_markdown_to_workspace(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    patched_entry_points.append(
        _FakeEntryPoint(name="x", group="nexus_eval_runners", _target=_make_runner_class("x"))
    )

    await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: cases_dir,
    )
    report_path = tmp_path / "meta_harness_report.md"
    assert report_path.is_file()
    assert "Meta-Harness Report" in report_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_persists_scorecards_when_store_provided(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    patched_entry_points.append(
        _FakeEntryPoint(name="x", group="nexus_eval_runners", _target=_make_runner_class("x"))
    )
    store = _semantic_store_with_prior_scorecards([])

    await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: cases_dir,
        semantic_store=store,
    )
    # one scorecard upsert (entity_type=agent_scorecard).
    assert store.upsert_entity.await_count >= 1
    types_written = {call.kwargs["entity_type"] for call in store.upsert_entity.await_args_list}
    assert "agent_scorecard" in types_written


@pytest.mark.asyncio
async def test_no_op_kg_when_store_none(
    patched_entry_points: list[_FakeEntryPoint],
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    patched_entry_points.append(
        _FakeEntryPoint(name="x", group="nexus_eval_runners", _target=_make_runner_class("x"))
    )

    with caplog.at_level(logging.INFO, logger="meta_harness.kg_writer"):
        await run(
            customer_id="acme",
            run_id="r1",
            workspace_root=tmp_path,
            cases_resolver=lambda _aid: cases_dir,
            semantic_store=None,
        )
    assert any("skipped" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_ab_compare_end_to_end_attaches_to_report(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    nlah_a = tmp_path / "nlah_a"
    nlah_b = tmp_path / "nlah_b"
    _write_nlah(nlah_a)
    _write_nlah(nlah_b)

    patched_entry_points.append(
        _FakeEntryPoint(name="x", group="nexus_eval_runners", _target=_make_runner_class("x"))
    )

    report = await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: cases_dir,
        ab_variant_a=nlah_a,
        ab_variant_b=nlah_b,
        ab_target_agent="x",
    )
    assert report.ab_comparison is not None
    assert report.ab_comparison.agent_id == "x"


@pytest.mark.asyncio
async def test_ab_compare_partial_inputs_raises(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    nlah_a = tmp_path / "nlah_a"
    _write_nlah(nlah_a)
    patched_entry_points.append(
        _FakeEntryPoint(name="x", group="nexus_eval_runners", _target=_make_runner_class("x"))
    )

    with pytest.raises(ValueError, match="all three"):
        await run(
            customer_id="acme",
            run_id="r1",
            workspace_root=tmp_path,
            cases_resolver=lambda _aid: cases_dir,
            ab_variant_a=nlah_a,
            # missing ab_variant_b and ab_target_agent
        )


@pytest.mark.asyncio
async def test_ab_result_persisted_when_store_provided(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    nlah_a = tmp_path / "nlah_a"
    nlah_b = tmp_path / "nlah_b"
    _write_nlah(nlah_a)
    _write_nlah(nlah_b)
    patched_entry_points.append(
        _FakeEntryPoint(name="x", group="nexus_eval_runners", _target=_make_runner_class("x"))
    )
    store = _semantic_store_with_prior_scorecards([])

    await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: cases_dir,
        semantic_store=store,
        ab_variant_a=nlah_a,
        ab_variant_b=nlah_b,
        ab_target_agent="x",
    )
    types_written = {call.kwargs["entity_type"] for call in store.upsert_entity.await_args_list}
    assert "ab_comparison_result" in types_written


@pytest.mark.asyncio
async def test_introspect_skip_on_parse_error_does_not_kill_run(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    # No NLAH dir created; introspect will skip with NlahParseError.
    patched_entry_points.append(
        _FakeEntryPoint(name="x", group="nexus_eval_runners", _target=_make_runner_class("x"))
    )

    report = await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: cases_dir,
    )
    assert report.manifests == ()  # introspection skipped
    assert report.total_agents_evaluated == 1  # eval still happened


@pytest.mark.asyncio
async def test_introspect_happy_path(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    nlah_dir = tmp_path / "packages/agents/cloud-posture/src/cloud_posture/nlah"
    _write_nlah(nlah_dir, persona="Cloud sentinel.")
    patched_entry_points.append(
        _FakeEntryPoint(
            name="cloud_posture",
            group="nexus_eval_runners",
            _target=_make_runner_class("cloud_posture"),
        )
    )

    report = await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: cases_dir,
    )
    assert len(report.manifests) == 1
    assert report.manifests[0].persona == "Cloud sentinel."


@pytest.mark.asyncio
async def test_agent_filter_restricts_batch(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir_a = tmp_path / "a_cases"
    cases_dir_b = tmp_path / "b_cases"
    _write_case(cases_dir_a, "a1")
    _write_case(cases_dir_b, "b1")
    patched_entry_points.append(
        _FakeEntryPoint(name="a", group="nexus_eval_runners", _target=_make_runner_class("a"))
    )
    patched_entry_points.append(
        _FakeEntryPoint(name="b", group="nexus_eval_runners", _target=_make_runner_class("b"))
    )

    report = await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda aid: cases_dir_a if aid == "a" else cases_dir_b,
        agent_filter=frozenset({"a"}),
    )
    assert [s.agent_id for s in report.scorecards] == ["a"]


@pytest.mark.asyncio
async def test_regressions_surface_in_report(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    patched_entry_points.append(
        _FakeEntryPoint(
            name="x",
            group="nexus_eval_runners",
            _target=_make_runner_class("x", default_passed=False),
        )
    )
    # Prior pass_rate=1.0, current=0.0 -> -100 pct delta, regression.
    prior_row = _prior_scorecard_row(
        "x",
        pass_rate=1.0,
        created_at=_NOW - timedelta(days=1),
    )
    store = _semantic_store_with_prior_scorecards([prior_row])

    report = await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: cases_dir,
        semantic_store=store,
    )
    assert len(report.regressions_flagged) == 1
    assert report.regressions_flagged[0].agent_id == "x"


@pytest.mark.asyncio
async def test_scan_timestamps_populated(
    patched_entry_points: list[_FakeEntryPoint], tmp_path: Path
) -> None:
    cases_dir = tmp_path / "cases"
    _write_case(cases_dir, "c1")
    patched_entry_points.append(
        _FakeEntryPoint(name="x", group="nexus_eval_runners", _target=_make_runner_class("x"))
    )

    before = datetime.now(UTC)
    report = await run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=lambda _aid: cases_dir,
    )
    after = datetime.now(UTC)
    assert (
        before <= report.scan_started_at <= report.scan_completed_at <= after + timedelta(seconds=1)
    )


def test_default_nlah_dir_resolver_kebab_case(tmp_path: Path) -> None:
    """Bonus sanity — resolver outputs the convention path."""
    resolver = default_nlah_dir_resolver(tmp_path)
    assert resolver("multi_cloud_posture") == (
        tmp_path
        / "packages"
        / "agents"
        / "multi-cloud-posture"
        / "src"
        / "multi_cloud_posture"
        / "nlah"
    )


# Quiet the "unused" warning on the agent_module import (we use it via
# the patched entry-point monkeypatching above).
_ = agent_module
