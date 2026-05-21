"""``MetaHarnessEvalRunner`` — the canonical ``EvalRunner`` for A.4.

Per Task 12 of the A.4 v0.1 plan. Each case fixture defines a small
synthetic fleet of agents that the runner registers as ephemeral
``nexus_eval_runners`` entry points; the runner then invokes
``meta_harness.agent.run`` against that fleet and compares the
returned ``MetaHarnessReport`` to ``case.expected``.

**Stub LLM provider (Task 14).** Canned LLM outputs (when needed
by the meta-eval cases) live in
``eval/stub_responses/<case_id>/responses.json`` (JSON array of
strings). Meta-harness itself does not consume an LLM in v0.1, but
the runner threads any provided ``llm_provider`` through to the
batch (downstream agents may need it).

**Fixture keys** (under ``fixture``):

- ``agents: list[dict]`` — synthetic agents to register. Each entry:
  ``{"agent_id": str, "default_passed": bool, "case_count": int,
  "raises": Optional[str]}``.
- ``prior_scorecards: list[dict]`` — previous-run scorecards to
  inject via the mocked SemanticStore. Each entry:
  ``{"agent_id": str, "pass_rate": float, "run_id": Optional[str]}``.
- ``semantic_store: bool`` — when False, the runner passes
  ``semantic_store=None`` (default True so cases exercise the
  persistence path).
- ``ab: Optional[dict]`` — A/B-compare inputs. Shape:
  ``{"target_agent": str, "variant_a_dirname": str,
  "variant_b_dirname": str}``. When absent, the run skips Stage 3.

**Expected keys** (under ``expected``):

- ``total_agents_evaluated: int``
- ``successful_runs: int``
- ``regressions_count: int``
- ``ab_present: bool``
- ``ab_byte_equal: Optional[bool]``
- ``manifest_count: int``
- ``markdown_contains: list[str]``
- ``markdown_excludes: list[str]``
- ``scorecard_upserts: Optional[int]`` — total ``upsert_entity``
  calls observed when ``semantic_store=True``.

Registered via the ``[project.entry-points."nexus_eval_runners"]``
hook in ``pyproject.toml`` (shipped in Task 1).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock

from charter.llm import LLMProvider
from charter.memory.semantic import EntityRow, SemanticStore
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome

from meta_harness import agent as agent_mod
from meta_harness.eval import batch as batch_module
from meta_harness.schemas import MetaHarnessReport
from meta_harness.tools import ab_compare as ab_module

_STUB_RESPONSES_ROOT = Path(__file__).parent.parent.parent / "eval" / "stub_responses"


class MetaHarnessEvalRunner:
    """Reference ``EvalRunner`` for the Meta-Harness Agent (A.4)."""

    @property
    def agent_name(self) -> str:
        return "meta_harness"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        workspace.mkdir(parents=True, exist_ok=True)
        fixture = case.fixture
        use_store = bool(fixture.get("semantic_store", True))

        synthetic_agents = _SyntheticAgent.from_fixture(fixture.get("agents") or [])
        cases_root = workspace / "cases_root"
        _materialize_case_dirs(cases_root, synthetic_agents)

        prior_rows = _build_prior_rows(fixture.get("prior_scorecards") or [])
        store_mock = _build_store_mock(prior_rows) if use_store else None

        ab_inputs = _parse_ab_inputs(fixture.get("ab"), workspace)

        with _patched_entry_points(synthetic_agents):
            report = await agent_mod.run(
                customer_id="cust_eval",
                run_id="r_eval",
                workspace_root=workspace,
                semantic_store=cast(SemanticStore, store_mock) if store_mock else None,
                llm_provider=llm_provider,
                ab_variant_a=ab_inputs.variant_a if ab_inputs else None,
                ab_variant_b=ab_inputs.variant_b if ab_inputs else None,
                ab_target_agent=ab_inputs.target_agent if ab_inputs else None,
                cases_resolver=lambda aid: cases_root / aid,
            )

        passed, failure_reason = _evaluate(case, report, workspace, store_mock=store_mock)
        actuals: dict[str, Any] = {
            "total_agents_evaluated": report.total_agents_evaluated,
            "successful_runs": report.successful_runs,
            "regressions_count": report.total_regressions,
            "ab_present": report.ab_comparison is not None,
            "ab_byte_equal": report.ab_comparison.byte_equal if report.ab_comparison else None,
            "manifest_count": len(report.manifests),
            "scorecard_upserts": _count_upserts(store_mock),
        }
        return passed, failure_reason, actuals, None


# ---------------------------------------------------------------------------
# Synthetic agent registration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SyntheticAgent:
    agent_id: str
    default_passed: bool
    case_count: int
    raises: str | None

    @classmethod
    def from_fixture(cls, entries: list[dict[str, Any]]) -> list[_SyntheticAgent]:
        out: list[_SyntheticAgent] = []
        for entry in entries:
            out.append(
                cls(
                    agent_id=str(entry["agent_id"]),
                    default_passed=bool(entry.get("default_passed", True)),
                    case_count=int(entry.get("case_count", 1)),
                    raises=entry.get("raises"),
                )
            )
        return out


@dataclass(frozen=True)
class _FakeEntryPoint:
    name: str
    group: str
    _target: object

    def load(self) -> object:
        return self._target


def _materialize_case_dirs(root: Path, agents: list[_SyntheticAgent]) -> None:
    for agent in agents:
        dir_ = root / agent.agent_id
        dir_.mkdir(parents=True, exist_ok=True)
        for i in range(agent.case_count):
            (dir_ / f"c{i:02d}.yaml").write_text(
                f"case_id: {agent.agent_id}_c{i:02d}\n"
                f"description: synthetic case for {agent.agent_id}\n"
                "fixture: {}\n"
                "expected: {}\n",
                encoding="utf-8",
            )


def _make_runner_class(agent: _SyntheticAgent) -> type:
    raises_msg = agent.raises
    default_passed = agent.default_passed
    agent_name = agent.agent_id

    class _Runner:
        @property
        def agent_name(self) -> str:
            return agent_name

        async def run(
            self,
            case: EvalCase,
            *,
            workspace: Path,
            llm_provider: LLMProvider | None = None,
        ) -> RunOutcome:
            del case, workspace, llm_provider
            if raises_msg is not None:
                raise RuntimeError(raises_msg)
            return default_passed, None if default_passed else "synthetic fail", {}, None

    return _Runner


@contextmanager
def _patched_entry_points(agents: list[_SyntheticAgent]) -> Iterator[None]:
    """Monkey-patch ``entry_points`` in both modules that read it."""
    eps = [
        _FakeEntryPoint(
            name=agent.agent_id,
            group="nexus_eval_runners",
            _target=_make_runner_class(agent),
        )
        for agent in agents
    ]

    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        if group != "nexus_eval_runners":
            return []
        return list(eps)

    original_batch = getattr(batch_module, "entry_points")  # noqa: B009
    original_ab = getattr(ab_module, "entry_points")  # noqa: B009
    setattr(batch_module, "entry_points", fake_entry_points)  # noqa: B010
    setattr(ab_module, "entry_points", fake_entry_points)  # noqa: B010
    try:
        yield
    finally:
        setattr(batch_module, "entry_points", original_batch)  # noqa: B010
        setattr(ab_module, "entry_points", original_ab)  # noqa: B010


# ---------------------------------------------------------------------------
# SemanticStore mock with prior scorecards
# ---------------------------------------------------------------------------


def _build_prior_rows(entries: list[dict[str, Any]]) -> list[EntityRow]:
    rows: list[EntityRow] = []
    now = datetime(2026, 5, 21, tzinfo=UTC)
    for i, entry in enumerate(entries):
        pass_rate = float(entry["pass_rate"])
        agent_id = str(entry["agent_id"])
        run_id = str(entry.get("run_id", f"r_prior_{i}"))
        rows.append(
            EntityRow(
                entity_id=f"ent_{agent_id}",
                tenant_id="cust_eval",
                entity_type="agent_scorecard",
                external_id=f"cust_eval:{run_id}:{agent_id}",
                properties={
                    "customer_id": "cust_eval",
                    "run_id": run_id,
                    "agent_id": agent_id,
                    "total_cases": 10,
                    "passed": round(pass_rate * 10),
                    "failed": 10 - round(pass_rate * 10),
                    "pass_rate": pass_rate,
                    "error": None,
                    "evaluated_at": now.isoformat(),
                },
                created_at=now,
            )
        )
    return rows


def _build_store_mock(prior_rows: list[EntityRow]) -> AsyncMock:
    entity_ids: dict[tuple[str, str], str] = {}

    async def fake_list(*, tenant_id: str, entity_type: str) -> list[EntityRow]:
        del tenant_id
        if entity_type == "agent_scorecard":
            return list(prior_rows)
        return []

    async def fake_upsert(
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str:
        del tenant_id, properties
        key = (entity_type, external_id)
        if key not in entity_ids:
            entity_ids[key] = f"ent_{entity_type}_{len(entity_ids)}"
        return entity_ids[key]

    store = AsyncMock(spec=SemanticStore)
    store.list_entities_by_type.side_effect = fake_list
    store.upsert_entity.side_effect = fake_upsert
    return store


# ---------------------------------------------------------------------------
# A/B inputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ABInputs:
    target_agent: str
    variant_a: Path
    variant_b: Path


def _parse_ab_inputs(spec: dict[str, Any] | None, workspace: Path) -> _ABInputs | None:
    if not spec:
        return None
    variant_a = workspace / str(spec["variant_a_dirname"])
    variant_b = workspace / str(spec["variant_b_dirname"])
    for d in (variant_a, variant_b):
        d.mkdir(parents=True, exist_ok=True)
        (d / "README.md").write_text(f"# {d.name}\n\nA test variant.\n", encoding="utf-8")
    return _ABInputs(
        target_agent=str(spec["target_agent"]),
        variant_a=variant_a,
        variant_b=variant_b,
    )


# ---------------------------------------------------------------------------
# Stub responses (Task 14 layout; meta-harness rarely needs LLM, but
# the hook is here for cases that may add one in v0.2)
# ---------------------------------------------------------------------------


def _resolve_canned_responses(case: EvalCase) -> list[str]:
    case_dir = _STUB_RESPONSES_ROOT / case.case_id
    responses_file = case_dir / "responses.json"
    if responses_file.is_file():
        raw = json.loads(responses_file.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(f"stub_responses/{case.case_id}/responses.json must be a JSON list")
        return [str(r) for r in raw]
    return []


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _evaluate(
    case: EvalCase,
    report: MetaHarnessReport,
    workspace: Path,
    *,
    store_mock: AsyncMock | None,
) -> tuple[bool, str | None]:
    expected = case.expected

    expected_total = expected.get("total_agents_evaluated")
    if expected_total is not None and report.total_agents_evaluated != int(expected_total):
        return (
            False,
            f"total_agents_evaluated expected {expected_total}, "
            f"got {report.total_agents_evaluated}",
        )

    expected_success = expected.get("successful_runs")
    if expected_success is not None and report.successful_runs != int(expected_success):
        return (
            False,
            f"successful_runs expected {expected_success}, got {report.successful_runs}",
        )

    expected_regressions = expected.get("regressions_count")
    if expected_regressions is not None and report.total_regressions != int(expected_regressions):
        return (
            False,
            f"regressions_count expected {expected_regressions}, got {report.total_regressions}",
        )

    expected_ab_present = expected.get("ab_present")
    if expected_ab_present is not None:
        actual_present = report.ab_comparison is not None
        if actual_present != bool(expected_ab_present):
            return False, f"ab_present expected {expected_ab_present}, got {actual_present}"

    expected_ab_byte_equal = expected.get("ab_byte_equal")
    if (
        expected_ab_byte_equal is not None
        and report.ab_comparison is not None
        and report.ab_comparison.byte_equal != bool(expected_ab_byte_equal)
    ):
        return (
            False,
            f"ab_byte_equal expected {expected_ab_byte_equal}, "
            f"got {report.ab_comparison.byte_equal}",
        )

    expected_manifest_count = expected.get("manifest_count")
    if expected_manifest_count is not None and len(report.manifests) != int(
        expected_manifest_count
    ):
        return (
            False,
            f"manifest_count expected {expected_manifest_count}, got {len(report.manifests)}",
        )

    markdown_path = workspace / "meta_harness_report.md"
    md_required = expected.get("markdown_contains") or []
    if md_required:
        markdown = markdown_path.read_text(encoding="utf-8")
        for sub in md_required:
            if str(sub) not in markdown:
                return False, f"meta_harness_report.md missing required substring: {sub!r}"

    md_excluded = expected.get("markdown_excludes") or []
    if md_excluded:
        markdown = markdown_path.read_text(encoding="utf-8")
        for sub in md_excluded:
            if str(sub) in markdown:
                return False, f"meta_harness_report.md must NOT contain: {sub!r}"

    expected_upserts = expected.get("scorecard_upserts")
    if expected_upserts is not None:
        actual = _count_upserts(store_mock)
        if actual != int(expected_upserts):
            return False, f"scorecard_upserts expected {expected_upserts}, got {actual}"

    return True, None


def _count_upserts(store_mock: AsyncMock | None) -> int:
    if store_mock is None:
        return 0
    return int(store_mock.upsert_entity.await_count)


# Unused-import guard — _resolve_canned_responses is the future hook for
# cases that need LLM stubs; reference it here so static checkers don't
# strip the import path during dead-code elimination.
_ = _resolve_canned_responses


__all__ = ["MetaHarnessEvalRunner"]
