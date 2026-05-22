"""``MetaHarnessEvalRunner`` — the canonical ``EvalRunner`` for A.4.

Per Task 12 of the A.4 v0.1 plan + Task 15 of the A.4 v0.2 plan.
Each case fixture defines a small synthetic fleet of agents that the
runner registers as ephemeral ``nexus_eval_runners`` entry points; the
runner then invokes ``meta_harness.agent.run`` against that fleet and
compares the returned ``MetaHarnessReport`` to ``case.expected``.

**v0.2 skill-lifecycle support (Task 15).** When ``skill_lifecycle_enabled``
is ``true`` in the fixture, the runner wires ``llm_provider``,
``audit_chain_loader``, and ``eval_runner_loader`` so Stages 6 + 7
execute. The fixture can also pre-populate the skill-class registry
and configure per-agent audit entries + overlay-failure behaviour.

**Fixture keys** (under ``fixture``):

- ``agents: list[dict]`` — synthetic agents to register. Each entry:
  ``{"agent_id": str, "default_passed": bool, "case_count": int,
  "raises": Optional[str], "fail_when_overlay": Optional[bool],
  "audit_entries": Optional[list[dict]]}``.
- ``prior_scorecards: list[dict]`` — previous-run scorecards.
- ``semantic_store: bool`` — when False, passes ``semantic_store=None``.
- ``ab: Optional[dict]`` — A/B-compare inputs.
- ``skill_lifecycle_enabled: bool`` (v0.2) — when True, wires
  ``llm_provider`` / ``audit_chain_loader`` / ``eval_runner_loader``
  so Stages 6 + 7 run.
- ``llm_responses: list[str]`` (v0.2) — canned LLM responses for
  ``FakeLLMProvider``.
- ``skill_registry: dict`` (v0.2) — pre-populated registry shape
  ``{"classes": [{"agent_id": ..., "category": ..., ...}]}``.

**Expected keys** (under ``expected``):

- ``total_agents_evaluated: int``
- ``successful_runs: int``
- ``regressions_count: int``
- ``ab_present: bool``
- ``ab_byte_equal: Optional[bool]``
- ``manifest_count: int``
- ``markdown_contains: list[str]``
- ``markdown_excludes: list[str]``
- ``scorecard_upserts: Optional[int]``
- ``skill_pending_review_count: int`` (v0.2)
- ``skill_deployment_count: int`` (v0.2)
- ``skill_auto_deploy_count: int`` (v0.2)
- ``skill_rejected_count: int`` (v0.2)
- ``notification_file_exists: bool`` (v0.2)
- ``candidate_meta_exists: bool`` (v0.2)

Registered via the ``[project.entry-points."nexus_eval_runners"]``
hook in ``pyproject.toml``.
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
        lifecycle_enabled = bool(fixture.get("skill_lifecycle_enabled", False))

        synthetic_agents = _SyntheticAgent.from_fixture(fixture.get("agents") or [])
        cases_root = workspace / "cases_root"
        _materialize_case_dirs(cases_root, synthetic_agents)

        prior_rows = _build_prior_rows(fixture.get("prior_scorecards") or [])
        store_mock = _build_store_mock(prior_rows) if use_store else None

        ab_inputs = _parse_ab_inputs(fixture.get("ab"), workspace)

        lifecycle_kwargs: dict[str, Any] = {}
        if lifecycle_enabled:
            lifecycle_kwargs = _build_lifecycle_kwargs(
                fixture=fixture,
                synthetic_agents=synthetic_agents,
                workspace=workspace,
            )

        with _patched_entry_points(synthetic_agents):
            report = await agent_mod.run(
                customer_id="cust_eval",
                run_id="r_eval",
                workspace_root=workspace,
                semantic_store=cast(SemanticStore, store_mock) if store_mock else None,
                llm_provider=lifecycle_kwargs.get("llm_provider", llm_provider),
                ab_variant_a=ab_inputs.variant_a if ab_inputs else None,
                ab_variant_b=ab_inputs.variant_b if ab_inputs else None,
                ab_target_agent=ab_inputs.target_agent if ab_inputs else None,
                cases_resolver=lambda aid: cases_root / aid,
                audit_chain_loader=lifecycle_kwargs.get("audit_chain_loader"),
                eval_runner_loader=lifecycle_kwargs.get("eval_runner_loader"),
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
            "skill_pending_review_count": len(report.skill_lifecycle.pending_operator_review),
            "skill_deployment_count": len(report.skill_lifecycle.deployments),
            "skill_auto_deploy_count": sum(
                1 for d in report.skill_lifecycle.deployments if d.approval_mode == "auto_approved"
            ),
            "skill_rejected_count": sum(
                1 for d in report.skill_lifecycle.deployments if not d.deployed
            ),
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
    fail_when_overlay: bool = False
    audit_entries: list[dict[str, Any]] | None = None

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
                    fail_when_overlay=bool(entry.get("fail_when_overlay", False)),
                    audit_entries=entry.get("audit_entries"),
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
    fail_when_overlay = agent.fail_when_overlay

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
            if fail_when_overlay:
                from meta_harness.skill_eval_gate import get_active_skill_overlay

                if get_active_skill_overlay() is not None:
                    return False, "regression under candidate overlay", {}, None
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
# Skill-lifecycle wiring (v0.2 / Task 15)
# ---------------------------------------------------------------------------


def _build_lifecycle_kwargs(
    *,
    fixture: dict[str, Any],
    synthetic_agents: list[_SyntheticAgent],
    workspace: Path,
) -> dict[str, Any]:
    """Construct ``llm_provider``, ``audit_chain_loader``, and
    ``eval_runner_loader`` from the fixture so Stages 6 + 7 execute.

    Also pre-populates the skill-class registry on disk when the
    fixture carries a ``skill_registry`` key.
    """
    from charter.llm import (
        FakeLLMProvider,
        LLMResponse,
        TokenUsage,
    )
    from eval_framework.runner import EvalRunner

    # Build FakeLLMProvider from canned responses.
    canned: list[str] = fixture.get("llm_responses") or []
    responses = [
        LLMResponse(
            text=r,
            stop_reason="end_turn",
            usage=TokenUsage(input_tokens=0, output_tokens=0),
        )
        for r in canned
    ]
    llm_provider = FakeLLMProvider(responses=responses)

    # Build per-agent audit-entry map.
    agent_map: dict[str, list[dict[str, Any]]] = {}
    for agent in synthetic_agents:
        if agent.audit_entries:
            agent_map[agent.agent_id] = list(agent.audit_entries)

    def audit_chain_loader(agent_id: str) -> list[dict[str, Any]]:
        return agent_map.get(agent_id, [])

    # Build eval_runner_loader that returns the synthetic runner for
    # each target agent (same class that BATCH_EVAL uses).
    def eval_runner_loader(agent_id: str) -> EvalRunner:
        agent = next(a for a in synthetic_agents if a.agent_id == agent_id)
        return _make_runner_class(agent)()

    # Pre-populate registry on disk if the fixture provides one.
    registry_fixture = fixture.get("skill_registry")
    if registry_fixture is not None:
        from meta_harness.skill_registry import (
            SkillClassRegistry,
            save_skill_class_registry,
        )

        registry = SkillClassRegistry.model_validate(registry_fixture)
        save_skill_class_registry(registry, workspace_root=workspace)

    return {
        "llm_provider": llm_provider,
        "audit_chain_loader": audit_chain_loader,
        "eval_runner_loader": eval_runner_loader,
    }


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

    # ----- v0.2 skill-lifecycle checks (Task 15) -----

    expected_pending = expected.get("skill_pending_review_count")
    if expected_pending is not None:
        actual_pending = len(report.skill_lifecycle.pending_operator_review)
        if actual_pending != int(expected_pending):
            return (
                False,
                f"skill_pending_review_count expected {expected_pending}, got {actual_pending}",
            )

    expected_deployments = expected.get("skill_deployment_count")
    if expected_deployments is not None:
        actual_deployments = len(report.skill_lifecycle.deployments)
        if actual_deployments != int(expected_deployments):
            return (
                False,
                f"skill_deployment_count expected {expected_deployments}, got {actual_deployments}",
            )

    expected_auto = expected.get("skill_auto_deploy_count")
    if expected_auto is not None:
        actual_auto = sum(
            1 for d in report.skill_lifecycle.deployments if d.approval_mode == "auto_approved"
        )
        if actual_auto != int(expected_auto):
            return False, f"skill_auto_deploy_count expected {expected_auto}, got {actual_auto}"

    expected_rejected = expected.get("skill_rejected_count")
    if expected_rejected is not None:
        actual_rejected = sum(1 for d in report.skill_lifecycle.deployments if not d.deployed)
        if actual_rejected != int(expected_rejected):
            return (
                False,
                f"skill_rejected_count expected {expected_rejected}, got {actual_rejected}",
            )

    expected_notification = expected.get("notification_file_exists")
    if expected_notification is not None:
        from meta_harness.skill_approval import compute_notification_path

        for skill_id in report.skill_lifecycle.pending_operator_review:
            npath = compute_notification_path(workspace, skill_id)
            actual_exists = npath.is_file()
            if actual_exists != bool(expected_notification):
                return False, (
                    f"notification_file_exists expected {expected_notification}, "
                    f"got {actual_exists} for {skill_id}"
                )

    expected_meta = expected.get("candidate_meta_exists")
    if expected_meta is not None:
        meta_dir = workspace / ".nexus" / "candidate-skills"
        any_meta = False
        if meta_dir.is_dir():
            for meta_file in meta_dir.rglob("candidate_meta.json"):
                if meta_file.is_file():
                    any_meta = True
                    break
        if any_meta != bool(expected_meta):
            return False, f"candidate_meta_exists expected {expected_meta}, got {any_meta}"

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
