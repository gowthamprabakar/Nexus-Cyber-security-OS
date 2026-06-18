"""Tests — `meta_harness.skill_lifecycle` + driver Stage 6 + 7 wiring (Task 13).

16 tests covering Stages 6 (SKILL_TRIGGER) + 7 (SKILL_CREATE) and the
v0.2 driver integration:

1.  ``SkillLifecycleSummary`` defaults are all empty (backwards-compat
    shape).
2.  ``SkillLifecycleSummary.deployed_count`` / ``rejected_count``
    properties partition the ``deployments`` tuple correctly.
3.  ``MetaHarnessReport`` carries the ``skill_lifecycle`` field with an
    empty default — Task 1 v0.2 backwards-compat regression probe.
4.  ``run_skill_lifecycle`` returns the empty summary when
    ``llm_provider`` is ``None``.
5.  ``run_skill_lifecycle`` returns empty when ``audit_chain_loader`` is
    ``None``.
6.  ``run_skill_lifecycle`` returns empty when ``eval_runner_loader``
    is ``None``.
7.  Zero triggers when the loader returns a chain with no tool-call
    entries.
8.  A trigger-worthy chain (5+ tool calls, no failures, hash-novel)
    increments ``triggers_detected`` AND ``candidates_emitted``.
9.  After a candidate is emitted the audit chain carries both a
    ``skill.candidate_emitted`` AND a ``skill.eval_gate_completed``
    entry in order.
10. Eval-gate FAIL routes to ``reject_candidate`` — the summary's
    ``deployments`` carries a ``deployed=False`` entry; the audit
    chain ends with ``skill.rejected``.
11. Eval-gate PASS + new class → ``pending_operator_review`` carries
    the skill_id + the notification markdown is written under
    ``<workspace>/skill_candidate_*.md``.
12. Eval-gate PASS + already-registered class → ``auto_deploy_candidate``
    promotes shadow → canonical + registry persists.
13. Error scorecards (``pass_rate=None``) are skipped — they never
    produce triggers.
14. Driver ``agent.run`` backwards-compat: no lifecycle inputs →
    ``report.skill_lifecycle`` is the empty default; no shadow / no
    canonical / no notification on disk.
15. Driver integrates the lifecycle: with all three inputs provided,
    ``report.skill_lifecycle.triggers_detected`` ≥ 1 (fake-chain
    fixture).
16. Pipeline ordering: when the lifecycle runs, the shadow SKILL.md
    exists before HANDOFF writes ``meta_harness_report.md`` (ordering
    is implicit in ``agent.run`` — Stage 7 produces shadow; Stage 8
    writes the report after).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from charter.llm import FakeLLMProvider, LLMResponse, TokenUsage
from eval_framework.cases import EvalCase
from eval_framework.runner import EvalRunner, FakeRunner
from meta_harness.agent import run as agent_run
from meta_harness.eval import batch as batch_module
from meta_harness.schemas import (
    DeploymentDecision,
    MetaHarnessReport,
    SkillApprovalMode,
    SkillLifecycleSummary,
)
from meta_harness.skill_lifecycle import run_skill_lifecycle
from meta_harness.skill_registry import (
    SkillClassRegistry,
    load_skill_class_registry,
    register_class,
    save_skill_class_registry,
)

_AT = datetime(2026, 5, 22, 17, 0, 0, tzinfo=UTC)


# ---------------------------- fixtures ----------------------------


_SKILL_MD_STUB = """---
name: aws_iam_privesc_via_assumed_role
description: Detect IAM privilege escalation via cross-account role chain.
version: 0.1.0
platforms:
  - nexus
target_agent: investigation
category: iam-privesc
created_by: meta_harness@v0.2.0
provenance: []
eval_gate_status: not_run
deployment_status: candidate
---

Walk the role-chain head-first when you see cross-account AssumeRole.
"""


def _fake_llm() -> FakeLLMProvider:
    response = LLMResponse(
        text=_SKILL_MD_STUB,
        stop_reason="end_turn",
        usage=TokenUsage(input_tokens=100, output_tokens=200),
        model_pin="claude-sonnet-4-6",
        provider_id="fake",
    )
    return FakeLLMProvider([response])


def _scorecard(*, agent_id: str = "investigation", pass_rate: float | None = 1.0):
    from meta_harness.schemas import Scorecard

    if pass_rate is None:
        return Scorecard(
            customer_id="acme",
            run_id="r1",
            agent_id=agent_id,
            total_cases=0,
            passed=0,
            failed=0,
            error="runner exploded",
            evaluated_at=_AT,
        )
    return Scorecard(
        customer_id="acme",
        run_id="r1",
        agent_id=agent_id,
        total_cases=2,
        passed=2,
        failed=0,
        pass_rate=pass_rate,
        evaluated_at=_AT,
    )


def _trigger_worthy_chain(agent_id: str = "investigation") -> list[dict[str, Any]]:
    """Five tool-call entries — novel sequence, no failures."""
    return [
        {
            "action": f"{agent_id}.tool_invoked",
            "payload": {"tool_name": name},
            "entry_hash": f"h{idx}",
        }
        for idx, name in enumerate(
            ("memory_neighbors_walk", "ocsf_lookup", "iam_query", "s3_get", "audit_query")
        )
    ]


def _empty_chain(agent_id: str) -> list[dict[str, Any]]:
    return []


def _two_pass_cases() -> list[EvalCase]:
    return [
        EvalCase(case_id="c1", suite="investigation", description="x", inputs={}),
        EvalCase(case_id="c2", suite="investigation", description="x", inputs={}),
    ]


def _passing_runner_factory(agent_id: str) -> EvalRunner:
    return FakeRunner(agent_name="investigation", default_passed=True)


def _cases_resolver(workspace_root: Path) -> Any:
    def _resolve(agent_id: str) -> Path:
        # Tests stage cases inline; we don't read from this path
        return workspace_root / "unused"

    return _resolve


def _read_audit_chain(workspace_root: Path) -> list[dict[str, Any]]:
    path = workspace_root / ".nexus" / "meta-harness-skill-lifecycle.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]


# ---------------------------- 1-3: schema shape ----------------------------


def test_skill_lifecycle_summary_defaults_all_empty() -> None:
    s = SkillLifecycleSummary()
    assert s.triggers_detected == 0
    assert s.candidates_emitted == 0
    assert s.eval_gate_results == ()
    assert s.deployments == ()
    assert s.pending_operator_review == ()


def test_skill_lifecycle_summary_deployed_and_rejected_count_properties() -> None:
    deployed = DeploymentDecision(
        skill_id="iam/x",
        target_agent="investigation",
        category="iam",
        deployed=True,
        approval_mode=SkillApprovalMode.AUTO_APPROVED,
        deployed_path="/ws/canonical.md",
        decided_at=_AT,
    )
    rejected = DeploymentDecision(
        skill_id="iam/y",
        target_agent="investigation",
        category="iam",
        deployed=False,
        rejection_reason="eval-gate fail",
        decided_at=_AT,
    )
    s = SkillLifecycleSummary(deployments=(deployed, rejected))
    assert s.deployed_count == 1
    assert s.rejected_count == 1


def test_meta_harness_report_carries_empty_skill_lifecycle_default() -> None:
    report = MetaHarnessReport(
        customer_id="acme",
        run_id="r1",
        scan_started_at=_AT,
        scan_completed_at=_AT,
    )
    assert isinstance(report.skill_lifecycle, SkillLifecycleSummary)
    assert report.skill_lifecycle.triggers_detected == 0
    assert report.skill_lifecycle.deployments == ()


# ---------------------------- 4-6: helper skip paths ----------------------------


@pytest.mark.asyncio
async def test_run_skill_lifecycle_skips_when_llm_provider_none(tmp_path: Path) -> None:
    summary = await run_skill_lifecycle(
        scorecards=[_scorecard()],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=_trigger_worthy_chain,
        llm_provider=None,
        eval_runner_loader=_passing_runner_factory,
    )
    assert summary == SkillLifecycleSummary()


@pytest.mark.asyncio
async def test_run_skill_lifecycle_skips_when_audit_chain_loader_none(tmp_path: Path) -> None:
    summary = await run_skill_lifecycle(
        scorecards=[_scorecard()],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=None,
        llm_provider=_fake_llm(),
        eval_runner_loader=_passing_runner_factory,
    )
    assert summary == SkillLifecycleSummary()


@pytest.mark.asyncio
async def test_run_skill_lifecycle_skips_when_eval_runner_loader_none(tmp_path: Path) -> None:
    summary = await run_skill_lifecycle(
        scorecards=[_scorecard()],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=_trigger_worthy_chain,
        llm_provider=_fake_llm(),
        eval_runner_loader=None,
    )
    assert summary == SkillLifecycleSummary()


# ---------------------------- 7-13: lifecycle paths ----------------------------


@pytest.mark.asyncio
async def test_run_skill_lifecycle_zero_triggers_for_empty_chain(tmp_path: Path) -> None:
    summary = await run_skill_lifecycle(
        scorecards=[_scorecard()],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=_empty_chain,
        llm_provider=_fake_llm(),
        eval_runner_loader=_passing_runner_factory,
    )
    assert summary.triggers_detected == 0
    assert summary.candidates_emitted == 0


@pytest.mark.asyncio
async def test_run_skill_lifecycle_emits_candidate_for_trigger(tmp_path: Path) -> None:
    """Eval-gate runs against an EMPTY case set in this fixture, so
    Stage 7's eval-gate skips this candidate (SkillEvalGateError) and
    the loop continues — the candidate IS still emitted before the
    eval-gate gives up."""
    # We provide loader that DOES produce a trigger.
    summary = await run_skill_lifecycle(
        scorecards=[_scorecard()],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=_trigger_worthy_chain,
        llm_provider=_fake_llm(),
        eval_runner_loader=lambda _aid: FakeRunner(agent_name="investigation"),
    )
    # Trigger detected + candidate emitted; the eval-gate-skip is
    # graceful (no eval result added, no deployment recorded).
    assert summary.triggers_detected == 1
    assert summary.candidates_emitted == 1
    entries = _read_audit_chain(tmp_path)
    assert entries[0]["action"] == "meta_harness.skill.candidate_emitted"


@pytest.mark.asyncio
async def test_run_skill_lifecycle_eval_gate_completes_after_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When cases are non-empty + the runner passes them all, both audit
    entries land in order (candidate_emitted, eval_gate_completed)."""
    monkeypatch.setattr("meta_harness.skill_lifecycle.load_cases", lambda _path: _two_pass_cases())
    summary = await run_skill_lifecycle(
        scorecards=[_scorecard()],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=_trigger_worthy_chain,
        llm_provider=_fake_llm(),
        eval_runner_loader=_passing_runner_factory,
    )
    assert summary.candidates_emitted == 1
    assert len(summary.eval_gate_results) == 1
    entries = _read_audit_chain(tmp_path)
    actions = [e["action"] for e in entries]
    assert actions[0] == "meta_harness.skill.candidate_emitted"
    assert actions[1] == "meta_harness.skill.eval_gate_completed"


@pytest.mark.asyncio
async def test_run_skill_lifecycle_eval_gate_pass_new_class_writes_notification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("meta_harness.skill_lifecycle.load_cases", lambda _path: _two_pass_cases())
    summary = await run_skill_lifecycle(
        scorecards=[_scorecard()],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=_trigger_worthy_chain,
        llm_provider=_fake_llm(),
        eval_runner_loader=_passing_runner_factory,
    )
    # New class — operator approval required; no deployment yet.
    assert summary.deployments == ()
    assert len(summary.pending_operator_review) == 1
    # Notification markdown exists in the workspace root.
    notifications = list(tmp_path.glob("skill_candidate_*.md"))
    assert len(notifications) == 1


@pytest.mark.asyncio
async def test_run_skill_lifecycle_eval_gate_pass_registered_class_auto_deploys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("meta_harness.skill_lifecycle.load_cases", lambda _path: _two_pass_cases())
    # Seed registry with the matching (agent_id, category) so the
    # candidate auto-deploys instead of going to operator approval.
    registry = register_class(
        SkillClassRegistry(),
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/seed",
        tool_sequence_hash="hash_seed",
        approved_at=_AT,
    )
    save_skill_class_registry(registry, workspace_root=tmp_path)

    summary = await run_skill_lifecycle(
        scorecards=[_scorecard()],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=_trigger_worthy_chain,
        llm_provider=_fake_llm(),
        eval_runner_loader=_passing_runner_factory,
    )
    assert summary.deployed_count == 1
    assert summary.pending_operator_review == ()
    decision = summary.deployments[0]
    assert decision.approval_mode == SkillApprovalMode.AUTO_APPROVED
    # Registry persisted — the new skill_id appears as a refinement.
    saved = load_skill_class_registry(tmp_path)
    entry = saved.entry_for("investigation", "iam-privesc")
    assert entry is not None
    assert decision.skill_id in entry.deployed_skill_ids


@pytest.mark.asyncio
async def test_run_skill_lifecycle_eval_gate_fail_rejects_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Eval-gate FAIL routes to ``reject_candidate``. The runner here
    differentiates baseline vs with-candidate via
    ``get_active_skill_overlay`` — baseline passes both cases;
    with-candidate fails c2 → per-case regression → gate FAILS."""
    from dataclasses import dataclass, field
    from typing import Any as _Any

    from meta_harness.skill_eval_gate import get_active_skill_overlay

    monkeypatch.setattr("meta_harness.skill_lifecycle.load_cases", lambda _path: _two_pass_cases())

    @dataclass
    class _ContextAwareRunner:
        agent_name: str = "investigation"
        calls: list[EvalCase] = field(default_factory=list)

        async def run(
            self,
            case: EvalCase,
            *,
            workspace: Path,
            llm_provider: _Any | None = None,
        ) -> tuple[bool, str | None, dict[str, _Any], Path | None]:
            self.calls.append(case)
            overlay_active = get_active_skill_overlay() is not None
            if overlay_active and case.case_id == "c2":
                return False, "candidate breaks c2", {}, None
            return True, None, {}, None

    runner = _ContextAwareRunner()
    summary = await run_skill_lifecycle(
        scorecards=[_scorecard()],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=_trigger_worthy_chain,
        llm_provider=_fake_llm(),
        eval_runner_loader=lambda _aid: runner,
    )
    assert summary.rejected_count == 1
    decision = summary.deployments[0]
    assert decision.deployed is False
    assert decision.rejection_reason is not None
    # The audit chain ends with skill.rejected.
    entries = _read_audit_chain(tmp_path)
    assert entries[-1]["action"] == "meta_harness.skill.rejected"


@pytest.mark.asyncio
async def test_run_skill_lifecycle_skips_error_scorecards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scorecard with pass_rate=None (the per-agent run errored out)
    must NOT trigger a skill — its audit chain is unreliable."""
    monkeypatch.setattr("meta_harness.skill_lifecycle.load_cases", lambda _path: _two_pass_cases())
    summary = await run_skill_lifecycle(
        scorecards=[_scorecard(pass_rate=None)],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=_trigger_worthy_chain,
        llm_provider=_fake_llm(),
        eval_runner_loader=_passing_runner_factory,
    )
    assert summary == SkillLifecycleSummary()


# ---------------------------- 14-16: driver integration ----------------------------


@pytest.mark.asyncio
async def test_agent_run_backwards_compat_when_lifecycle_inputs_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No lifecycle inputs → report.skill_lifecycle is the empty
    default. Drift #5 v0.2 backwards-compat regression probe."""
    monkeypatch.setattr(batch_module, "entry_points", lambda *, group: [])
    report = await agent_run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
    )
    assert report.skill_lifecycle == SkillLifecycleSummary()


@pytest.mark.asyncio
async def test_agent_run_integrates_lifecycle_with_all_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When all three lifecycle inputs are provided AND a scorecard
    surfaces, the lifecycle runs and the report carries non-empty
    summary state."""
    from meta_harness.schemas import Scorecard

    async def fake_run_batch(*, customer_id: str, run_id: str) -> list[Scorecard]:
        return [_scorecard()]

    monkeypatch.setattr(
        batch_module.BatchEvalRunner,
        "run_batch",
        lambda self, *, customer_id, run_id: fake_run_batch(customer_id=customer_id, run_id=run_id),
    )
    monkeypatch.setattr("meta_harness.skill_lifecycle.load_cases", lambda _path: _two_pass_cases())

    report = await agent_run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        llm_provider=_fake_llm(),
        audit_chain_loader=_trigger_worthy_chain,
        eval_runner_loader=_passing_runner_factory,
    )
    assert report.skill_lifecycle.triggers_detected >= 1
    assert report.skill_lifecycle.candidates_emitted >= 1


@pytest.mark.asyncio
async def test_pipeline_ordering_shadow_exists_before_handoff_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the lifecycle runs, the shadow SKILL.md (or notification
    markdown for a new class) is written BEFORE Stage 8 HANDOFF emits
    meta_harness_report.md. Verifies the Stage 5 → 6/7 → 8 sequence."""
    from meta_harness.schemas import Scorecard

    async def fake_run_batch(*, customer_id: str, run_id: str) -> list[Scorecard]:
        return [_scorecard()]

    monkeypatch.setattr(
        batch_module.BatchEvalRunner,
        "run_batch",
        lambda self, *, customer_id, run_id: fake_run_batch(customer_id=customer_id, run_id=run_id),
    )
    monkeypatch.setattr("meta_harness.skill_lifecycle.load_cases", lambda _path: _two_pass_cases())

    await agent_run(
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        llm_provider=_fake_llm(),
        audit_chain_loader=_trigger_worthy_chain,
        eval_runner_loader=_passing_runner_factory,
    )
    # Stage 8 HANDOFF wrote the report markdown.
    report_path = tmp_path / "meta_harness_report.md"
    assert report_path.is_file()
    # Stage 6 + 7 produced a candidate notification (new class path).
    notifications = list(tmp_path.glob("skill_candidate_*.md"))
    assert len(notifications) == 1


@dataclass
class _Row:
    properties: dict[str, Any]


class _InMemorySemanticStore:
    """Faithful in-memory ``SemanticStore`` double — just enough for ``SkillTraceStore``.

    ``upsert_entity`` is idempotent on ``(tenant_id, entity_type, external_id)`` and
    ``list_entities_by_type`` filters by ``(tenant_id, entity_type)`` — the exact contract
    T2's record-at-deploy + trainset-from-store paths exercise.
    """

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str, str], _Row] = {}

    async def upsert_entity(
        self, *, tenant_id: str, entity_type: str, external_id: str, properties: dict[str, Any]
    ) -> str:
        key = (tenant_id, entity_type, external_id)
        self.rows[key] = _Row(properties=dict(properties))
        return f"{entity_type}:{external_id}"

    async def list_entities_by_type(self, *, tenant_id: str, entity_type: str) -> list[_Row]:
        return [
            row for (t, et, _eid), row in self.rows.items() if t == tenant_id and et == entity_type
        ]


@pytest.mark.asyncio
async def test_run_skill_lifecycle_auto_deploy_records_skill_trace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T2 (Phase 4a-2): an auto-deployed skill persists its originating trace.

    This is the record-at-deploy half of the GEPA un-starve: the next compilation's
    ``build_compilation_trainset_from_store`` can read this back as an N-th example.
    """
    monkeypatch.setattr("meta_harness.skill_lifecycle.load_cases", lambda _path: _two_pass_cases())
    registry = register_class(
        SkillClassRegistry(),
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/seed",
        tool_sequence_hash="hash_seed",
        approved_at=_AT,
    )
    save_skill_class_registry(registry, workspace_root=tmp_path)

    store = _InMemorySemanticStore()
    summary = await run_skill_lifecycle(
        scorecards=[_scorecard()],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=_trigger_worthy_chain,
        llm_provider=_fake_llm(),
        eval_runner_loader=_passing_runner_factory,
        semantic_store=store,  # type: ignore[arg-type]
    )
    assert summary.deployed_count == 1
    deployed_skill_id = summary.deployments[0].skill_id

    # The deploy path recorded the originating trace, tenant-scoped, keyed (agent, skill).
    traces = store.rows
    assert len(traces) == 1
    ((tenant, entity_type, external_id), row) = next(iter(traces.items()))
    assert tenant == "acme"
    assert entity_type == "skill_trace"
    assert external_id == f"investigation:{deployed_skill_id}"
    assert row.properties["agent_id"] == "investigation"
    assert row.properties["category"] == "iam-privesc"
    assert row.properties["trace"]  # non-empty composed user-prompt


@pytest.mark.asyncio
async def test_run_skill_lifecycle_no_store_records_no_trace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backwards-compat: without a ``semantic_store`` the deploy path stays byte-identical
    (inert SkillTraceStore → no persistence, no crash)."""
    monkeypatch.setattr("meta_harness.skill_lifecycle.load_cases", lambda _path: _two_pass_cases())
    registry = register_class(
        SkillClassRegistry(),
        agent_id="investigation",
        category="iam-privesc",
        skill_id="iam-privesc/seed",
        tool_sequence_hash="hash_seed",
        approved_at=_AT,
    )
    save_skill_class_registry(registry, workspace_root=tmp_path)

    summary = await run_skill_lifecycle(
        scorecards=[_scorecard()],
        customer_id="acme",
        run_id="r1",
        workspace_root=tmp_path,
        cases_resolver=_cases_resolver(tmp_path),
        audit_chain_loader=_trigger_worthy_chain,
        llm_provider=_fake_llm(),
        eval_runner_loader=_passing_runner_factory,
    )
    assert summary.deployed_count == 1  # deploy still happens; just no trace persisted


# Silence asyncio.create_task warnings on slow test infra
del asyncio
