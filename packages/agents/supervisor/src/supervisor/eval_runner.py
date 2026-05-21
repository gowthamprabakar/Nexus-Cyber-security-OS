"""``SupervisorEvalRunner`` — the canonical ``EvalRunner`` for Supervisor (#0).

Per Task 12 of the Supervisor v0.1 plan + plan §"Q4 — eval-runner
identity": this is the **first eval-runner divergence from the
existing 16-agent pattern**. Where every other agent's eval suite
tests OCSF outputs given input findings, Supervisor's tests
**routing decisions** given input tasks.

Each case fixture defines a single ``IncomingTask`` envelope + an
optional invoker-behavior selector; the runner invokes
``supervisor.agent.run`` against the bundled ``routing/agents.md``
and compares the resulting ``SupervisorReport`` + audit-chain
entries to ``case.expected``.

**Fixture keys** (under ``fixture``):

- ``task_id: str`` — required.
- ``target_agent: str | None`` — routing key.
- ``task_type: str | None`` — routing key.
- ``delta_type: str | None`` — routing key.
- ``trigger_source: "operator_cli" | "events_bus" | "scheduled_queue"``
  (default ``"operator_cli"``).
- ``description: str`` (default ``""``).
- ``invoker_behavior: "ok" | "raise" | "slow"`` (default ``"ok"``).
- ``invoker_delay_sec: float`` (only when ``invoker_behavior="slow"``;
  the contract budget is overridden to a small value so the slow
  invoker trips the timeout deterministically).
- ``extra_rules: list[dict]`` — additional routing rules merged
  with the bundled set (e.g., to seed an Ambiguous case).
- ``extra_triggers: list[dict]`` — additional ``IncomingTask``
  envelopes to fan-out alongside the primary trigger (e.g., the
  over-capacity case).
- ``concurrency: int`` (default 5).

**Expected keys** (under ``expected``):

- ``decision_kind: "match" | "no_match" | "ambiguous" | "escalate"``.
- ``target_agent: str`` — when ``decision_kind == "match"``.
- ``audit_actions: list[str]`` — exact ordered sequence the audit
  chain should carry.
- ``delegation_count: int``.
- ``escalation_count: int``.
- ``triggers_received: int``.

Registered via the ``[project.entry-points."nexus_eval_runners"]``
hook in ``pyproject.toml`` (shipped in Task 1) — Supervisor is
the **17th** entry, and A.4 batch-eval picks it up automatically.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from charter.llm import LLMProvider
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome

from supervisor.agent import run as agent_run
from supervisor.dispatch import DelegationInvoker
from supervisor.routing.parser import load_routing_rules
from supervisor.schemas import (
    DelegationContract,
    IncomingTask,
    RoutingMatch,
    RoutingRule,
    TriggerSource,
)

_BUNDLED_AGENTS_MD = Path(__file__).parent / "routing" / "agents.md"
_STUB_RESPONSES_ROOT = Path(__file__).parent.parent.parent / "eval" / "stub_responses"


class SupervisorEvalRunner:
    """Reference ``EvalRunner`` for Supervisor (#0)."""

    @property
    def agent_name(self) -> str:
        return "supervisor"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        del llm_provider  # Supervisor doesn't consume an LLM in v0.1.
        workspace.mkdir(parents=True, exist_ok=True)
        fixture = case.fixture
        expected = case.expected

        # Build rule set (bundled + extras).
        rules = list(load_routing_rules(_BUNDLED_AGENTS_MD))
        for extra in fixture.get("extra_rules") or []:
            rules.append(RoutingRule.model_validate(extra))

        # Build triggers (primary + extras).
        triggers: list[IncomingTask] = [_build_task(fixture)]
        for extra in fixture.get("extra_triggers") or []:
            triggers.append(_build_task(extra))

        # Select invoker.
        invoker_behavior = str(fixture.get("invoker_behavior", "ok"))
        invoker = _build_invoker(
            behavior=invoker_behavior,
            delay_sec=float(fixture.get("invoker_delay_sec", 5.0)),
        )

        report = await agent_run(
            customer_id="cust_eval",
            workspace_root=workspace,
            routing_rules=rules,
            triggers=triggers,
            invoker=invoker,
            concurrency=int(fixture.get("concurrency", 5)),
        )

        audit_actions = _read_audit_actions(workspace / "audit.jsonl")
        passed, failure_reason = _evaluate(
            expected=expected,
            report=report,
            audit_actions=audit_actions,
        )
        actuals: dict[str, Any] = {
            "triggers_received": report.total_triggers,
            "delegation_count": report.total_delegations,
            "successful_delegations": report.successful_delegations,
            "escalation_count": report.total_escalations,
            "first_decision_kind": (
                report.routing_decisions[0].kind if report.routing_decisions else None
            ),
            "first_target_agent": _first_target_agent(report),
            "audit_actions": audit_actions,
        }
        return passed, failure_reason, actuals, None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_task(fixture: dict[str, Any]) -> IncomingTask:
    trigger_source_raw = fixture.get("trigger_source", "operator_cli")
    try:
        trigger_source = TriggerSource(trigger_source_raw)
    except ValueError as exc:
        raise ValueError(f"unknown trigger_source: {trigger_source_raw!r}") from exc

    return IncomingTask(
        task_id=str(fixture["task_id"]),
        customer_id=str(fixture.get("customer_id", "cust_eval")),
        trigger_source=trigger_source,
        target_agent=_optional_str(fixture.get("target_agent")),
        task_type=_optional_str(fixture.get("task_type")),
        delta_type=_optional_str(fixture.get("delta_type")),
        description=str(fixture.get("description", "")),
        priority=int(fixture.get("priority", 0)),
        received_at=datetime.now(UTC),
    )


def _build_invoker(*, behavior: str, delay_sec: float) -> DelegationInvoker:
    """Three invoker behaviors keyed by string for YAML fixture clarity."""

    async def _ok(contract: DelegationContract) -> None:
        del contract

    async def _raise(contract: DelegationContract) -> None:
        del contract
        raise RuntimeError("synthetic invoker error")

    async def _slow(contract: DelegationContract) -> None:
        import asyncio

        del contract
        await asyncio.sleep(delay_sec)

    if behavior == "ok":
        return _ok
    if behavior == "raise":
        return _raise
    if behavior == "slow":
        return _slow
    raise ValueError(f"unknown invoker_behavior: {behavior!r}")


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _read_audit_actions(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [
        json.loads(line)["action"]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _first_target_agent(report: Any) -> str | None:
    if not report.routing_decisions:
        return None
    decision = report.routing_decisions[0]
    if isinstance(decision, RoutingMatch):
        return decision.target_agent
    return None


def _evaluate(
    *,
    expected: dict[str, Any],
    report: Any,
    audit_actions: list[str],
) -> tuple[bool, str | None]:
    expected_kind = expected.get("decision_kind")
    if expected_kind is not None:
        if not report.routing_decisions:
            return False, f"expected decision_kind={expected_kind!r}; report had no decisions"
        actual = report.routing_decisions[0].kind
        if actual != expected_kind:
            return False, f"decision_kind expected {expected_kind!r}, got {actual!r}"

    expected_target = expected.get("target_agent")
    if expected_target is not None:
        actual_target = _first_target_agent(report)
        if actual_target != expected_target:
            return False, f"target_agent expected {expected_target!r}, got {actual_target!r}"

    expected_audit = expected.get("audit_actions")
    if expected_audit is not None and audit_actions != list(expected_audit):
        return False, f"audit_actions expected {expected_audit}, got {audit_actions}"

    expected_delegation_count = expected.get("delegation_count")
    if expected_delegation_count is not None and report.total_delegations != int(
        expected_delegation_count
    ):
        return (
            False,
            f"delegation_count expected {expected_delegation_count}, got {report.total_delegations}",
        )

    expected_escalation_count = expected.get("escalation_count")
    if expected_escalation_count is not None and report.total_escalations != int(
        expected_escalation_count
    ):
        return (
            False,
            f"escalation_count expected {expected_escalation_count}, got {report.total_escalations}",
        )

    expected_triggers = expected.get("triggers_received")
    if expected_triggers is not None and report.total_triggers != int(expected_triggers):
        return (
            False,
            f"triggers_received expected {expected_triggers}, got {report.total_triggers}",
        )

    return True, None


def _resolve_canned_responses(case: EvalCase) -> list[str]:
    """Stub-harness hook (Task 14). Supervisor doesn't consume an
    LLM in v0.1, so every shipped responses.json is empty."""
    case_dir = _STUB_RESPONSES_ROOT / case.case_id
    responses_file = case_dir / "responses.json"
    if responses_file.is_file():
        raw = json.loads(responses_file.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(f"stub_responses/{case.case_id}/responses.json must be a JSON list")
        return [str(r) for r in raw]
    return []


_ = _resolve_canned_responses


__all__ = ["SupervisorEvalRunner"]
