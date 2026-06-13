"""Supervisor schemas — pydantic models for the 5-stage pipeline.

Per Q1 of the Supervisor v0.1 plan, the agent emits in 2 + 1
directions per heartbeat tick:

  1. F.6 audit chain — 4 additive audit-action vocabulary entries.
  2. ``supervisor_report.md`` workspace markdown.
  3. (Conditional) ``escalation_<run_id>.md`` — only when a
     delegation times out OR a routing rule matches an "escalate-
     only" terminal.

This module ships the internal pydantic types that flow through
the 5-stage pipeline:

  Stage 1 INGEST    -> IncomingTask (metadata-only envelope read
                       from events.> bus / CLI / scheduled queue)
  Stage 2 ROUTE     -> RoutingDecision (Match / NoMatch /
                       Ambiguous / Escalate variants)
  Stage 3 DISPATCH  -> DelegationContract + DelegationOutcome
                       (one pair per delegation; parallel under
                       Semaphore(5))
  Stage 4 AUDIT     -> (consumed via audit_emit.py — Task 9)
  Stage 5 HANDOFF   -> SupervisorReport (assembled run artefact)

**Read-only contract (WI-4) preserved in the schemas.** Every
field carries metadata only — no OCSF payload bodies are
materialised in any model. ``IncomingTask`` carries the envelope
routing-keys (target_agent / task_type / delta_type) but never
the OCSF event body.

**No LLM fields.** Q-ARCH-2 enforced structurally: nothing in
this module references LLM primitives. Routing is rule-based.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_MAX_AGENT_ID_LENGTH = 64
_MAX_TASK_DESC_LENGTH = 512
_MAX_REASON_LENGTH = 512
_MAX_DELEGATION_CONTRACT_ID_LENGTH = 128
_MAX_PERMITTED_TOOLS = 64
_MAX_PERMITTED_TOOL_NAME_LENGTH = 128

# v0.1 cap (per plan Q3): parallel dispatch concurrency limit.
MAX_PARALLEL_DISPATCH = 5


class TriggerSource(StrEnum):
    """Where an IncomingTask arrived from (Stage 1 INGEST)."""

    EVENTS_BUS = "events_bus"  # F.7 events.> subscription
    OPERATOR_CLI = "operator_cli"  # `supervisor schedule` or direct CLI
    SCHEDULED_QUEUE = "scheduled_queue"  # file-backed queue
    CONTINUOUS = "continuous"  # per-tenant continuous scheduler (Phase C; A.0-orchestrated)


class IncomingTask(BaseModel):
    """Envelope metadata for a task arriving at the supervisor.

    **Read-only contract (WI-4):** carries ONLY routing-relevant
    metadata. No OCSF payload body — the supervisor never opens
    findings / remediation diffs / classifier labels at deeper
    than envelope level.
    """

    model_config = ConfigDict(frozen=True)

    task_id: str = Field(min_length=1, max_length=128)
    customer_id: str = Field(min_length=1, max_length=128)
    trigger_source: TriggerSource
    target_agent: str | None = Field(default=None, max_length=_MAX_AGENT_ID_LENGTH)
    task_type: str | None = Field(default=None, max_length=64)
    delta_type: str | None = Field(default=None, max_length=64)
    description: str = Field(default="", max_length=_MAX_TASK_DESC_LENGTH)
    priority: int = Field(default=0, ge=0, le=10)
    received_at: datetime


class RoutingRule(BaseModel):
    """One declarative routing rule from ``routing/agents.md``.

    A rule matches an IncomingTask when EITHER:

    - ``target_agent_declared`` matches the task's ``target_agent``
      field (explicit routing), OR
    - ``task_type_pattern`` matches the task's ``task_type``
      (pattern-match fallback), OR
    - ``delta_type_pattern`` matches the task's ``delta_type``
      (delta-match fallback).

    ``priority`` breaks ties when multiple rules match the same
    task; higher wins. Equal priority + multiple matches ->
    ``Ambiguous`` decision (per Q2).

    ``permitted_tools`` is the per-rule allowlist that lands in
    the delegation contract — keeps Supervisor decoupled from A.4
    introspection (Q-ARCH-2).
    """

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(min_length=1, max_length=128)
    target_agent: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    target_agent_declared: str | None = Field(default=None, max_length=_MAX_AGENT_ID_LENGTH)
    task_type_pattern: str | None = Field(default=None, max_length=64)
    delta_type_pattern: str | None = Field(default=None, max_length=64)
    permitted_tools: tuple[str, ...] = Field(default_factory=tuple, max_length=_MAX_PERMITTED_TOOLS)
    priority: int = Field(default=0, ge=0, le=100)

    @model_validator(mode="after")
    def _at_least_one_match_predicate(self) -> RoutingRule:
        if (
            self.target_agent_declared is None
            and self.task_type_pattern is None
            and self.delta_type_pattern is None
        ):
            raise ValueError(
                f"RoutingRule {self.rule_id!r} must specify at least one match predicate "
                "(target_agent_declared / task_type_pattern / delta_type_pattern)"
            )
        return self

    @model_validator(mode="after")
    def _bound_each_permitted_tool(self) -> RoutingRule:
        for tool in self.permitted_tools:
            if not tool:
                raise ValueError("permitted_tools entries must be non-empty")
            if len(tool) > _MAX_PERMITTED_TOOL_NAME_LENGTH:
                raise ValueError(
                    f"permitted tool name exceeds {_MAX_PERMITTED_TOOL_NAME_LENGTH} chars"
                )
        return self


# RoutingDecision is a tagged union via a discriminator on `kind`.


class RoutingMatch(BaseModel):
    """The task matched exactly one rule -> dispatch."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["match"] = "match"
    rule_id: str = Field(min_length=1, max_length=128)
    target_agent: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    permitted_tools: tuple[str, ...] = Field(default_factory=tuple, max_length=_MAX_PERMITTED_TOOLS)


class RoutingNoMatch(BaseModel):
    """No rule matched the task -> escalate."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["no_match"] = "no_match"
    reason: str = Field(min_length=1, max_length=_MAX_REASON_LENGTH)


class RoutingAmbiguous(BaseModel):
    """Multiple rules at the same priority matched -> escalate."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["ambiguous"] = "ambiguous"
    candidate_rule_ids: tuple[str, ...] = Field(min_length=2)
    reason: str = Field(min_length=1, max_length=_MAX_REASON_LENGTH)


class RoutingEscalate(BaseModel):
    """A rule matched with an explicit ``escalate`` terminal."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["escalate"] = "escalate"
    rule_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=_MAX_REASON_LENGTH)


RoutingDecision = Annotated[
    RoutingMatch | RoutingNoMatch | RoutingAmbiguous | RoutingEscalate,
    Field(discriminator="kind"),
]


class DelegationContract(BaseModel):
    """The bounded contract Supervisor passes to a specialist.

    Mirrors a subset of ``charter.contract.ExecutionContract`` —
    the fields Supervisor populates per delegation. The specialist's
    own machinery enforces the budget; Supervisor records the
    outcome.
    """

    model_config = ConfigDict(frozen=True)

    delegation_id: str = Field(min_length=1, max_length=_MAX_DELEGATION_CONTRACT_ID_LENGTH)
    customer_id: str = Field(min_length=1, max_length=128)
    target_agent: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    task_id: str = Field(min_length=1, max_length=128)
    task_description: str = Field(default="", max_length=_MAX_TASK_DESC_LENGTH)
    permitted_tools: tuple[str, ...] = Field(default_factory=tuple, max_length=_MAX_PERMITTED_TOOLS)
    budget_wall_clock_sec: float = Field(gt=0.0, le=3600.0)
    budget_max_tool_calls: int = Field(ge=1, le=10_000)
    created_at: datetime
    trigger_source: str | None = None
    """How the run was triggered. Values: 'events_bus', 'operator_cli',
    'scheduled_queue', or None (legacy contracts predating G2 Task 3).
    Populated from IncomingTask.trigger_source.value.
    """


class DelegationStatus(StrEnum):
    OK = "ok"
    TIMEOUT_PARTIAL = "timeout_partial"
    ERROR = "error"


class DelegationOutcome(BaseModel):
    """Result of one delegation invocation.

    Per Q4: on budget exceeded, Supervisor receives a partial
    outcome (status=``timeout_partial``). On per-delegation raise,
    status=``error``. On clean completion, status=``ok``.
    """

    model_config = ConfigDict(frozen=True)

    delegation_id: str = Field(min_length=1, max_length=_MAX_DELEGATION_CONTRACT_ID_LENGTH)
    target_agent: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    status: DelegationStatus
    duration_sec: float = Field(ge=0.0)
    reason: str | None = Field(default=None, max_length=_MAX_REASON_LENGTH)
    completed_at: datetime

    @model_validator(mode="after")
    def _reason_required_when_not_ok(self) -> DelegationOutcome:
        if self.status != DelegationStatus.OK and not self.reason:
            raise ValueError(f"reason required when DelegationOutcome.status={self.status.value!r}")
        return self


class EscalationNotice(BaseModel):
    """One escalation event surfaced to the operator (Q4).

    Triggered by (a) a ``RoutingNoMatch`` / ``RoutingAmbiguous`` /
    ``RoutingEscalate`` terminal at routing time, OR (b) a
    delegation that returned status=``timeout_partial`` or
    ``error``. Supervisor writes a markdown notification artefact
    keyed by ``escalation_id`` + emits a
    ``supervisor.escalation.raised`` audit entry.
    """

    model_config = ConfigDict(frozen=True)

    escalation_id: str = Field(min_length=1, max_length=128)
    customer_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=_MAX_REASON_LENGTH)
    raised_at: datetime


class SupervisorReport(BaseModel):
    """Top-level run artefact emitted by Stage 5 HANDOFF.

    Serialised by Stage 5 to ``supervisor_report.md`` (one per
    heartbeat tick). Per Q-ARCH-2: no fabric publish.
    """

    model_config = ConfigDict(frozen=True)

    customer_id: str = Field(min_length=1, max_length=128)
    tick_id: str = Field(min_length=1, max_length=128)
    tick_started_at: datetime
    tick_completed_at: datetime
    triggers_received: tuple[IncomingTask, ...] = Field(default_factory=tuple)
    routing_decisions: tuple[RoutingDecision, ...] = Field(default_factory=tuple)
    delegations: tuple[DelegationOutcome, ...] = Field(default_factory=tuple)
    escalations: tuple[EscalationNotice, ...] = Field(default_factory=tuple)
    schema_version: Literal["supervisor.v0.1"] = "supervisor.v0.1"

    @property
    def total_triggers(self) -> int:
        return len(self.triggers_received)

    @property
    def total_delegations(self) -> int:
        return len(self.delegations)

    @property
    def total_escalations(self) -> int:
        return len(self.escalations)

    @property
    def successful_delegations(self) -> int:
        return sum(1 for d in self.delegations if d.status == DelegationStatus.OK)


__all__ = [
    "MAX_PARALLEL_DISPATCH",
    "DelegationContract",
    "DelegationOutcome",
    "DelegationStatus",
    "EscalationNotice",
    "IncomingTask",
    "RoutingAmbiguous",
    "RoutingDecision",
    "RoutingEscalate",
    "RoutingMatch",
    "RoutingNoMatch",
    "RoutingRule",
    "SupervisorReport",
    "TriggerSource",
]
