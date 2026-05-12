"""Investigation Agent driver — 6-stage Orchestrator-Workers pipeline (D.7 Task 12).

Implements the 6-stage forensic pipeline per the agent spec + the D.7
plan:

    SCOPE → SPAWN → SYNTHESIZE → VALIDATE → PLAN → HANDOFF

Each stage is a small async function; the orchestrator runs Stage 2
sub-investigations concurrently under `SubAgentOrchestrator.spawn_batch`
(allowlist-enforced, depth ≤ 3, parallel ≤ 5).

The driver writes 4 artifacts to the charter workspace:

  incident_report.json    — OCSF 2005 envelope (wire shape)
  timeline.json           — sorted Timeline
  hypotheses.md           — operator-readable hypothesis tracking
  containment_plan.yaml   — Stage-5 output

ADR-007 conformance:

- v1.1 — LLM use through `charter.llm_adapter` only (the synthesizer).
- v1.2 — NLAH bundle + 25-LOC shim (loaded by the synthesizer).
- v1.3 — D.7 is **NOT** in the always-on class. Extended budget caps
  apply but still raise `BudgetExhausted` on overrun.
- v1.4 (candidate) — sub-agent spawning primitive lives in
  `investigation.orchestrator` for v0.1; hoists to `charter.subagent`
  on the third duplicate.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from audit.schemas import AuditEvent
from audit.store import AuditStore
from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from charter.memory import SemanticStore
from ulid import ULID

from investigation.orchestrator import SubAgentOrchestrator, SubResult
from investigation.schemas import (
    Hypothesis,
    IncidentReport,
    IocItem,
    MitreTechnique,
    Timeline,
    TimelineEvent,
)
from investigation.synthesizer import synthesize_hypotheses
from investigation.timeline import reconstruct_timeline
from investigation.tools.audit_trail import audit_trail_query
from investigation.tools.ioc_extractor import extract_iocs
from investigation.tools.memory_walk import memory_neighbors_walk
from investigation.tools.mitre_mapper import map_to_mitre
from investigation.tools.related_findings import RelatedFinding, find_related_findings

_LOG = logging.getLogger(__name__)


# ---------------------------- internal types ----------------------------


@dataclass(slots=True)
class _InvestigationScope:
    """Stage 1 output — bounds the entire investigation."""

    tenant_id: str
    correlation_id: str
    since: datetime | None
    until: datetime | None
    sibling_workspaces: tuple[Path, ...]


@dataclass(slots=True)
class _SubInvestigationOutputs:
    """Stage 2 merged outputs from the 4 sub-investigations."""

    audit_events: tuple[AuditEvent, ...] = ()
    related_findings: tuple[RelatedFinding, ...] = ()
    iocs: tuple[IocItem, ...] = ()
    mitre_techniques: tuple[MitreTechnique, ...] = ()
    extra_timeline_events: tuple[TimelineEvent, ...] = field(default_factory=tuple)


# ---------------------------- public driver -----------------------------


def build_registry() -> ToolRegistry:
    """Compose the tool universe D.7 sees."""
    reg = ToolRegistry()
    reg.register("audit_trail_query", audit_trail_query, version="0.1.0", cloud_calls=0)
    reg.register("memory_neighbors_walk", memory_neighbors_walk, version="0.1.0", cloud_calls=0)
    reg.register("find_related_findings", find_related_findings, version="0.1.0", cloud_calls=0)
    reg.register("extract_iocs", extract_iocs, version="0.1.0", cloud_calls=0)
    reg.register("map_to_mitre", map_to_mitre, version="0.1.0", cloud_calls=0)
    return reg


async def run(
    contract: ExecutionContract,
    *,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
    llm_provider: LLMProvider | None = None,
    sibling_workspaces: Sequence[Path] = (),
    since: datetime | None = None,
    until: datetime | None = None,
) -> IncidentReport:
    """Run the 6-stage Orchestrator-Workers pipeline end-to-end.

    Returns an `IncidentReport` and writes the 4 artifacts to the
    charter workspace.
    """
    registry = build_registry()

    with Charter(contract, tools=registry) as ctx:
        # Stage 1 — SCOPE
        scope = _stage_scope(
            contract,
            sibling_workspaces=tuple(sibling_workspaces),
            since=since,
            until=until,
        )

        # Stage 2 — SPAWN (4 parallel sub-investigations)
        sub_outputs = await _stage_spawn(
            scope=scope,
            audit_store=audit_store,
            semantic_store=semantic_store,
        )

        # Stage 3 — SYNTHESIZE (timeline + hypotheses)
        timeline = reconstruct_timeline(
            audit_events=sub_outputs.audit_events,
            related_findings=sub_outputs.related_findings,
            extra_events=sub_outputs.extra_timeline_events,
        )
        hypotheses = await synthesize_hypotheses(
            llm_provider=llm_provider,
            audit_events=sub_outputs.audit_events,
            related_findings=sub_outputs.related_findings,
            timeline=timeline,
        )

        # Stage 4 — VALIDATE (drop unresolved-evidence hypotheses)
        validated = _stage_validate(
            hypotheses=hypotheses,
            audit_events=sub_outputs.audit_events,
            related_findings=sub_outputs.related_findings,
        )

        # Stage 5 — PLAN (containment templates per finding class_uid)
        containment_plan = _stage_plan(
            related_findings=sub_outputs.related_findings,
        )

        # Stage 6 — HANDOFF
        report = _build_incident_report(
            scope=scope,
            timeline=timeline,
            hypotheses=validated,
            iocs=sub_outputs.iocs,
            mitre_techniques=sub_outputs.mitre_techniques,
            containment_plan=containment_plan,
        )
        _write_artifacts(
            ctx=ctx,
            report=report,
            timeline=timeline,
            hypotheses=validated,
            containment_plan=containment_plan,
            llm_used=llm_provider is not None,
        )

    return report


# ---------------------------- Stage 1: SCOPE ---------------------------


def _stage_scope(
    contract: ExecutionContract,
    *,
    sibling_workspaces: tuple[Path, ...],
    since: datetime | None,
    until: datetime | None,
) -> _InvestigationScope:
    """Derive investigation bounds from the contract."""
    return _InvestigationScope(
        tenant_id=contract.customer_id,
        correlation_id=contract.delegation_id,
        since=since,
        until=until,
        sibling_workspaces=sibling_workspaces,
    )


# ---------------------------- Stage 2: SPAWN ---------------------------


async def _stage_spawn(
    *,
    scope: _InvestigationScope,
    audit_store: AuditStore,
    semantic_store: SemanticStore,
) -> _SubInvestigationOutputs:
    """Run the 4 sub-investigations in parallel under the orchestrator."""
    orch = SubAgentOrchestrator(parent_agent_id="investigation")

    async def _worker(scope_dict: dict[str, Any]) -> dict[str, Any]:
        kind = str(scope_dict["kind"])
        if kind == "timeline":
            events = await audit_trail_query(
                audit_store=audit_store,
                tenant_id=scope.tenant_id,
                since=scope.since,
                until=scope.until,
            )
            return {"audit_events": tuple(events)}
        if kind == "ioc_pivot":
            # IOC extraction needs evidence — runs on collected findings.
            findings = await find_related_findings(sibling_workspaces=scope.sibling_workspaces)
            iocs = extract_iocs([rf.payload for rf in findings])
            return {"related_findings": tuple(findings), "iocs": tuple(iocs)}
        if kind == "asset_enum":
            # v0.1 — semantic graph walk is a no-op when no seed entity
            # was named. The driver passes seeds via scope_dict in the
            # future (Phase 1c); v0.1 returns an empty enumeration.
            seed = scope_dict.get("seed_entity_id")
            if not seed:
                return {"entities": ()}
            entities = await memory_neighbors_walk(
                semantic_store=semantic_store,
                tenant_id=scope.tenant_id,
                entity_id=str(seed),
                depth=int(scope_dict.get("depth", 2)),
            )
            return {"entities": tuple(entities)}
        if kind == "attribution":
            findings = await find_related_findings(sibling_workspaces=scope.sibling_workspaces)
            techniques = map_to_mitre([rf.payload for rf in findings])
            return {"mitre_techniques": tuple(techniques)}
        return {}

    scopes = [
        {"kind": "timeline"},
        {"kind": "ioc_pivot"},
        {"kind": "asset_enum"},
        {"kind": "attribution"},
    ]
    results = await orch.spawn_batch(parent_depth=0, scopes=scopes, worker=_worker)
    return _merge_sub_outputs(results)


def _merge_sub_outputs(results: tuple[SubResult, ...]) -> _SubInvestigationOutputs:
    """Collapse 4 sub-investigations into a single outputs struct."""
    audit_events: tuple[AuditEvent, ...] = ()
    related_findings: tuple[RelatedFinding, ...] = ()
    iocs: tuple[IocItem, ...] = ()
    mitre_techniques: tuple[MitreTechnique, ...] = ()

    for result in results:
        payload = result.result if isinstance(result.result, dict) else {}
        if result.kind == "timeline":
            audit_events = payload.get("audit_events", ())
        elif result.kind == "ioc_pivot":
            # ioc_pivot also surfaces the sibling findings (it had to
            # read them to extract IOCs).
            related_findings = payload.get("related_findings", related_findings)
            iocs = payload.get("iocs", ())
        elif result.kind == "attribution":
            mitre_techniques = payload.get("mitre_techniques", ())

    return _SubInvestigationOutputs(
        audit_events=audit_events,
        related_findings=related_findings,
        iocs=iocs,
        mitre_techniques=mitre_techniques,
    )


# ---------------------------- Stage 4: VALIDATE ------------------------


def _stage_validate(
    *,
    hypotheses: tuple[Hypothesis, ...],
    audit_events: tuple[AuditEvent, ...],
    related_findings: tuple[RelatedFinding, ...],
) -> tuple[Hypothesis, ...]:
    """Re-validate hypothesis evidence_refs against the collected corpus.

    The synthesizer already validates LLM-generated hypotheses against
    the same corpus; this stage is a defence-in-depth re-check (and
    catches the case where fallback hypotheses might reference findings
    that got pruned by Stage 2 — currently impossible by construction,
    but Phase 1c may add finding-level filtering).
    """
    valid_refs: set[str] = set()
    for ae in audit_events:
        valid_refs.add(f"audit_event:{ae.entry_hash[:16]}")
    for rf in related_findings:
        uid = str((rf.payload.get("finding_info") or {}).get("uid", ""))
        if uid:
            valid_refs.add(f"finding:{uid}")

    out: list[Hypothesis] = []
    for h in hypotheses:
        if all(ref in valid_refs for ref in h.evidence_refs):
            out.append(h)
        else:
            _LOG.warning(
                "validate stage dropping hypothesis %s — unresolved evidence refs",
                h.hypothesis_id,
            )
    return tuple(out)


# ---------------------------- Stage 5: PLAN ---------------------------


_CONTAINMENT_TEMPLATES: dict[int, str] = {
    2002: "Apply patch per the CVE's vendor advisory.",
    2003: "Re-run remediation playbook for the affected resource.",
    2004: "Quarantine the affected resource pending operator review.",
    2005: "Escalate to incident-response team (this finding is itself an incident).",
    6003: "Review the API audit record for unauthorized actions.",
}


def _stage_plan(*, related_findings: tuple[RelatedFinding, ...]) -> dict[str, Any]:
    """Emit a containment plan keyed by finding class_uid."""
    steps: list[dict[str, Any]] = []
    for rf in related_findings:
        uid = str((rf.payload.get("finding_info") or {}).get("uid", ""))
        if not uid:
            continue
        template = _CONTAINMENT_TEMPLATES.get(
            rf.class_uid, "Investigate manually — no automatic containment template."
        )
        steps.append(
            {
                "finding_uid": uid,
                "class_uid": rf.class_uid,
                "source_agent": rf.source_agent,
                "action": template,
            }
        )

    return {
        "steps": steps,
        "eradication": [s["action"] for s in steps],
        "recovery_validation": [
            "Re-run sibling agents over the affected scope; confirm zero new findings.",
        ],
    }


# ---------------------------- Stage 6: HANDOFF -------------------------


def _build_incident_report(
    *,
    scope: _InvestigationScope,
    timeline: Timeline,
    hypotheses: tuple[Hypothesis, ...],
    iocs: tuple[IocItem, ...],
    mitre_techniques: tuple[MitreTechnique, ...],
    containment_plan: dict[str, Any],
) -> IncidentReport:
    # Aggregate hypothesis confidences into a single report confidence
    # (mean — naive but defensible for v0.1; Phase 1c uses Bayesian).
    if hypotheses:
        report_confidence = sum(h.confidence for h in hypotheses) / len(hypotheses)
    else:
        report_confidence = 0.0

    return IncidentReport(
        incident_id=str(ULID()),
        tenant_id=scope.tenant_id,
        correlation_id=scope.correlation_id,
        timeline=timeline,
        hypotheses=hypotheses,
        iocs=iocs,
        mitre_techniques=mitre_techniques,
        containment_summary=_summarise_plan(containment_plan),
        confidence=report_confidence,
        emitted_at=datetime.now(UTC),
    )


def _summarise_plan(plan: dict[str, Any]) -> str:
    steps = plan.get("steps") or []
    if not steps:
        return "No containment steps — no findings ingested."
    lines = [f"{len(steps)} containment step(s):"]
    for i, step in enumerate(steps, 1):
        lines.append(f"  {i}. (finding={step['finding_uid']}) {step['action']}")
    return "\n".join(lines)


def _write_artifacts(
    *,
    ctx: Charter,
    report: IncidentReport,
    timeline: Timeline,
    hypotheses: tuple[Hypothesis, ...],
    containment_plan: dict[str, Any],
    llm_used: bool,
) -> None:
    # incident_report.json — OCSF wire shape
    ctx.write_output(
        "incident_report.json",
        json.dumps(report.to_ocsf(), indent=2, default=_json_default).encode("utf-8"),
    )

    # timeline.json — the Timeline pydantic model dumped
    ctx.write_output(
        "timeline.json",
        timeline.model_dump_json(indent=2).encode("utf-8"),
    )

    # hypotheses.md — operator-readable
    ctx.write_output(
        "hypotheses.md", _render_hypotheses_markdown(hypotheses, llm_used=llm_used).encode("utf-8")
    )

    # containment_plan.yaml
    ctx.write_output(
        "containment_plan.yaml",
        yaml.safe_dump(containment_plan, sort_keys=False).encode("utf-8"),
    )


def _render_hypotheses_markdown(hypotheses: tuple[Hypothesis, ...], *, llm_used: bool) -> str:
    lines: list[str] = ["# Hypotheses"]
    lines.append("")
    if not llm_used:
        lines.append(
            "> Note: this report was generated without LLM synthesis. "
            "Hypotheses are enumerated from collected findings; an operator "
            "should re-run with LLM enabled for richer correlation."
        )
        lines.append("")
    if not hypotheses:
        lines.append("_No hypotheses generated — no findings ingested._")
        return "\n".join(lines) + "\n"
    for h in hypotheses:
        lines.append(f"## {h.hypothesis_id}  (confidence: {h.confidence:.2f})")
        lines.append("")
        lines.append(h.statement)
        lines.append("")
        lines.append("**Evidence:**")
        for ref in h.evidence_refs:
            lines.append(f"- `{ref}`")
        lines.append("")
    return "\n".join(lines)


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Cannot serialise {type(value).__name__} to JSON")


__all__ = ["build_registry", "run"]
