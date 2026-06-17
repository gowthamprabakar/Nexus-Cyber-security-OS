"""Compliance Agent driver — wires charter + CIS loader + 2 correlators + aggregator + scorer + summarizer.

Task 11 of the D.9 v0.1 plan. Mirrors D.8 Threat Intel's
:mod:`threat_intel.agent` shape with the D.9-specific 7-stage layout
(adds an AGGREGATE stage between CORRELATE and SCORE).

Seven-stage pipeline (per the NLAH README):

  1. INGEST     — load bundled CIS YAML via ``ctx.call_tool``.
  2. ENRICH     — build the control index (Tasks 6/7 shared
                  helper). Optional SemanticStore writes for the
                  framework + control entities (single-tenant
                  ``semantic_store=None`` opt-in default).
  3. CORRELATE  — 2 correlators concurrent via ``asyncio.TaskGroup``
                  (cloud_posture + data_security).
  4. AGGREGATE  — per-control PASS/FAIL roll-up (Task 8).
  5. SCORE      — canonical severity re-stamp (Task 9).
  6. SUMMARIZE  — deterministic markdown (Task 10, with CIS
                  Benchmarks® attribution footer).
  7. HANDOFF    — write findings.json + report.md to the charter
                  workspace; the charter-emitted audit chain hash-
                  chains the run.

**Single-tenant SemanticStore opt-in default.** The runtime
charter's multi-tenant production blocks on the future SET LOCAL
``$1`` tenant-RLS substrate-fix plan; in v0.1 the agent driver
guards SemanticStore writes behind ``semantic_store=None`` so the
agent's filesystem-only output path (findings.json + report.md) is
fully exercised even without a substrate.

**Q6 reminder.** No PII; no verbatim CIS Securesuite text. The
agent operates on bundled paraphrased control metadata + sibling-
agent OCSF structured fields only.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from charter.memory import SemanticStore
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from compliance import __version__ as agent_version
from compliance.aggregator import aggregate_controls
from compliance.correlators.cloud_posture_correlator import correlate_cloud_posture
from compliance.correlators.control_index import (
    ControlIndex,
    build_control_by_id,
    build_control_index,
)
from compliance.correlators.data_security_correlator import correlate_data_security
from compliance.entities import ControlEntity, FrameworkEntity
from compliance.kg_writer import KnowledgeGraphWriter
from compliance.schemas import (
    ComplianceFinding,
    ComplianceFramework,
    FindingsReport,
)
from compliance.scorer import score_findings
from compliance.summarizer import render_summary
from compliance.tools.cis_aws_benchmark import (
    CisControl,
    default_cis_aws_v3_path,
    read_cis_aws_benchmark,
)

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to the D.9 agent.

    Only the bundled CIS YAML reader is charter-registered. The two
    correlators (which read sibling workspaces) are called directly
    from the driver — they're pure I/O against operator-pinned paths
    and don't consume charter cloud-call budget (filesystem-only in
    v0.1).
    """
    reg = ToolRegistry()
    reg.register("read_cis_aws_benchmark", read_cis_aws_benchmark, version="0.1.0", cloud_calls=0)
    return reg


def _envelope(
    contract: ExecutionContract,
    *,
    correlation_id: str,
    model_pin: str,
) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id=contract.customer_id,
        agent_id="compliance",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # plumbed; not called in v0.1
    cloud_posture_workspace: Path | str | None = None,
    data_security_workspace: Path | str | None = None,
    semantic_store: SemanticStore | None = None,
) -> FindingsReport:
    """Run the Compliance Agent end-to-end under the runtime charter.

    Args:
        contract: The signed ``ExecutionContract``.
        llm_provider: Reserved for future LLM-driven flows; not
            called in v0.1.
        cloud_posture_workspace: Optional path to an F.3 Cloud
            Posture workspace (with ``findings.json``). Skipped if
            None.
        data_security_workspace: Optional path to a D.5 Data
            Security workspace. Skipped if None.
        semantic_store: Optional SemanticStore for KG writes
            (single-tenant v0.1; multi-tenant production blocks on
            the future SET LOCAL tenant-RLS substrate-fix plan).

    Returns:
        The ``FindingsReport``. Side effects: writes
        ``findings.json`` and ``report.md`` to the charter
        workspace; emits a hash-chained audit log at
        ``audit.jsonl``.
    """
    del llm_provider  # reserved for future iterations

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)

        # Stage 1: INGEST — load bundled CIS YAML via the charter.
        controls = await ctx.call_tool("read_cis_aws_benchmark", path=default_cis_aws_v3_path())
        controls_tuple: tuple[CisControl, ...] = tuple(controls)

        # Stage 2: ENRICH — build the cross-correlator control index;
        # optionally persist framework + control entities to the KG.
        control_index = build_control_index(controls_tuple)
        # A-3: control-by-id catalog for native-CIS attribution (Prowler's own
        # evidence.cis_controls on cloud-posture findings).
        controls_by_id = build_control_by_id(controls_tuple)
        if semantic_store is not None:
            await _persist_to_semantic_store(
                semantic_store=semantic_store,
                customer_id=contract.customer_id,
                controls=controls_tuple,
            )

        # Stage 3: CORRELATE — two correlators concurrent.
        correlated_at = datetime.now(UTC)
        cp_findings, ds_findings = await _correlate(
            cloud_posture_workspace=_as_path(cloud_posture_workspace),
            data_security_workspace=_as_path(data_security_workspace),
            control_index=control_index,
            controls_by_id=controls_by_id,
            correlated_at=correlated_at,
            envelope=envelope,
        )

        merged: list[ComplianceFinding] = []
        merged.extend(cp_findings)
        merged.extend(ds_findings)

        # Stage 4: AGGREGATE — per-control PASS/FAIL roll-up.
        aggregated = aggregate_controls(merged, envelope=envelope, aggregated_at=correlated_at)

        # Stage 5: SCORE — canonical severity re-stamp.
        scored = score_findings(aggregated)

        # Stages 6 + 7: SUMMARIZE + HANDOFF.
        report = FindingsReport(
            agent="compliance",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
        )
        # F.3's FindingsReport.add_finding is typed against
        # CloudPostureFinding; D.9 wraps the same OCSF dict in
        # ComplianceFinding (which validates the D.9 regex). Append
        # the raw payload dict directly so the FindingsReport pydantic
        # serialisation stays clean.
        for f in scored:
            report.findings.append(f.to_dict())

        ctx.write_output(
            "findings.json",
            report.model_dump_json(indent=2).encode("utf-8"),
        )
        ctx.write_output(
            "report.md",
            render_summary(report).encode("utf-8"),
        )

        ctx.assert_complete()

    return report


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------


async def _persist_to_semantic_store(
    *,
    semantic_store: SemanticStore,
    customer_id: str,
    controls: Sequence[CisControl],
) -> None:
    """Stage 2 KG persistence (optional v0.1).

    Persists one ``FrameworkEntity`` per loaded framework + one
    ``ControlEntity`` per control. Failures bubble up to abort
    the run (no silent KG drift).
    """
    writer = KnowledgeGraphWriter(semantic_store, customer_id=customer_id)
    framework = FrameworkEntity(
        framework=ComplianceFramework.CIS_AWS_V3,
        version="3.0.0",
        name="CIS AWS Foundations Benchmark v3.0",
    )
    await writer.upsert_framework(framework)
    for control in controls:
        await writer.upsert_control(
            ControlEntity(
                framework=ComplianceFramework.CIS_AWS_V3,
                control_id=control.control_id,
                name=control.name,
                level=control.level,
                required=control.required,
                applicability=list(control.applicability),
                description=control.description,
                source_mappings=list(control.source_mappings),
            )
        )


async def _correlate(
    *,
    cloud_posture_workspace: Path | None,
    data_security_workspace: Path | None,
    control_index: ControlIndex,
    controls_by_id: Mapping[str, CisControl],
    correlated_at: datetime,
    envelope: NexusEnvelope,
) -> tuple[
    tuple[ComplianceFinding, ...],
    tuple[ComplianceFinding, ...],
]:
    """Stage 3 — two correlators concurrent via TaskGroup."""
    async with asyncio.TaskGroup() as tg:
        cp_task = tg.create_task(
            correlate_cloud_posture(
                cloud_posture_workspace=cloud_posture_workspace,
                control_index=control_index,
                controls_by_id=controls_by_id,
                correlated_at=correlated_at,
                envelope=envelope,
            )
        )
        ds_task = tg.create_task(
            correlate_data_security(
                data_security_workspace=data_security_workspace,
                control_index=control_index,
                correlated_at=correlated_at,
                envelope=envelope,
            )
        )

    return cp_task.result(), ds_task.result()


def _as_path(value: Path | str | None) -> Path | None:
    if value is None:
        return None
    return Path(value)


__all__ = ["build_registry", "run"]
