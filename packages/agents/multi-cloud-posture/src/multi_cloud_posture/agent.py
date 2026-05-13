"""Multi-Cloud Posture Agent driver — wires charter + 4 readers + 2 normalizers + summarizer.

Mirrors D.4's [`agent.py`](../../../network-threat/src/network_threat/agent.py)
shape (filesystem-only fan-out via TaskGroup) with the D.5-specific
five-stage pipeline. ADR-007 pattern check (D.5): the `agent.run`
signature converges across agents — `(contract, *, llm_provider, ...)`.
Confirmed for the eighth time.

Five-stage pipeline (per the NLAH README):

1. INGEST     — four feeds concurrent via `asyncio.TaskGroup`
2. NORMALIZE  — Azure + GCP raw records → OCSF 2003 (F.3 re-export)
3. SCORE      — deterministic severity per source (in the normalizers)
4. SUMMARIZE  — render markdown report with per-cloud + CRITICAL pinned
5. HANDOFF    — write findings.json + report.md; emit audit chain

Differences from D.4:

- **Four** ingest tools instead of three (two per cloud).
- **Two** normalizers (Azure + GCP), each lifting per-source records
  into the F.3 OCSF 2003 wire shape via `build_finding`.
- No detector layer — Azure/GCP findings are already analyst
  interpretations from upstream tooling; D.5 only normalises them.
- `customer_domain_allowlist` is plumbed into the GCP IAM reader for
  the external-user severity rule.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from multi_cloud_posture import __version__ as agent_version
from multi_cloud_posture.normalizers.azure import normalize_azure
from multi_cloud_posture.normalizers.gcp import normalize_gcp
from multi_cloud_posture.schemas import FindingsReport
from multi_cloud_posture.summarizer import render_summary
from multi_cloud_posture.tools.azure_activity import (
    AzureActivityRecord,
    read_azure_activity,
)
from multi_cloud_posture.tools.azure_defender import (
    AzureDefenderFinding,
    read_azure_findings,
)
from multi_cloud_posture.tools.gcp_iam import GcpIamFinding, read_gcp_iam_findings
from multi_cloud_posture.tools.gcp_scc import GcpSccFinding, read_gcp_findings

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent."""
    reg = ToolRegistry()
    reg.register("read_azure_findings", read_azure_findings, version="0.1.0", cloud_calls=0)
    reg.register("read_azure_activity", read_azure_activity, version="0.1.0", cloud_calls=0)
    reg.register("read_gcp_findings", read_gcp_findings, version="0.1.0", cloud_calls=0)
    reg.register("read_gcp_iam_findings", read_gcp_iam_findings, version="0.1.0", cloud_calls=0)
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
        agent_id="multi_cloud_posture",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # plumbed; not called in v0.1
    azure_findings_feed: Path | str | None = None,
    azure_activity_feed: Path | str | None = None,
    gcp_findings_feed: Path | str | None = None,
    gcp_iam_feed: Path | str | None = None,
    customer_domain_allowlist: tuple[str, ...] = (),
) -> FindingsReport:
    """Run the Multi-Cloud Posture Agent end-to-end under the runtime charter.

    Args:
        contract: The signed `ExecutionContract`.
        llm_provider: Reserved for future LLM-driven flows; not called in v0.1.
        azure_findings_feed: Optional Azure Defender for Cloud JSON path. Skipped if None.
        azure_activity_feed: Optional Azure Activity Log JSON path. Skipped if None.
        gcp_findings_feed: Optional GCP SCC findings JSON path. Skipped if None.
        gcp_iam_feed: Optional GCP Cloud Asset Inventory IAM JSON path. Skipped if None.
        customer_domain_allowlist: Internal-domain allowlist for the GCP IAM analyser.

    Returns:
        The `FindingsReport`. Side effects: writes `findings.json` and
        `report.md` to the charter workspace; emits a hash-chained audit
        log at `audit.jsonl`.
    """
    del llm_provider  # reserved for future iterations

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)

        # Stage 1: INGEST — four feeds concurrent via TaskGroup.
        (
            defender_records,
            activity_records,
            scc_records,
            iam_records,
        ) = await _ingest(
            ctx,
            azure_findings_feed=azure_findings_feed,
            azure_activity_feed=azure_activity_feed,
            gcp_findings_feed=gcp_findings_feed,
            gcp_iam_feed=gcp_iam_feed,
            customer_domain_allowlist=customer_domain_allowlist,
        )

        # Stage 2/3: NORMALIZE + SCORE.
        azure_findings = normalize_azure(
            defender=defender_records,
            activity=activity_records,
            envelope=envelope,
            scan_time=scan_started,
        )
        gcp_findings = normalize_gcp(
            scc=scc_records,
            iam=iam_records,
            envelope=envelope,
            scan_time=scan_started,
        )

        # Stage 4/5: SUMMARIZE + HANDOFF.
        report = FindingsReport(
            agent="multi_cloud_posture",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
        )
        for f in (*azure_findings, *gcp_findings):
            report.add_finding(f)

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


# ---------------------------- pipeline stages -----------------------------


async def _ingest(
    ctx: Charter,
    *,
    azure_findings_feed: Path | str | None,
    azure_activity_feed: Path | str | None,
    gcp_findings_feed: Path | str | None,
    gcp_iam_feed: Path | str | None,
    customer_domain_allowlist: tuple[str, ...],
) -> tuple[
    Sequence[AzureDefenderFinding],
    Sequence[AzureActivityRecord],
    Sequence[GcpSccFinding],
    Sequence[GcpIamFinding],
]:
    """Stage 1 — fan out the four feeds via TaskGroup. Skipped feeds → empty tuple."""
    async with asyncio.TaskGroup() as tg:
        defender_task = (
            tg.create_task(ctx.call_tool("read_azure_findings", path=Path(azure_findings_feed)))
            if azure_findings_feed
            else None
        )
        activity_task = (
            tg.create_task(ctx.call_tool("read_azure_activity", path=Path(azure_activity_feed)))
            if azure_activity_feed
            else None
        )
        scc_task = (
            tg.create_task(ctx.call_tool("read_gcp_findings", path=Path(gcp_findings_feed)))
            if gcp_findings_feed
            else None
        )
        iam_task = (
            tg.create_task(
                ctx.call_tool(
                    "read_gcp_iam_findings",
                    path=Path(gcp_iam_feed),
                    customer_domain_allowlist=customer_domain_allowlist,
                )
            )
            if gcp_iam_feed
            else None
        )

    defender: Sequence[AzureDefenderFinding] = defender_task.result() if defender_task else ()
    activity: Sequence[AzureActivityRecord] = activity_task.result() if activity_task else ()
    scc: Sequence[GcpSccFinding] = scc_task.result() if scc_task else ()
    iam: Sequence[GcpIamFinding] = iam_task.result() if iam_task else ()
    return defender, activity, scc, iam


__all__ = ["build_registry", "run"]
