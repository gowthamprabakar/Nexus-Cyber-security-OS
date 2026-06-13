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
from multi_cloud_posture.tools.azure_discovery import (
    discover_locations,
    discover_subscription_id,
)
from multi_cloud_posture.tools.gcp_discovery import discover_project_id, discover_regions
from multi_cloud_posture.tools.gcp_iam import GcpIamFinding, read_gcp_iam_findings
from multi_cloud_posture.tools.gcp_scc import GcpSccFinding, read_gcp_findings

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent.

    Phase C SS4: the v0.2 live scope-discovery helpers are registered so they dispatch
    through the charter proxy (ADR-016) — budget/audit/permission bound — rather than
    being importable-but-ungoverned. They are scope discovery only (resolve the single
    subscription/project + its regions, Q6); ``run()`` does NOT route to them yet because
    the live Azure/GCP *findings* scanners that would consume the resolved scope are a v0.3
    deliverable (the offline flow scans feeds, not a live subscription). Registering now
    makes the governed dispatch path ready for those readers. cloud_calls=1 — each makes
    outbound cloud-API calls.
    """
    reg = ToolRegistry()
    reg.register("read_azure_findings", read_azure_findings, version="0.1.0", cloud_calls=0)
    reg.register("read_azure_activity", read_azure_activity, version="0.1.0", cloud_calls=0)
    reg.register("read_gcp_findings", read_gcp_findings, version="0.1.0", cloud_calls=0)
    reg.register("read_gcp_iam_findings", read_gcp_iam_findings, version="0.1.0", cloud_calls=0)
    # v0.2 live scope-discovery (register-only; run() routing awaits v0.3 scan readers).
    reg.register(
        "discover_subscription_id", discover_subscription_id, version="0.2.0", cloud_calls=1
    )
    reg.register("discover_locations", discover_locations, version="0.2.0", cloud_calls=1)
    reg.register("discover_project_id", discover_project_id, version="0.2.0", cloud_calls=1)
    reg.register("discover_regions", discover_regions, version="0.2.0", cloud_calls=1)
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
    azure_subscription_id: str | None = None,
    azure_regions: list[str] | None = None,
    gcp_project_id: str | None = None,
    gcp_regions: list[str] | None = None,
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
        azure_subscription_id: Single Azure subscription (Q6); discovered via
            `tools.azure_discovery` when None. Reserved — consumed when the live
            Azure readers land; the offline flow does not scan a subscription.
        azure_regions: Explicit Azure regions (precedence via
            `region_scope.resolve_scan_regions`); all discovered when None.
            Reserved — consumed by the live Azure readers.
        gcp_project_id: Single GCP project (Q6); discovered via
            `tools.gcp_discovery` when None. Reserved — consumed by the live GCP
            readers; the offline flow does not scan a project.
        gcp_regions: Explicit GCP regions (precedence via
            `region_scope.resolve_scan_regions`); all discovered when None.
            Reserved — consumed by the live GCP readers.

    Returns:
        The `FindingsReport`. Side effects: writes `findings.json` and
        `report.md` to the charter workspace; emits a hash-chained audit
        log at `audit.jsonl`.
    """
    del llm_provider  # reserved for future iterations
    del azure_subscription_id  # reserved for live Azure scanning (consumed later in M2/M4)
    del azure_regions  # reserved for live Azure scanning (precedence via region_scope)
    del gcp_project_id  # reserved for live GCP scanning (consumed later in M3/M4)
    del gcp_regions  # reserved for live GCP scanning (precedence via region_scope)

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
