"""Runtime Threat Agent driver — wires charter + tools + normalizer + summarizer.

Mirrors D.2's [`agent.py`](../../../packages/agents/identity/src/identity/agent.py)
shape. ADR-007 pattern check (D.3 risk-down): the agent.run signature
converges across agents — `(contract, *, llm_provider, ...)`. Confirmed
for the fourth time.

Differences from D.2:

- Three primary tools (Falco JSONL reader, Tracee JSONL reader, OSQuery
  subprocess) instead of three IAM-shaped tools.
- The three feeds are read concurrently via `asyncio.TaskGroup`. Any
  feed left unset (None) is simply skipped — the agent gracefully
  handles operators who only have one sensor wired up.
- `osquery_pack` is a path to a `.sql` file (one query per v0.1). Future
  Phase 1c work introduces multi-query packs.
- The agent imports both `charter.llm_adapter` (ADR-007 v1.1) and
  `charter.nlah_loader` (ADR-007 v1.2) directly via D.3's shim files;
  no per-agent re-exports.
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

from runtime_threat import __version__ as agent_version
from runtime_threat.normalizer import normalize_to_findings
from runtime_threat.schemas import FindingsReport
from runtime_threat.summarizer import render_summary
from runtime_threat.tools.falco import FalcoAlert, falco_alerts_read
from runtime_threat.tools.osquery import OsqueryResult, osquery_run
from runtime_threat.tools.tracee import TraceeAlert, tracee_alerts_read

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent."""
    reg = ToolRegistry()
    reg.register(
        "falco_alerts_read",
        falco_alerts_read,
        version="0.1.0",
        cloud_calls=0,  # filesystem read; no cloud-API budget impact
    )
    reg.register(
        "tracee_alerts_read",
        tracee_alerts_read,
        version="0.1.0",
        cloud_calls=0,
    )
    reg.register(
        "osquery_run",
        osquery_run,
        version="0.1.0",
        cloud_calls=0,  # local subprocess
    )
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
        agent_id="runtime_threat",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # plumbed; not called in v0.1
    falco_feed: Path | str | None = None,
    tracee_feed: Path | str | None = None,
    osquery_pack: Path | str | None = None,
    osquery_severity: int = 2,
    osquery_finding_context: str = "query_hit",
) -> FindingsReport:
    """Run the Runtime Threat Agent end-to-end under the runtime charter.

    Args:
        contract: The signed `ExecutionContract`.
        llm_provider: Reserved for future LLM-driven flows; not called in v0.1.
        falco_feed: Optional path to a Falco JSONL feed. When None, skipped.
        tracee_feed: Optional path to a Tracee JSONL feed. When None, skipped.
        osquery_pack: Optional path to a `.sql` file (one query per v0.1).
            When None, OSQuery is skipped.
        osquery_severity: Severity for OSQuery findings (0-3 scale, same as
            Tracee). Default 2 (medium).
        osquery_finding_context: Context slug for OSQuery findings' IDs.

    Returns:
        The `FindingsReport`. Side effects: writes `findings.json` and
        `summary.md` to the charter workspace; emits a hash-chained audit
        log at `audit.jsonl`.
    """
    del llm_provider  # reserved for future iterations

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(
            contract,
            correlation_id=correlation_id,
            model_pin=model_pin,
        )

        falco_alerts, tracee_alerts, osquery_results = await _fetch_feeds(
            ctx,
            falco_feed=falco_feed,
            tracee_feed=tracee_feed,
            osquery_pack=osquery_pack,
        )

        findings = await normalize_to_findings(
            falco_alerts,
            tracee_alerts,
            osquery_results,
            envelope=envelope,
            detected_at=scan_started,
            osquery_severity=osquery_severity,
            osquery_finding_context=osquery_finding_context,
        )

        report = FindingsReport(
            agent="runtime_threat",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
        )
        for f in findings:
            report.add_finding(f)

        ctx.write_output(
            "findings.json",
            report.model_dump_json(indent=2).encode("utf-8"),
        )
        ctx.write_output(
            "summary.md",
            render_summary(report).encode("utf-8"),
        )

        ctx.assert_complete()

    return report


async def _fetch_feeds(
    ctx: Charter,
    *,
    falco_feed: Path | str | None,
    tracee_feed: Path | str | None,
    osquery_pack: Path | str | None,
) -> tuple[
    Sequence[FalcoAlert],
    Sequence[TraceeAlert],
    Sequence[OsqueryResult],
]:
    """Read the three feeds concurrently. Skipped feeds return empty results."""
    osquery_sql = _read_osquery_pack(osquery_pack)

    async with asyncio.TaskGroup() as tg:
        falco_task = (
            tg.create_task(ctx.call_tool("falco_alerts_read", feed_path=falco_feed))
            if falco_feed
            else None
        )
        tracee_task = (
            tg.create_task(ctx.call_tool("tracee_alerts_read", feed_path=tracee_feed))
            if tracee_feed
            else None
        )
        osquery_task = (
            tg.create_task(ctx.call_tool("osquery_run", sql=osquery_sql)) if osquery_sql else None
        )

    falco_alerts: Sequence[FalcoAlert] = falco_task.result() if falco_task else ()
    tracee_alerts: Sequence[TraceeAlert] = tracee_task.result() if tracee_task else ()
    osquery_results: Sequence[OsqueryResult] = (osquery_task.result(),) if osquery_task else ()
    return falco_alerts, tracee_alerts, osquery_results


def _read_osquery_pack(pack: Path | str | None) -> str | None:
    """Read a single SQL query from a `.sql` file. v0.1 supports one query.

    Phase 1c will introduce JSON-formatted multi-query packs.
    """
    if pack is None:
        return None
    path = Path(pack)
    return path.read_text(encoding="utf-8").strip() or None


__all__ = ["build_registry", "run"]
