"""Network Threat Agent driver — wires charter + 3 feeds + 3 detectors + enrichment + summarizer.

Mirrors D.3's [`agent.py`](../../../runtime-threat/src/runtime_threat/agent.py)
shape (three-feed TaskGroup ingest) with the D.4-specific six-stage
pipeline. ADR-007 pattern check (D.4): the `agent.run` signature
converges across agents — `(contract, *, llm_provider, ...)`. Confirmed
for the seventh time.

Six-stage pipeline (per the NLAH README):

1. INGEST           — three feeds concurrent via `asyncio.TaskGroup`
2. PATTERN_DETECT   — three pure-function detectors over parsed observations
3. ENRICH           — bundled-intel annotation; severity uplift on match
4. SCORE            — composite per-detection score (deterministic; no LLM)
5. SUMMARIZE        — render markdown report with beacons + DGA pinned
6. HANDOFF          — write findings.json + report.md; emit audit event

Differences from D.3:

- Ingest tools are **filesystem-only** (Suricata eve.json, VPC Flow
  Logs file, DNS log file). v0.1 has no subprocess invocations.
- Detectors live in a separate `detectors/` package; called directly
  from the driver (not via `ctx.call_tool` — they're pure functions
  with no charter-budget impact).
- A finding-builder helper folds each `Detection` into an OCSF 2004
  `NetworkFinding` here in the driver (no per-detector OCSF logic).
- A driver-side **dedup pass** applies `Detection.dedup_key()` from
  schemas.py per Q6 of the plan.
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

from network_threat import __version__ as agent_version
from network_threat.detectors.beacon import detect_beacon
from network_threat.detectors.dga import detect_dga
from network_threat.detectors.port_scan import detect_port_scan
from network_threat.enrichment import enrich_with_intel
from network_threat.schemas import (
    AffectedNetwork,
    Detection,
    DnsEvent,
    FindingsReport,
    FindingType,
    FlowRecord,
    NetworkFinding,
    Severity,
    SuricataAlert,
    SuricataAlertSeverity,
    build_finding,
    finding_type_token,
    short_ip_token,
)
from network_threat.summarizer import render_summary
from network_threat.tools.dns_log_reader import read_dns_logs
from network_threat.tools.suricata_reader import read_suricata_alerts
from network_threat.tools.vpc_flow_reader import read_vpc_flow_logs

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent."""
    reg = ToolRegistry()
    reg.register(
        "read_suricata_alerts",
        read_suricata_alerts,
        version="0.1.0",
        cloud_calls=0,
    )
    reg.register(
        "read_vpc_flow_logs",
        read_vpc_flow_logs,
        version="0.1.0",
        cloud_calls=0,
    )
    reg.register(
        "read_dns_logs",
        read_dns_logs,
        version="0.1.0",
        cloud_calls=0,
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
        agent_id="network_threat",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # plumbed; not called in v0.1
    suricata_feed: Path | str | None = None,
    vpc_flow_feed: Path | str | None = None,
    dns_feed: Path | str | None = None,
) -> FindingsReport:
    """Run the Network Threat Agent end-to-end under the runtime charter.

    Args:
        contract: The signed `ExecutionContract`.
        llm_provider: Reserved for future LLM-driven flows; not called in v0.1.
        suricata_feed: Optional path to a Suricata eve.json file. Skipped if None.
        vpc_flow_feed: Optional path to an AWS VPC Flow Logs file (plain or .gz).
            Skipped if None.
        dns_feed: Optional path to a DNS log file (BIND text or Route 53 JSON).
            Skipped if None.

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

        # Stage 1: INGEST — three feeds concurrent.
        suricata_alerts, flow_records, dns_events = await _ingest(
            ctx,
            suricata_feed=suricata_feed,
            vpc_flow_feed=vpc_flow_feed,
            dns_feed=dns_feed,
        )

        # Stage 2: PATTERN_DETECT — three deterministic detectors over the parsed feeds.
        detections = _detect(
            flow_records=flow_records,
            dns_events=dns_events,
            suricata_alerts=suricata_alerts,
            scan_started=scan_started,
        )

        # Stage 3: ENRICH — bundled intel annotation + severity uplift.
        enriched = enrich_with_intel(detections)

        # Stage 4: SCORE (deterministic dedup pass; composite score lives in evidence).
        unique = _dedupe(enriched)

        # Stage 5: SUMMARIZE / Stage 6: HANDOFF — build findings + write artifacts.
        findings = _build_findings(unique, envelope=envelope)
        report = FindingsReport(
            agent="network_threat",
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
            "report.md",
            render_summary(report).encode("utf-8"),
        )

        ctx.assert_complete()

    return report


# ---------------------------- pipeline stages -----------------------------


async def _ingest(
    ctx: Charter,
    *,
    suricata_feed: Path | str | None,
    vpc_flow_feed: Path | str | None,
    dns_feed: Path | str | None,
) -> tuple[Sequence[SuricataAlert], Sequence[FlowRecord], Sequence[DnsEvent]]:
    """Stage 1 — fan out the three feeds via TaskGroup. Skipped feeds → empty tuple."""
    async with asyncio.TaskGroup() as tg:
        suricata_task = (
            tg.create_task(ctx.call_tool("read_suricata_alerts", path=Path(suricata_feed)))
            if suricata_feed
            else None
        )
        flow_task = (
            tg.create_task(ctx.call_tool("read_vpc_flow_logs", path=Path(vpc_flow_feed)))
            if vpc_flow_feed
            else None
        )
        dns_task = (
            tg.create_task(ctx.call_tool("read_dns_logs", path=Path(dns_feed)))
            if dns_feed
            else None
        )

    suricata: Sequence[SuricataAlert] = suricata_task.result() if suricata_task else ()
    flows: Sequence[FlowRecord] = flow_task.result() if flow_task else ()
    dns: Sequence[DnsEvent] = dns_task.result() if dns_task else ()
    return suricata, flows, dns


def _detect(
    *,
    flow_records: Sequence[FlowRecord],
    dns_events: Sequence[DnsEvent],
    suricata_alerts: Sequence[SuricataAlert],
    scan_started: datetime,
) -> list[Detection]:
    """Stage 2 — run the three deterministic detectors + lift Suricata alerts."""
    out: list[Detection] = []
    out.extend(detect_port_scan(flow_records))
    out.extend(detect_beacon(flow_records))
    out.extend(detect_dga(dns_events))
    out.extend(_suricata_to_detections(suricata_alerts, scan_started=scan_started))
    return out


def _suricata_to_detections(
    alerts: Sequence[SuricataAlert],
    *,
    scan_started: datetime,
) -> list[Detection]:
    """Lift each Suricata alert into a `Detection` with the SURICATA finding_type."""
    sev_map = {
        SuricataAlertSeverity.HIGH: Severity.HIGH,
        SuricataAlertSeverity.MEDIUM: Severity.MEDIUM,
        SuricataAlertSeverity.LOW: Severity.LOW,
    }
    seq_by_src: dict[str, int] = {}
    out: list[Detection] = []
    for a in alerts:
        src = a.src_ip or ""
        seq_by_src[src] = seq_by_src.get(src, 0) + 1
        sequence = seq_by_src[src]
        token = short_ip_token(src) if src else "UNKNOWN"
        finding_id = f"NETWORK-SURICATA-{token}-{sequence:03d}-sig{a.signature_id}"
        det = Detection(
            finding_type=FindingType.SURICATA,
            severity=sev_map.get(a.severity, Severity.MEDIUM),
            title=f"Suricata: {a.signature}",
            description=(
                f"Signature {a.signature_id} matched: {a.signature!r} (category {a.category!r})."
            ),
            detector_id=f"suricata:{a.signature_id}",
            src_ip=src,
            dst_ip=a.dst_ip or "",
            detected_at=a.timestamp or scan_started,
            evidence={
                "finding_id": finding_id,
                "signature_id": a.signature_id,
                "signature": a.signature,
                "category": a.category,
                "src_ip": src,
                "dst_ip": a.dst_ip or "",
                "src_port": a.src_port,
                "dst_port": a.dst_port,
                "protocol": a.protocol,
                "rev": a.rev,
            },
        )
        out.append(det)
    return out


def _dedupe(detections: Sequence[Detection]) -> list[Detection]:
    """Stage 4 — dedup by composite key per Q6 of the plan.

    First-seen wins; subsequent detections with the same key are dropped.
    """
    seen: set[tuple[str, str, str, int]] = set()
    out: list[Detection] = []
    for d in detections:
        key = d.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def _build_findings(
    detections: Sequence[Detection],
    *,
    envelope: NexusEnvelope,
) -> list[NetworkFinding]:
    """Stage 5/6 — turn each Detection into an OCSF 2004 NetworkFinding."""
    findings: list[NetworkFinding] = []
    for d in detections:
        finding_id = _resolve_finding_id(d)
        affected = AffectedNetwork(
            src_ip=d.src_ip or "0.0.0.0",  # noqa: S104  # OCSF placeholder for missing src_ip
            dst_ip=d.dst_ip,
            src_cidr=d.src_cidr,
        )
        finding = build_finding(
            finding_id=finding_id,
            finding_type=d.finding_type,
            severity=d.severity,
            title=d.title,
            description=d.description,
            affected_networks=[affected],
            evidence=d.evidence,
            detected_at=d.detected_at,
            envelope=envelope,
            detector_id=d.detector_id,
        )
        findings.append(finding)
    return findings


def _resolve_finding_id(d: Detection) -> str:
    """Take the detector-built `finding_id` from `evidence` when present, otherwise synthesise.

    Detectors stash their own finding_id (so dedup + suppression preserves it);
    if a Detection is constructed elsewhere without one, we synthesise a fresh ID.
    """
    candidate = d.evidence.get("finding_id")
    if isinstance(candidate, str) and candidate:
        return candidate
    token = short_ip_token(d.src_ip) if d.src_ip else "UNKNOWN"
    type_token = finding_type_token(d.finding_type)
    return f"NETWORK-{type_token}-{token}-001-synthesised"


__all__ = ["build_registry", "run"]
