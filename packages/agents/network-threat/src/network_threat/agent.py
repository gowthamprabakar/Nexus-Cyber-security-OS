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
from charter.memory.semantic import SemanticStore
from nexus_runtime.realtime import EventStream, bounded_drain
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from network_threat import __version__ as agent_version
from network_threat.actions.temporary_ip_block import (
    build_temporary_ip_blocks,
    temporary_ip_blocks_to_json,
)
from network_threat.detectors.beacon import detect_beacon
from network_threat.detectors.dga import detect_dga
from network_threat.detectors.port_scan import detect_port_scan
from network_threat.enrichment import enrich_with_intel
from network_threat.kg_writer import KnowledgeGraphWriter
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
from network_threat.tools.suricata_normalize import normalize_suricata_event
from network_threat.tools.suricata_reader import read_suricata_alerts
from network_threat.tools.vpc_flow_reader import read_vpc_flow_logs
from network_threat.tools.vpc_flow_realtime_aws import read_vpc_flow_live
from network_threat.tools.zeek_normalize import normalize_zeek_dns

#: A-1.4 default bounded-drain cap for an injected live stream — a single-shot
#: run() drains at most this many events (count bound) so an infinite push
#: stream always terminates. Operators tune via ``realtime_max_events``.
DEFAULT_REALTIME_MAX_EVENTS = 10_000

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent.

    Phase C SS4: ``read_vpc_flow_live`` is registered so the v0.2 live CloudWatch VPC-flow
    poller dispatches through the charter proxy (ADR-016) and ``run()`` can route to a live
    log group behind a guarded flag. cloud_calls=1 (CloudWatch filter_log_events). The Suricata
    + Zeek REALTIME subscribers are continuous/streaming infrastructure (SS1 ContinuousDriver
    territory), not request/response tools, so they are intentionally NOT registered here.
    """
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
    reg.register(
        "read_vpc_flow_live",
        read_vpc_flow_live,
        version="0.2.0",
        cloud_calls=1,
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
    vpc_flow_log_group: str | None = None,
    aws_profile: str | None = None,
    aws_region: str = "us-east-1",
    suricata_stream: EventStream | None = None,
    zeek_stream: EventStream | None = None,
    realtime_max_events: int = DEFAULT_REALTIME_MAX_EVENTS,
    semantic_store: SemanticStore | None = None,
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
        vpc_flow_log_group: Phase C SS4 guarded live route. When set, the VPC
            flow source is a live CloudWatch Logs group polled via
            ``read_vpc_flow_live`` (boto3) instead of ``vpc_flow_feed`` —
            mutually exclusive with it. Suricata/DNS still come from feeds.
        aws_profile: Optional boto3 profile for the live VPC-flow poll.
        aws_region: AWS region for the live VPC-flow poll (default us-east-1).
        suricata_stream: A-1.4 live-loop wiring. An injected Suricata push event
            stream (``subscribe()`` yields raw eve.json dicts). When set, INGEST
            drains it via ``bounded_drain`` (count-bounded by
            ``realtime_max_events``) through the existing
            ``normalize_suricata_event`` — byte-identical to the offline
            ``SuricataAlert`` shape. Mutually exclusive with ``suricata_feed``.
        zeek_stream: A-1.4 live-loop wiring. An injected Zeek push event stream.
            INGEST drains it through ``normalize_zeek_dns`` (DNS events only;
            Zeek-conn → FlowRecord is a deferred follow-up), byte-identical to
            the offline DNS shape. Mutually exclusive with ``dns_feed``.
        realtime_max_events: Count bound for the live drains (default
            ``DEFAULT_REALTIME_MAX_EVENTS``) so an infinite stream terminates.
        semantic_store: v0.4 Stage 1.4 (D.4) opt-in fleet-graph sink. When set,
            the observed network topology (flow endpoints + ``COMMUNICATES_WITH``
            edges) is written via ``KnowledgeGraphWriter`` after INGEST. Default
            None is inert — no graph writes, ``findings.json`` byte-identical.

    Returns:
        The `FindingsReport`. Side effects: writes `findings.json` and
        `report.md` to the charter workspace; emits a hash-chained audit
        log at `audit.jsonl`.
    """
    del llm_provider  # reserved for future iterations

    if vpc_flow_log_group is not None and vpc_flow_feed:
        raise ValueError(
            "vpc_flow_log_group is mutually exclusive with vpc_flow_feed — pick the live "
            "CloudWatch route or the file feed (Phase C SS4)"
        )
    if suricata_stream is not None and suricata_feed:
        raise ValueError(
            "suricata_stream is mutually exclusive with suricata_feed — pick the live "
            "realtime stream or the eve.json feed (A-1)"
        )
    if zeek_stream is not None and dns_feed:
        raise ValueError(
            "zeek_stream is mutually exclusive with dns_feed — Zeek emits the DNS events "
            "for that slot (A-1)"
        )

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)

        # Stage 1: INGEST — three feeds concurrent (VPC flow may come from a live group).
        suricata_alerts, flow_records, dns_events = await _ingest(
            ctx,
            suricata_feed=suricata_feed,
            vpc_flow_feed=vpc_flow_feed,
            dns_feed=dns_feed,
            vpc_flow_log_group=vpc_flow_log_group,
            aws_profile=aws_profile,
            aws_region=aws_region,
            suricata_stream=suricata_stream,
            zeek_stream=zeek_stream,
            realtime_max_events=realtime_max_events,
            received_at=scan_started,
        )

        # v0.4 Stage 1.4: write the observed network topology (flow endpoints +
        # COMMUNICATES_WITH edges) to the fleet graph when a SemanticStore is
        # injected. Opt-in — default None is inert (no graph writes), so
        # findings.json + report.md stay byte-identical. Computed reachability
        # (CAN_REACH) stays Stage 3 correlation (#715a).
        if semantic_store is not None:
            kg = KnowledgeGraphWriter(semantic_store, contract.customer_id)
            await kg.record_flows(flow_records)

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

        # Phase C SS2: emit TTL-bounded IP-block proposals for HIGH/CRITICAL findings' public
        # source IPs. Every block routes through assert_block_authorized (Q4/WI-N8/WI-N10),
        # making that invariant load-bearing; private/invalid IPs are skipped by the guard.
        # Additive artifact — findings.json is byte-identical.
        ip_blocks = build_temporary_ip_blocks(findings, requested_at=scan_started)
        ctx.write_output(
            "ip_block_actions.json",
            temporary_ip_blocks_to_json(ip_blocks).encode("utf-8"),
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
    vpc_flow_log_group: str | None = None,
    aws_profile: str | None = None,
    aws_region: str = "us-east-1",
    suricata_stream: EventStream | None = None,
    zeek_stream: EventStream | None = None,
    realtime_max_events: int = DEFAULT_REALTIME_MAX_EVENTS,
    received_at: datetime | None = None,
) -> tuple[Sequence[SuricataAlert], Sequence[FlowRecord], Sequence[DnsEvent]]:
    """Stage 1 — fan out the feeds via TaskGroup. Skipped sources → empty tuple.

    Phase C SS4: the VPC-flow source is the live ``read_vpc_flow_live`` CloudWatch poll when
    ``vpc_flow_log_group`` is set (making that reader load-bearing through the charter),
    otherwise the offline ``read_vpc_flow_logs`` file feed. Both yield FlowRecord tuples, so
    downstream detection is source-agnostic.

    A-1.4: when ``suricata_stream`` / ``zeek_stream`` is set, that slot is drained from the
    injected live push stream via ``bounded_drain`` (count-bounded) through the existing
    per-sensor normalizer — byte-identical to the offline shape. Stream and feed for the same
    slot are mutually exclusive (guarded in ``run()``). Zeek emits DNS events only; Zeek-conn
    → FlowRecord is a deferred follow-up, so the live flow source stays VPC-only.
    """
    when = received_at if received_at is not None else datetime.now(UTC)

    # A-1.4 live drains — direct over the injected stream (the stream IS the live source).
    suricata_live: tuple[SuricataAlert, ...] | None = None
    if suricata_stream is not None:

        def _suricata_norm(raw: dict[str, object]) -> SuricataAlert | None:
            normalized = normalize_suricata_event(raw, received_at=when)
            return normalized.alert if normalized is not None else None

        suricata_live = await bounded_drain(
            suricata_stream, _suricata_norm, max_events=realtime_max_events
        )

    dns_live: tuple[DnsEvent, ...] | None = None
    if zeek_stream is not None:

        def _zeek_dns_norm(raw: dict[str, object]) -> DnsEvent | None:
            return normalize_zeek_dns(raw, received_at=when)

        dns_live = await bounded_drain(zeek_stream, _zeek_dns_norm, max_events=realtime_max_events)

    async with asyncio.TaskGroup() as tg:
        suricata_task = (
            tg.create_task(ctx.call_tool("read_suricata_alerts", path=Path(suricata_feed)))
            if suricata_feed
            else None
        )
        if vpc_flow_log_group is not None:
            flow_task = tg.create_task(
                ctx.call_tool(
                    "read_vpc_flow_live",
                    log_group=vpc_flow_log_group,
                    profile=aws_profile,
                    region=aws_region,
                )
            )
        elif vpc_flow_feed:
            flow_task = tg.create_task(
                ctx.call_tool("read_vpc_flow_logs", path=Path(vpc_flow_feed))
            )
        else:
            flow_task = None
        dns_task = (
            tg.create_task(ctx.call_tool("read_dns_logs", path=Path(dns_feed)))
            if dns_feed
            else None
        )

    # Live drains take their slot when present (mutually exclusive with the feed).
    suricata: Sequence[SuricataAlert] = (
        suricata_live
        if suricata_live is not None
        else (suricata_task.result() if suricata_task else ())
    )
    flows: Sequence[FlowRecord] = flow_task.result() if flow_task else ()
    dns: Sequence[DnsEvent] = (
        dns_live if dns_live is not None else (dns_task.result() if dns_task else ())
    )
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
