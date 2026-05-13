"""`NetworkThreatEvalRunner` — the canonical `EvalRunner` for D.4.

Mirrors D.3's
[`eval_runner.py`](../../../runtime-threat/src/runtime_threat/eval_runner.py)
shape — patches the three reader tools at the agent module's import
scope, builds an `ExecutionContract` rooted at the suite-supplied
workspace, calls `network_threat.agent.run`, then compares the
resulting `FindingsReport` to `case.expected`.

**Fixture keys** (under `fixture`):

Explicit lists (each item is a dict shaping the corresponding model):

- `flow_records: list[dict]` — `FlowRecord` shape (src_ip, dst_ip,
  dst_port, start_time / duration_seconds OR start + end, action).
- `dns_events: list[dict]` — `DnsEvent` shape (timestamp, kind,
  query_name, query_type, src_ip, ...).
- `suricata_alerts: list[dict]` — `SuricataAlert` shape (timestamp,
  src_ip, dst_ip, src_port, dst_port, protocol, signature_id,
  signature, severity, category).

Synthesizer directives (the runner expands these into many records
so the YAML stays compact):

- `flow_records_scan: { src_ip, dst_ip, count, spacing_ms,
  start_time, base_dst_port }` — emit `count` ACCEPT FlowRecords
  hitting `base_dst_port..base_dst_port+count` at `spacing_ms`
  intervals.
- `flow_records_beacon: { src_ip, dst_ip, dst_port, count,
  period_seconds, start_time }` — emit `count` ACCEPT FlowRecords
  to the same (src,dst,port) at `period_seconds` intervals.

**Comparison shape** (under `expected`):

- `finding_count: int`
- `by_severity: {sev: int}` — checked when present.
- `by_finding_type: {ft: int}` — checked when present.

Registered via `pyproject.toml`'s
`[project.entry-points."nexus_eval_runners"]` so
`eval-framework run --runner network_threat` resolves it.
"""

from __future__ import annotations

from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from charter.contract import BudgetSpec, ExecutionContract
from charter.llm import LLMProvider
from eval_framework.cases import EvalCase
from eval_framework.runner import RunOutcome

from network_threat import agent as agent_mod
from network_threat.schemas import (
    DnsEvent,
    DnsEventKind,
    FindingsReport,
    FlowRecord,
    SuricataAlert,
    SuricataAlertSeverity,
)


class NetworkThreatEvalRunner:
    """Reference `EvalRunner` for the Network Threat Agent."""

    @property
    def agent_name(self) -> str:
        return "network_threat"

    async def run(
        self,
        case: EvalCase,
        *,
        workspace: Path,
        llm_provider: LLMProvider | None = None,
    ) -> RunOutcome:
        workspace.mkdir(parents=True, exist_ok=True)
        contract = _build_contract(case, workspace)
        report = await _run_case_async(case, contract, llm_provider=llm_provider)

        passed, failure_reason = _evaluate(case, report)
        actuals: dict[str, Any] = {
            "finding_count": report.total,
            "by_severity": report.count_by_severity(),
            "by_finding_type": report.count_by_finding_type(),
        }
        audit_log_path = Path(contract.workspace) / "audit.jsonl"
        return (
            passed,
            failure_reason,
            actuals,
            audit_log_path if audit_log_path.exists() else None,
        )


# ---------------------------- internals ----------------------------------


async def _run_case_async(
    case: EvalCase,
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None,
) -> FindingsReport:
    fixture = case.fixture

    suricata_alerts = tuple(_parse_suricata(a) for a in fixture.get("suricata_alerts", []) or [])
    flow_records = tuple(_build_flow_records(fixture))
    dns_events = tuple(_parse_dns(e) for e in fixture.get("dns_events", []) or [])

    async def fake_suricata(**_: Any) -> tuple[SuricataAlert, ...]:
        return suricata_alerts

    async def fake_vpc_flow(**_: Any) -> tuple[FlowRecord, ...]:
        return flow_records

    async def fake_dns(**_: Any) -> tuple[DnsEvent, ...]:
        return dns_events

    workspace = Path(contract.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    suricata_feed: Path | None = None
    vpc_flow_feed: Path | None = None
    dns_feed: Path | None = None
    if suricata_alerts:
        suricata_feed = workspace / "_fixture_suricata.json"
        suricata_feed.write_text("placeholder\n")
    if flow_records:
        vpc_flow_feed = workspace / "_fixture_vpc_flow.log"
        vpc_flow_feed.write_text("placeholder\n")
    if dns_events:
        dns_feed = workspace / "_fixture_dns.log"
        dns_feed.write_text("placeholder\n")

    with ExitStack() as stack:
        stack.enter_context(patch.object(agent_mod, "read_suricata_alerts", fake_suricata))
        stack.enter_context(patch.object(agent_mod, "read_vpc_flow_logs", fake_vpc_flow))
        stack.enter_context(patch.object(agent_mod, "read_dns_logs", fake_dns))
        return await agent_mod.run(
            contract=contract,
            llm_provider=llm_provider,
            suricata_feed=suricata_feed,
            vpc_flow_feed=vpc_flow_feed,
            dns_feed=dns_feed,
        )


def _build_contract(case: EvalCase, workspace_root: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="network_threat",
        customer_id="cust_eval",
        task=case.description or case.case_id,
        required_outputs=["findings.json", "report.md"],
        budget=BudgetSpec(
            llm_calls=1,
            tokens=1,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["read_suricata_alerts", "read_vpc_flow_logs", "read_dns_logs"],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _evaluate(case: EvalCase, report: FindingsReport) -> tuple[bool, str | None]:
    sev_counts = report.count_by_severity()
    type_counts = report.count_by_finding_type()

    expected_count = case.expected.get("finding_count")
    if expected_count is not None and report.total != int(expected_count):
        return False, f"finding_count expected {expected_count}, got {report.total}"

    expected_sev = case.expected.get("by_severity") or {}
    for sev, want in expected_sev.items():
        actual = sev_counts.get(str(sev), 0)
        if actual != int(want):
            return False, f"severity '{sev}' expected {want}, got {actual}"

    expected_types = case.expected.get("by_finding_type") or {}
    for ft, want in expected_types.items():
        actual = type_counts.get(str(ft), 0)
        if actual != int(want):
            return False, f"finding_type '{ft}' expected {want}, got {actual}"

    return True, None


# ---------------------------- fixture -> dataclass parsing ---------------


def _build_flow_records(fixture: dict[str, Any]) -> list[FlowRecord]:
    """Combine explicit `flow_records` + synthesised `flow_records_scan/beacon`."""
    out: list[FlowRecord] = []
    for raw in fixture.get("flow_records", []) or []:
        out.append(_parse_flow_record(raw))
    scan_directive = fixture.get("flow_records_scan")
    if isinstance(scan_directive, dict):
        out.extend(_expand_scan(scan_directive))
    beacon_directive = fixture.get("flow_records_beacon")
    if isinstance(beacon_directive, dict):
        out.extend(_expand_beacon(beacon_directive))
    return out


def _expand_scan(directive: dict[str, Any]) -> list[FlowRecord]:
    src = str(directive.get("src_ip", ""))
    dst = str(directive.get("dst_ip", ""))
    count = int(directive.get("count", 0))
    spacing_ms = int(directive.get("spacing_ms", 100))
    base_dst_port = int(directive.get("base_dst_port", 1024))
    start = _parse_dt(directive.get("start_time")) or datetime.now(UTC)
    out: list[FlowRecord] = []
    for i in range(count):
        t = start + timedelta(milliseconds=i * spacing_ms)
        out.append(
            FlowRecord(
                src_ip=src,
                dst_ip=dst,
                src_port=49152,
                dst_port=base_dst_port + i,
                protocol=6,
                bytes_transferred=100,
                packets=1,
                start_time=t,
                end_time=t + timedelta(seconds=0.5),
                action="ACCEPT",
            )
        )
    return out


def _expand_beacon(directive: dict[str, Any]) -> list[FlowRecord]:
    src = str(directive.get("src_ip", ""))
    dst = str(directive.get("dst_ip", ""))
    dst_port = int(directive.get("dst_port", 443))
    count = int(directive.get("count", 0))
    period = float(directive.get("period_seconds", 60.0))
    start = _parse_dt(directive.get("start_time")) or datetime.now(UTC)
    out: list[FlowRecord] = []
    for i in range(count):
        t = start + timedelta(seconds=i * period)
        out.append(
            FlowRecord(
                src_ip=src,
                dst_ip=dst,
                src_port=49152,
                dst_port=dst_port,
                protocol=6,
                bytes_transferred=100,
                packets=1,
                start_time=t,
                end_time=t + timedelta(seconds=0.5),
                action="ACCEPT",
            )
        )
    return out


def _parse_flow_record(raw: dict[str, Any]) -> FlowRecord:
    start = _parse_dt(raw.get("start_time")) or datetime.now(UTC)
    duration = float(raw.get("duration_seconds", 0.5))
    end = _parse_dt(raw.get("end_time")) or (start + timedelta(seconds=duration))
    return FlowRecord(
        src_ip=str(raw.get("src_ip", "")),
        dst_ip=str(raw.get("dst_ip", "")),
        src_port=int(raw.get("src_port", 49152)),
        dst_port=int(raw.get("dst_port", 0)),
        protocol=int(raw.get("protocol", 6)),
        bytes_transferred=int(raw.get("bytes_transferred", 0)),
        packets=int(raw.get("packets", 0)),
        start_time=start,
        end_time=end,
        action=str(raw.get("action", "ACCEPT")),
    )


def _parse_dns(raw: dict[str, Any]) -> DnsEvent:
    timestamp = _parse_dt(raw.get("timestamp")) or datetime.now(UTC)
    kind_raw = str(raw.get("kind", "query")).lower()
    kind = DnsEventKind.RESPONSE if kind_raw == "response" else DnsEventKind.QUERY
    answers_raw = raw.get("answers", []) or []
    answers = tuple(str(a) for a in answers_raw if isinstance(a, str))
    return DnsEvent(
        timestamp=timestamp,
        kind=kind,
        query_name=str(raw.get("query_name", "")),
        query_type=str(raw.get("query_type", "A")),
        src_ip=str(raw.get("src_ip", "")),
        resolver_endpoint=str(raw.get("resolver_endpoint", "")),
        rcode=str(raw.get("rcode", "NOERROR")),
        answers=answers,
    )


def _parse_suricata(raw: dict[str, Any]) -> SuricataAlert:
    timestamp = _parse_dt(raw.get("timestamp")) or datetime.now(UTC)
    severity_str = str(raw.get("severity", "2"))
    try:
        severity = SuricataAlertSeverity(severity_str)
    except ValueError:
        severity = SuricataAlertSeverity.MEDIUM
    return SuricataAlert(
        timestamp=timestamp,
        src_ip=str(raw.get("src_ip", "")),
        dst_ip=str(raw.get("dst_ip", "")),
        src_port=int(raw.get("src_port", 0)),
        dst_port=int(raw.get("dst_port", 0)),
        protocol=str(raw.get("protocol", "TCP")),
        signature_id=int(raw.get("signature_id", 1)),
        signature=str(raw.get("signature", "")),
        category=str(raw.get("category", "")),
        severity=severity,
        rev=int(raw.get("rev", 1)),
    )


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


__all__ = ["NetworkThreatEvalRunner"]
