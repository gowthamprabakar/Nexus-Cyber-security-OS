"""WI-R4 (HARD) — live real-time event end-to-end (D.3 v0.2 Task 18).

Two-layer per the WI-V6 / WI-I4 / WI-T4 lineage:

1. **Offline layer (every push):** the real real-time pipeline — Falco / Tracee event
   subscription → normalization → MITRE mapping → OCSF 2004 finding emission — exercised
   end-to-end with injected fake streams (no live sensors). Snapshot action emission is
   verified read-only (Q4 — no kill/quarantine attempted).
2. **Gated-live layer (`NEXUS_LIVE_RUNTIME_FALCO/TRACEE=1`):** probes the live sensors;
   skipped in CI via the gate fixtures.

Honest scope (WI-R3): the real-time readers + framework are e2e-tested here through
emission; wiring them into the agent's *continuous* run loop is a v0.3 carry-forward —
the offline `run()` remains the deterministic OCSF-emitting path (WI-R5 byte-identical).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from runtime_threat.actions.snapshot import (
    UnauthorizedActionError,
    assert_authorized,
    request_workload_snapshot,
)
from runtime_threat.baseline.observer import BaselineObserver
from runtime_threat.correlators.cross_sensor import correlate_sensor_events, cross_sensor_events
from runtime_threat.handoff import attach_investigation_handoff, should_recommend_investigation
from runtime_threat.live_lane import falco_reachable, tracee_reachable
from runtime_threat.mitre.emission import MITRE_EVIDENCE_KEY, attach_techniques
from runtime_threat.mitre.mapper import falco_signals, map_signals, tracee_signals
from runtime_threat.schemas import (
    AffectedHost,
    FindingType,
    RuntimeFinding,
    Severity,
    build_finding,
)
from runtime_threat.tools.falco_normalize import normalize_falco_event
from runtime_threat.tools.falco_realtime import FalcoRealtimeSubscriber
from runtime_threat.tools.tracee_normalize import normalize_tracee_event
from runtime_threat.tools.tracee_realtime import TraceeRealtimeSubscriber

pytestmark = pytest.mark.asyncio

_RX = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)


class _Stream:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        for e in self._events:
            yield e


def _envelope() -> Any:
    from shared.fabric.envelope import NexusEnvelope

    return NexusEnvelope(
        correlation_id="corr_d3",
        tenant_id="cust_test",
        agent_id="runtime_threat@0.2.0",
        nlah_version="0.2.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )


def _emit(rule_signal_source: set[str], *, host: str) -> RuntimeFinding:
    """The shared emission tail: signals → mapping → OCSF 2004 finding with techniques."""
    mappings = map_signals(rule_signal_source)
    max_conf = max((m.confidence for m in mappings), default=0.0)
    evidence = attach_techniques({"proc_name": "bash"}, mappings)
    evidence = attach_investigation_handoff(
        evidence,
        recommended=should_recommend_investigation(severity="high", max_confidence=max_conf),
    )
    return build_finding(
        finding_id="RUNTIME-PROCESS-HOST1-001-shell",
        finding_type=FindingType.PROCESS,
        severity=Severity.HIGH,
        title="suspicious shell",
        description="real-time detection",
        affected_hosts=[AffectedHost(hostname=host, host_id="c1")],
        evidence=evidence,
        detected_at=_RX,
        envelope=_envelope(),
    )


# ------------------- offline layer: full pipeline ------------------------


async def test_falco_pipeline_emits_ocsf_2004_with_technique() -> None:
    findings: list[RuntimeFinding] = []

    async def handler(raw: dict[str, Any]) -> None:
        norm = normalize_falco_event(raw, received_at=_RX)
        if norm is None:
            return
        findings.append(_emit(falco_signals(norm.alert), host="node-1"))

    raw = {
        "rule": "Terminal shell in container",
        "tags": ["shell"],
        "output_fields": {"container.id": "c1"},
    }
    await FalcoRealtimeSubscriber(_Stream([raw]), handler).run()

    assert len(findings) == 1
    # Construction validated class_uid 2004; the technique block rode through.
    assert findings[0].finding_type == FindingType.PROCESS
    techniques = findings[0].evidence[MITRE_EVIDENCE_KEY]
    assert techniques[0]["technique_id"] == "T1059"


async def test_tracee_pipeline_emits_finding() -> None:
    findings: list[RuntimeFinding] = []

    async def handler(raw: dict[str, Any]) -> None:
        norm = normalize_tracee_event(raw, received_at=_RX)
        if norm is None:
            return
        findings.append(_emit(tracee_signals(norm.alert), host="node-1"))

    raw = {"eventName": "security_file_open", "containerId": "c1", "processName": "cat"}
    await TraceeRealtimeSubscriber(_Stream([raw]), handler).run()
    assert len(findings) == 1
    assert findings[0].evidence[MITRE_EVIDENCE_KEY][0]["technique_id"] == "T1005"


async def test_cross_sensor_correlation_e2e() -> None:
    f = normalize_falco_event(
        {"rule": "R", "output_fields": {"container.id": "c1", "proc.pid": "100"}}, received_at=_RX
    )
    t = normalize_tracee_event(
        {"eventName": "E", "containerId": "c1", "processId": 100}, received_at=_RX
    )
    assert f is not None and t is not None
    groups = correlate_sensor_events([f], [t])
    assert len(cross_sensor_events(groups)) == 1  # de-duped to one cross-sensor group


async def test_snapshot_action_is_read_only_no_kill() -> None:
    action = request_workload_snapshot("node-1", "c1", reason="shell", requested_at=_RX)
    assert action.action_type == "snapshot" and action.is_read_only is True
    # Q4 / WI-R8: a kill/quarantine attempt is hard-blocked.
    with pytest.raises(UnauthorizedActionError):
        assert_authorized("kill")
    with pytest.raises(UnauthorizedActionError):
        assert_authorized("quarantine")


async def test_investigation_handoff_flag_present() -> None:
    finding = _emit({"Outbound connection to C2"}, host="node-1")
    assert finding.evidence["investigation_recommended"] is True


async def test_passive_baseline_collected_during_run() -> None:
    obs = BaselineObserver()

    async def handler(raw: dict[str, Any]) -> None:
        norm = normalize_falco_event(raw, received_at=_RX)
        if norm is not None:
            obs.observe_falco(norm)

    raw = {"rule": "R", "output_fields": {"container.id": "c1", "proc.name": "nginx"}}
    await FalcoRealtimeSubscriber(_Stream([raw]), handler).run()
    wb = obs.baseline("c1")
    assert wb is not None and wb.processes == {"nginx"}


async def test_subscriber_drains_full_stream() -> None:
    seen: list[str] = []

    async def handler(raw: dict[str, Any]) -> None:
        seen.append(raw["rule"])

    events = [{"rule": f"r{i}", "output_fields": {}} for i in range(50)]
    stats = await FalcoRealtimeSubscriber(_Stream(events), handler).run()
    assert stats.handled == 50 and len(seen) == 50


# --------------------------- gated-live layer ----------------------------


async def test_live_falco_reachable(falco_gate: None) -> None:
    ok, reason = falco_reachable()
    assert ok, f"Falco unreachable: {reason}"


async def test_live_tracee_reachable(tracee_gate: None) -> None:
    ok, reason = tracee_reachable()
    assert ok, f"Tracee unreachable: {reason}"
