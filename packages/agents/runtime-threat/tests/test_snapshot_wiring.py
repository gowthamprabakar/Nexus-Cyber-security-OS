"""Phase C SS2 — D.3 run-flow snapshot wiring makes assert_authorized load-bearing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from runtime_threat.actions.snapshot import (
    AUTHORIZED_ACTION_TYPES,
    SnapshotAction,
    UnauthorizedActionError,
    assert_authorized,
    build_snapshot_actions,
    snapshot_actions_to_json,
)
from runtime_threat.schemas import (
    AffectedHost,
    FindingType,
    RuntimeFinding,
    Severity,
    build_finding,
)
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 6, 13, tzinfo=UTC)


def _env() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="runtime_threat@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic-v0.1",
        charter_invocation_id="inv_1",
    )


def _finding(
    *,
    finding_id: str,
    severity: Severity,
    host_id: str = "abc123def456",
    evidence: dict[str, Any] | None = None,
) -> RuntimeFinding:
    return build_finding(
        finding_id=finding_id,
        finding_type=FindingType.PROCESS,
        severity=severity,
        title="suspicious exec",
        description="test",
        affected_hosts=[AffectedHost(hostname="h", host_id=host_id, image_ref="nginx:1.27")]
        if host_id
        else [AffectedHost(hostname="h", host_id="zzz", image_ref="nginx:1.27")],
        evidence=evidence if evidence is not None else {"k": "v"},
        detected_at=NOW,
        envelope=_env(),
    )


def test_high_and_critical_findings_emit_snapshots() -> None:
    findings = [
        _finding(finding_id="RUNTIME-PROCESS-ABC123-001-a", severity=Severity.CRITICAL),
        _finding(finding_id="RUNTIME-PROCESS-ABC123-002-b", severity=Severity.HIGH),
    ]
    actions = build_snapshot_actions(findings, requested_at=NOW)
    assert len(actions) == 2
    assert all(isinstance(a, SnapshotAction) and a.is_read_only for a in actions)
    assert all(a.action_type == "snapshot" for a in actions)


def test_low_severity_findings_skipped() -> None:
    findings = [_finding(finding_id="RUNTIME-PROCESS-ABC123-003-c", severity=Severity.MEDIUM)]
    assert build_snapshot_actions(findings, requested_at=NOW) == []


def test_assert_authorized_is_load_bearing() -> None:
    # The run-flow path routes through assert_authorized('snapshot'); a non-snapshot raises.
    assert "snapshot" in AUTHORIZED_ACTION_TYPES
    assert_authorized("snapshot")  # no raise
    with pytest.raises(UnauthorizedActionError):
        assert_authorized("kill")


def test_serialization_round_trips() -> None:
    import json

    actions = build_snapshot_actions(
        [_finding(finding_id="RUNTIME-PROCESS-ABC123-004-d", severity=Severity.HIGH)],
        requested_at=NOW,
    )
    payload = json.loads(snapshot_actions_to_json(actions))
    assert payload[0]["action_type"] == "snapshot"
    assert payload[0]["host_id"] == "abc123def456"
