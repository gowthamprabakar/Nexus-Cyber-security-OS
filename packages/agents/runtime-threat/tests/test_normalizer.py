"""Tests for `runtime_threat.normalizer.normalize_to_findings`."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from runtime_threat.normalizer import normalize_to_findings
from runtime_threat.schemas import FindingType, RuntimeFinding, Severity
from runtime_threat.tools.falco import FalcoAlert
from runtime_threat.tools.osquery import OsqueryResult
from runtime_threat.tools.tracee import TraceeAlert
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 5, 11, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="runtime_threat@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic-v0.1",
        charter_invocation_id="invocation_001",
    )


# ---------------------------- builders ----------------------------------


def _falco(
    *,
    rule: str = "Terminal shell in container",
    priority: str = "Warning",
    output: str = "shell spawned",
    tags: tuple[str, ...] = ("container", "shell", "process"),
    output_fields: dict[str, Any] | None = None,
) -> FalcoAlert:
    fields = output_fields or {
        "container.id": "abc123def456",
        "container.image.repository": "nginx",
        "proc.cmdline": "/bin/sh",
        "k8s.pod.name": "frontend-7f9d",
        "k8s.ns.name": "production",
    }
    return FalcoAlert(
        time=NOW,
        rule=rule,
        priority=priority,
        output=output,
        output_fields=fields,
        tags=tags,
    )


def _tracee(
    *,
    event_name: str = "security_file_open",
    severity: int = 3,
    description: str = "Read /etc/shadow",
    args: dict[str, str] | None = None,
    process_name: str = "cat",
    host_name: str = "ip-10-0-1-42",
    container_id: str = "tracee-container-id",
) -> TraceeAlert:
    return TraceeAlert(
        timestamp=NOW,
        event_name=event_name,
        process_name=process_name,
        process_id=4242,
        host_name=host_name,
        container_image="alpine:3.18",
        container_id=container_id,
        args=args or {"pathname": "/etc/shadow"},
        severity=severity,
        description=description,
        pod_name="bastion",
        namespace="kube-system",
    )


def _osquery(
    rows: list[dict[str, str]], sql: str = "SELECT pid, name FROM processes"
) -> OsqueryResult:
    return OsqueryResult(sql=sql, rows=tuple(rows))


# ---------------------------- empty path --------------------------------


@pytest.mark.asyncio
async def test_empty_inputs_yield_no_findings() -> None:
    findings = await normalize_to_findings([], [], [], envelope=_envelope(), detected_at=NOW)
    assert findings == []


# ---------------------------- Falco family dispatch ---------------------


@pytest.mark.asyncio
async def test_falco_process_tag_yields_runtime_process() -> None:
    findings = await normalize_to_findings(
        [_falco(tags=("container", "shell", "process"))],
        [],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert len(findings) == 1
    assert findings[0].finding_type is FindingType.PROCESS


@pytest.mark.asyncio
async def test_falco_network_tag_yields_runtime_network() -> None:
    findings = await normalize_to_findings(
        [_falco(rule="Outbound to suspicious IP", tags=("network",))],
        [],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert findings[0].finding_type is FindingType.NETWORK


@pytest.mark.asyncio
async def test_falco_filesystem_tag_yields_runtime_file() -> None:
    findings = await normalize_to_findings(
        [_falco(rule="Sensitive file read", tags=("filesystem",))],
        [],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert findings[0].finding_type is FindingType.FILE


@pytest.mark.asyncio
async def test_falco_syscall_tag_yields_runtime_syscall() -> None:
    findings = await normalize_to_findings(
        [_falco(rule="Kernel module load", tags=("syscall", "kernel"))],
        [],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert findings[0].finding_type is FindingType.SYSCALL


@pytest.mark.asyncio
async def test_falco_no_dispatch_tag_defaults_to_process() -> None:
    """When no recognised tag is present, the alert is treated as PROCESS."""
    findings = await normalize_to_findings(
        [_falco(tags=("mitre_execution",))],
        [],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert findings[0].finding_type is FindingType.PROCESS


@pytest.mark.asyncio
async def test_falco_severity_propagates() -> None:
    """Critical priority → CRITICAL severity on the emitted finding."""
    findings = await normalize_to_findings(
        [_falco(priority="Critical")],
        [],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert findings[0].severity is Severity.CRITICAL


@pytest.mark.asyncio
async def test_falco_rule_lands_in_finding_info_product_uid() -> None:
    findings = await normalize_to_findings(
        [_falco(rule="Terminal shell in container")],
        [],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    payload = findings[0].to_dict()
    assert payload["finding_info"]["product_uid"] == "Terminal shell in container"


# ---------------------------- Tracee family dispatch --------------------


@pytest.mark.asyncio
async def test_tracee_security_file_event_yields_runtime_file() -> None:
    findings = await normalize_to_findings(
        [],
        [_tracee(event_name="security_file_open")],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert findings[0].finding_type is FindingType.FILE


@pytest.mark.asyncio
async def test_tracee_security_socket_event_yields_runtime_network() -> None:
    findings = await normalize_to_findings(
        [],
        [_tracee(event_name="security_socket_connect")],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert findings[0].finding_type is FindingType.NETWORK


@pytest.mark.asyncio
async def test_tracee_other_event_defaults_to_syscall() -> None:
    findings = await normalize_to_findings(
        [],
        [_tracee(event_name="sched_process_exec")],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert findings[0].finding_type is FindingType.SYSCALL


@pytest.mark.asyncio
async def test_tracee_severity_3_propagates_to_critical() -> None:
    findings = await normalize_to_findings(
        [],
        [_tracee(severity=3)],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert findings[0].severity is Severity.CRITICAL


# ---------------------------- OSQuery family ----------------------------


@pytest.mark.asyncio
async def test_osquery_emits_one_finding_per_row() -> None:
    result = _osquery(
        [
            {"pid": "1234", "name": "init"},
            {"pid": "2345", "name": "sshd"},
            {"pid": "3456", "name": "nginx"},
        ]
    )
    findings = await normalize_to_findings([], [], [result], envelope=_envelope(), detected_at=NOW)
    assert len(findings) == 3
    assert all(f.finding_type is FindingType.OSQUERY for f in findings)


@pytest.mark.asyncio
async def test_osquery_caller_supplied_severity_default_is_medium() -> None:
    result = _osquery([{"pid": "1", "name": "init"}])
    findings = await normalize_to_findings([], [], [result], envelope=_envelope(), detected_at=NOW)
    assert findings[0].severity is Severity.MEDIUM


@pytest.mark.asyncio
async def test_osquery_caller_can_override_severity() -> None:
    result = _osquery([{"pid": "1", "name": "init"}])
    findings = await normalize_to_findings(
        [],
        [],
        [result],
        envelope=_envelope(),
        detected_at=NOW,
        osquery_severity=3,
    )
    assert findings[0].severity is Severity.CRITICAL


@pytest.mark.asyncio
async def test_osquery_row_lands_in_evidence() -> None:
    result = _osquery([{"pid": "1234", "name": "init"}])
    findings = await normalize_to_findings([], [], [result], envelope=_envelope(), detected_at=NOW)
    assert findings[0].evidence["osquery_row"] == {"pid": "1234", "name": "init"}


# ---------------------------- multi-feed --------------------------------


@pytest.mark.asyncio
async def test_no_dedup_when_falco_and_tracee_describe_same_incident() -> None:
    """v0.1 emits both findings; correlation deferred to D.7 Investigation Agent."""
    findings = await normalize_to_findings(
        [_falco(rule="Sensitive file read", tags=("filesystem",))],
        [_tracee(event_name="security_file_open")],
        [],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert len(findings) == 2
    types = {f.finding_type for f in findings}
    assert types == {FindingType.FILE}


@pytest.mark.asyncio
async def test_multi_feed_rollup_emits_findings_in_deterministic_order() -> None:
    """Falco first, then Tracee, then OSQuery."""
    findings = await normalize_to_findings(
        [_falco(rule="shell-in-container")],
        [_tracee(event_name="security_file_open")],
        [_osquery([{"pid": "1234", "name": "init"}])],
        envelope=_envelope(),
        detected_at=NOW,
    )
    assert len(findings) == 3
    # Reconstruct via the OCSF wire format (no source-tagging on RuntimeFinding directly).
    payloads = [f.to_dict() for f in findings]
    assert payloads[0]["evidences"][0].get("falco_rule") == "shell-in-container"
    assert payloads[1]["evidences"][0].get("tracee_event") == "security_file_open"
    assert payloads[2]["evidences"][0].get("osquery_sql") is not None


# ---------------------------- envelope + shape invariants ---------------


@pytest.mark.asyncio
async def test_envelope_attached_to_each_finding() -> None:
    findings = await normalize_to_findings(
        [_falco()],
        [_tracee()],
        [_osquery([{"pid": "1", "name": "init"}])],
        envelope=_envelope(),
        detected_at=NOW,
    )
    for f in findings:
        assert isinstance(f, RuntimeFinding)
        assert f.envelope.tenant_id == "cust_test"


@pytest.mark.asyncio
async def test_finding_ids_are_unique_across_feeds() -> None:
    findings = await normalize_to_findings(
        [_falco(rule=f"rule-{i}") for i in range(3)],
        [_tracee(event_name=f"security_file_open_{i}") for i in range(3)],
        [_osquery([{"pid": f"{i}", "name": "init"} for i in range(3)])],
        envelope=_envelope(),
        detected_at=NOW,
    )
    ids = [f.finding_id for f in findings]
    assert len(ids) == len(set(ids)), f"duplicate finding_ids: {ids}"
