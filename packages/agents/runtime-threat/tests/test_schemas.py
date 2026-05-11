"""Tests for `runtime_threat.schemas` — OCSF Detection Finding (class_uid 2004) typing layer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from runtime_threat.schemas import (
    FINDING_ID_RE,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    AffectedHost,
    FindingsReport,
    FindingType,
    RuntimeFinding,
    Severity,
    build_finding,
    finding_type_token,
    severity_from_id,
    severity_to_id,
    short_host_id,
)
from shared.fabric.envelope import NexusEnvelope


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="runtime_threat@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic-v0.1",
        charter_invocation_id="invocation_001",
    )


def _host(host_id: str = "abc123def456", hostname: str = "ip-10-0-1-42") -> AffectedHost:
    return AffectedHost(
        hostname=hostname,
        host_id=host_id,
        image_ref="nginx:1.27",
        namespace="production",
        ip_addresses=("10.0.1.42",),
    )


# ---------------------------- OCSF constants -----------------------------


def test_ocsf_class_constants_are_2004_detection() -> None:
    assert OCSF_CLASS_UID == 2004
    assert OCSF_CLASS_NAME == "Detection Finding"
    assert OCSF_CATEGORY_UID == 2


# ---------------------------- Severity round-trip ------------------------


@pytest.mark.parametrize(
    ("sev", "expected_id"),
    [
        (Severity.INFO, 1),
        (Severity.LOW, 2),
        (Severity.MEDIUM, 3),
        (Severity.HIGH, 4),
        (Severity.CRITICAL, 5),
    ],
)
def test_severity_round_trip(sev: Severity, expected_id: int) -> None:
    assert severity_to_id(sev) == expected_id
    assert severity_from_id(expected_id) is sev


def test_severity_id_6_collapses_to_critical() -> None:
    """OCSF Fatal (id 6) collapses to Critical on read."""
    assert severity_from_id(6) is Severity.CRITICAL


def test_severity_from_id_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown OCSF severity_id"):
        severity_from_id(99)


# ---------------------------- FindingType --------------------------------


def test_finding_type_has_five_buckets() -> None:
    members = {ft.value for ft in FindingType}
    assert members == {
        "runtime_process",
        "runtime_file",
        "runtime_network",
        "runtime_syscall",
        "runtime_osquery",
    }


@pytest.mark.parametrize(
    ("ft", "token"),
    [
        (FindingType.PROCESS, "PROCESS"),
        (FindingType.FILE, "FILE"),
        (FindingType.NETWORK, "NETWORK"),
        (FindingType.SYSCALL, "SYSCALL"),
        (FindingType.OSQUERY, "OSQUERY"),
    ],
)
def test_finding_type_token(ft: FindingType, token: str) -> None:
    assert finding_type_token(ft) == token


# ---------------------------- AffectedHost -------------------------------


def test_affected_host_to_ocsf_round_trip() -> None:
    host = _host()
    out = host.to_ocsf()
    assert out["hostname"] == "ip-10-0-1-42"
    assert out["uid"] == "abc123def456"
    assert out["image"] == {"ref": "nginx:1.27"}
    assert out["namespace"] == "production"
    assert out["ip"] == ["10.0.1.42"]


def test_affected_host_minimal_omits_optional_fields() -> None:
    host = AffectedHost(hostname="bare", host_id="i-abc")
    out = host.to_ocsf()
    assert out == {"hostname": "bare", "uid": "i-abc"}


def test_affected_host_rejects_blank_hostname() -> None:
    with pytest.raises(ValueError):
        AffectedHost(hostname="", host_id="i-abc")


# ---------------------------- finding_id regex ---------------------------


@pytest.mark.parametrize(
    "finding_id",
    [
        "RUNTIME-PROCESS-ABC123DEF456-001-shell_in_container",
        "RUNTIME-FILE-ABC123-002-shadow_read",
        "RUNTIME-NETWORK-NODE01-003-tor-exit",
        "RUNTIME-SYSCALL-IP10-004-kmod_load",
        "RUNTIME-OSQUERY-CONT01-005-orphan_proc",
    ],
)
def test_finding_id_regex_matches_canonical_shapes(finding_id: str) -> None:
    assert FINDING_ID_RE.match(finding_id) is not None


@pytest.mark.parametrize(
    "bad_id",
    [
        "RUNTIME-PROCESS-host-001-x",  # lowercase in principal short
        "RUNTIME-UNKNOWN-ABC-001-x",  # finding-type not in enum
        "RUNT-PROCESS-ABC-001-x",  # wrong prefix
        "RUNTIME-PROCESS-ABC-1-x",  # not 3-digit sequence
        "RUNTIME-PROCESS-ABC-001-X",  # uppercase in context
        "",
    ],
)
def test_finding_id_regex_rejects_bad_shapes(bad_id: str) -> None:
    assert FINDING_ID_RE.match(bad_id) is None


# ---------------------------- build_finding ------------------------------


def _build(
    *,
    finding_id: str = "RUNTIME-PROCESS-ABC123DEF456-001-shell_in_container",
    finding_type: FindingType = FindingType.PROCESS,
    severity: Severity = Severity.HIGH,
    evidence: dict[str, Any] | None = None,
    rule_id: str | None = None,
) -> RuntimeFinding:
    return build_finding(
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        title="Test runtime finding",
        description="A test finding for the schemas test suite.",
        affected_hosts=[_host()],
        evidence=evidence if evidence is not None else {"proc_cmdline": "/bin/sh"},
        detected_at=datetime(2026, 5, 11, 12, 0, 0, tzinfo=UTC),
        envelope=_envelope(),
        rule_id=rule_id,
    )


def test_build_finding_yields_class_uid_2004() -> None:
    f = _build()
    assert f.to_dict()["class_uid"] == 2004


def test_build_finding_attaches_envelope() -> None:
    f = _build()
    assert f.envelope.tenant_id == "cust_test"


def test_build_finding_requires_at_least_one_host() -> None:
    with pytest.raises(ValueError, match="affected_hosts list must not be empty"):
        build_finding(
            finding_id="RUNTIME-PROCESS-ABC-001-x",
            finding_type=FindingType.PROCESS,
            severity=Severity.HIGH,
            title="t",
            description="d",
            affected_hosts=[],
            evidence={},
            detected_at=datetime.now(UTC),
            envelope=_envelope(),
        )


def test_build_finding_rejects_invalid_finding_id() -> None:
    with pytest.raises(ValueError, match=r"finding_id must match"):
        _build(finding_id="bogus")


def test_build_finding_records_rule_id_when_supplied() -> None:
    f = _build(rule_id="Terminal shell in container")
    assert f.to_dict()["finding_info"]["product_uid"] == "Terminal shell in container"


def test_build_finding_omits_rule_id_when_absent() -> None:
    f = _build()
    assert "product_uid" not in f.to_dict()["finding_info"]


# ---------------------------- RuntimeFinding wrapper ---------------------


def test_finding_wrapper_validates_class_uid() -> None:
    payload = _build().to_dict()
    payload["class_uid"] = 2003
    with pytest.raises(ValueError, match="expected OCSF class_uid=2004"):
        RuntimeFinding(payload)


def test_finding_wrapper_exposes_finding_type_and_hosts() -> None:
    f = _build()
    assert f.finding_type is FindingType.PROCESS
    assert "abc123def456" in f.host_ids
    assert f.evidence == {"proc_cmdline": "/bin/sh"}


# ---------------------------- FindingsReport -----------------------------


def test_findings_report_aggregates_severity_and_finding_type() -> None:
    report = FindingsReport(
        agent="runtime_threat",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_xyz",
        scan_started_at=datetime.now(UTC),
        scan_completed_at=datetime.now(UTC),
    )
    report.add_finding(
        _build(
            finding_id="RUNTIME-PROCESS-A-001-x",
            finding_type=FindingType.PROCESS,
            severity=Severity.CRITICAL,
        )
    )
    report.add_finding(
        _build(
            finding_id="RUNTIME-FILE-A-002-y",
            finding_type=FindingType.FILE,
            severity=Severity.HIGH,
        )
    )

    assert report.total == 2
    sev = report.count_by_severity()
    assert sev["critical"] == 1
    assert sev["high"] == 1
    types = report.count_by_finding_type()
    assert types["runtime_process"] == 1
    assert types["runtime_file"] == 1
    assert types["runtime_network"] == 0


def test_findings_report_empty_buckets_when_no_findings() -> None:
    report = FindingsReport(
        agent="runtime_threat",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_xyz",
        scan_started_at=datetime.now(UTC),
        scan_completed_at=datetime.now(UTC),
    )
    assert report.total == 0
    assert all(v == 0 for v in report.count_by_severity().values())
    assert all(v == 0 for v in report.count_by_finding_type().values())


# ---------------------------- short_host_id ------------------------------


def test_short_host_id_truncates_long_container_id() -> None:
    """Docker IDs are 64 hex chars; we keep the first 12."""
    long_id = "abc123def456789012345678901234567890abcdef1234567890abcdef123456"
    assert short_host_id(long_id) == "ABC123DEF456"


def test_short_host_id_strips_dashes_from_k8s_uid() -> None:
    """k8s pod UIDs are dashed UUIDs."""
    assert short_host_id("11111111-2222-3333-4444-555566667777") == "111111112222"


def test_short_host_id_falls_back_to_unknown() -> None:
    assert short_host_id("---") == "UNKNOWN"
    assert short_host_id("") == "UNKNOWN"
