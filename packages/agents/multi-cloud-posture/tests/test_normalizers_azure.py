"""Tests for `multi_cloud_posture.normalizers.azure`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from multi_cloud_posture.normalizers.azure import normalize_azure
from multi_cloud_posture.schemas import CSPMFindingType, Severity
from multi_cloud_posture.tools.azure_activity import AzureActivityRecord
from multi_cloud_posture.tools.azure_defender import AzureDefenderFinding
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="multi_cloud_posture@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )


def _defender(
    *,
    kind: str = "assessment",
    severity: str = "High",
    status: str = "Unhealthy",
    display_name: str = "Restrict public storage access",
    resource_id: str = "/subscriptions/aaa-bbb/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
    record_id: str = "/subscriptions/aaa-bbb/providers/Microsoft.Security/assessments/asmt-001",
) -> AzureDefenderFinding:
    return AzureDefenderFinding(
        kind=kind,
        record_id=record_id,
        display_name=display_name,
        severity=severity,
        status=status,
        description="x",
        resource_id=resource_id,
        subscription_id="aaa-bbb",
        assessment_type="BuiltIn",
        detected_at=NOW,
    )


def _activity(
    *,
    operation_name: str = "Microsoft.Authorization/roleAssignments/write",
    operation_class: str = "iam",
    category: str = "Administrative",
    level: str = "Informational",
    status: str = "Succeeded",
    resource_id: str = "/subscriptions/aaa-bbb/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
    record_id: str = "/subscriptions/aaa-bbb/providers/microsoft.insights/eventtypes/management/values/evt-001",
) -> AzureActivityRecord:
    return AzureActivityRecord(
        record_id=record_id,
        operation_name=operation_name,
        operation_class=operation_class,
        category=category,
        level=level,
        status=status,
        caller="user@example.com",
        resource_id=resource_id,
        subscription_id="aaa-bbb",
        resource_group="rg1",
        detected_at=NOW,
    )


# ---------------------------- empty inputs -------------------------------


def test_no_inputs_returns_empty() -> None:
    out = normalize_azure(envelope=_envelope(), scan_time=NOW)
    assert out == ()


# ---------------------------- defender ----------------------------------


@pytest.mark.parametrize(
    ("source_severity", "expected_severity"),
    [
        ("Critical", Severity.CRITICAL),
        ("High", Severity.HIGH),
        ("Medium", Severity.MEDIUM),
        ("Low", Severity.LOW),
        ("Informational", Severity.INFO),
    ],
)
def test_defender_severity_round_trip(source_severity: str, expected_severity: Severity) -> None:
    out = normalize_azure(
        defender=[_defender(severity=source_severity)],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 1
    assert out[0].severity == expected_severity


def test_defender_healthy_assessment_dropped() -> None:
    """Healthy = configured correctly; not a finding."""
    out = normalize_azure(
        defender=[_defender(status="Healthy")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert out == ()


def test_defender_finding_id_format() -> None:
    out = normalize_azure(
        defender=[_defender(display_name="Restrict public storage access")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 1
    fid = out[0].finding_id
    # F.3 regex: ^CSPM-[A-Z]+-[A-Z0-9]+-\d{3}-[a-z0-9_-]+$
    assert fid.startswith("CSPM-AZURE-DEFENDER-001-")
    assert "restrict-public-storage-access" in fid


def test_defender_finding_carries_evidence() -> None:
    out = normalize_azure(
        defender=[_defender()],
        envelope=_envelope(),
        scan_time=NOW,
    )
    raw = out[0].to_dict()
    ev = raw["evidences"][0]
    assert ev["kind"] == "assessment"
    assert ev["status"] == "Unhealthy"
    assert ev["assessment_type"] == "BuiltIn"
    assert ev["source_finding_type"] == CSPMFindingType.AZURE_DEFENDER.value


def test_defender_alert_lifts_to_ocsf() -> None:
    out = normalize_azure(
        defender=[_defender(kind="alert", severity="High", status="Active")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 1
    # Alerts always lift (no "Healthy" gate on alerts).
    raw = out[0].to_dict()
    assert raw["evidences"][0]["kind"] == "alert"


# ---------------------------- activity ----------------------------------


def test_activity_iam_record_emits_finding() -> None:
    out = normalize_azure(
        activity=[_activity(operation_class="iam")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 1
    fid = out[0].finding_id
    assert fid.startswith("CSPM-AZURE-ACTIVITY-001-")


def test_activity_network_record_emits_finding() -> None:
    out = normalize_azure(
        activity=[
            _activity(
                operation_class="network",
                operation_name="Microsoft.Network/networkSecurityGroups/write",
            )
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 1


def test_activity_storage_record_emits_finding() -> None:
    out = normalize_azure(
        activity=[
            _activity(
                operation_class="storage",
                operation_name="Microsoft.Storage/storageAccounts/write",
            )
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 1


def test_activity_keyvault_record_emits_finding() -> None:
    out = normalize_azure(
        activity=[
            _activity(
                operation_class="keyvault",
                operation_name="Microsoft.KeyVault/vaults/secrets/write",
            )
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 1


@pytest.mark.parametrize("dropped_class", ["compute", "other"])
def test_activity_compute_and_other_dropped(dropped_class: str) -> None:
    """v0.1 doesn't emit findings for compute (normal lifecycle) or other (noise)."""
    out = normalize_azure(
        activity=[_activity(operation_class=dropped_class)],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert out == ()


@pytest.mark.parametrize(
    ("level", "expected_severity"),
    [
        ("Critical", Severity.HIGH),
        ("Error", Severity.HIGH),
        ("Warning", Severity.MEDIUM),
        ("Informational", Severity.INFO),
        ("Verbose", Severity.INFO),
        ("UnknownLevel", Severity.INFO),  # default fallback
    ],
)
def test_activity_level_mapping(level: str, expected_severity: Severity) -> None:
    out = normalize_azure(
        activity=[_activity(level=level)],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 1
    assert out[0].severity == expected_severity


def test_activity_evidence_carries_operation_class() -> None:
    out = normalize_azure(
        activity=[_activity()],
        envelope=_envelope(),
        scan_time=NOW,
    )
    raw = out[0].to_dict()
    ev = raw["evidences"][0]
    assert ev["kind"] == "activity"
    assert ev["operation_class"] == "iam"
    assert ev["caller"] == "user@example.com"
    assert ev["resource_group"] == "rg1"


# ---------------------------- mixed inputs ------------------------------


def test_mixed_defender_and_activity() -> None:
    out = normalize_azure(
        defender=[_defender(severity="High"), _defender(severity="Medium")],
        activity=[_activity(operation_class="iam"), _activity(operation_class="network")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 4


def test_sequence_counters_are_per_subscription_and_source() -> None:
    out = normalize_azure(
        defender=[_defender(), _defender()],
        activity=[_activity(), _activity()],
        envelope=_envelope(),
        scan_time=NOW,
    )
    fids = sorted(f.finding_id.split("-")[3] for f in out)  # NNN segment
    # 001/002 for each source (DEFENDER + ACTIVITY).
    assert fids == ["001", "001", "002", "002"]


# ---------------------------- finding_id regex ---------------------------


def test_finding_id_matches_f3_regex() -> None:
    """Every emitted finding_id must satisfy F.3's FINDING_ID_RE."""
    from multi_cloud_posture.schemas import FINDING_ID_RE

    out = normalize_azure(
        defender=[_defender()],
        activity=[_activity()],
        envelope=_envelope(),
        scan_time=NOW,
    )
    for f in out:
        assert FINDING_ID_RE.match(f.finding_id) is not None, (
            f"finding_id {f.finding_id!r} doesn't match F.3 regex"
        )
