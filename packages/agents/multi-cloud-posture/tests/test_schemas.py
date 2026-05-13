"""Tests for `multi_cloud_posture.schemas` — re-export of F.3 + D.5 enums."""

from __future__ import annotations

import pytest
from multi_cloud_posture.schemas import (
    FINDING_ID_RE,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    AffectedResource,
    CloudPostureFinding,
    CloudProvider,
    CSPMFindingType,
    FindingsReport,
    Severity,
    build_finding,
    cloud_provider_for,
    severity_from_id,
    severity_to_id,
    short_resource_token,
    source_token,
)

# ---------------------------- re-export integrity ------------------------


def test_reexports_class_uid_2003() -> None:
    """Q1 confirmed — D.5 emits the same OCSF Compliance Finding shape as F.3."""
    assert OCSF_CLASS_UID == 2003
    assert OCSF_CLASS_NAME == "Compliance Finding"
    assert OCSF_CATEGORY_UID == 2


def test_reexports_severity_round_trip() -> None:
    """Severity enum + helpers come straight from F.3."""
    assert severity_to_id(Severity.CRITICAL) == 5
    assert severity_from_id(5) == Severity.CRITICAL


def test_reexports_finding_id_regex() -> None:
    """F.3's `CSPM-<CLOUD>-<SVC>-<NNN>-<context>` regex works for Azure/GCP too."""
    assert FINDING_ID_RE.match("CSPM-AZURE-DEFENDER-001-overpermissive_iam") is not None
    assert FINDING_ID_RE.match("CSPM-GCP-SCC-001-public-bucket") is not None
    # F.3-shaped AWS IDs still match — the regex is cloud-agnostic.
    assert FINDING_ID_RE.match("CSPM-AWS-IAM-001-root_mfa") is not None


def test_reexports_affected_resource_is_generic() -> None:
    """`AffectedResource` works for Azure subscription IDs and GCP project IDs too."""
    azure_res = AffectedResource(
        cloud="azure",
        account_id="00000000-0000-0000-0000-000000000000",
        region="eastus",
        resource_type="VirtualMachine",
        resource_id="/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
        arn="/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
    )
    out = azure_res.to_ocsf()
    assert out["cloud_partition"] == "azure"
    assert out["region"] == "eastus"

    gcp_res = AffectedResource(
        cloud="gcp",
        account_id="my-gcp-project",
        region="us-central1",
        resource_type="ComputeInstance",
        resource_id="//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/instance-1",
        arn="//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/instance-1",
    )
    out = gcp_res.to_ocsf()
    assert out["cloud_partition"] == "gcp"


# ---------------------------- CloudProvider enum -------------------------


def test_cloud_provider_values() -> None:
    assert CloudProvider.AZURE.value == "azure"
    assert CloudProvider.GCP.value == "gcp"


# ---------------------------- CSPMFindingType enum -----------------------


def test_cspm_finding_type_values() -> None:
    assert CSPMFindingType.AZURE_DEFENDER.value == "cspm_azure_defender"
    assert CSPMFindingType.AZURE_ACTIVITY.value == "cspm_azure_activity"
    assert CSPMFindingType.GCP_SCC.value == "cspm_gcp_scc"
    assert CSPMFindingType.GCP_IAM.value == "cspm_gcp_iam"


@pytest.mark.parametrize(
    ("ft", "expected_cloud"),
    [
        (CSPMFindingType.AZURE_DEFENDER, CloudProvider.AZURE),
        (CSPMFindingType.AZURE_ACTIVITY, CloudProvider.AZURE),
        (CSPMFindingType.GCP_SCC, CloudProvider.GCP),
        (CSPMFindingType.GCP_IAM, CloudProvider.GCP),
    ],
)
def test_cloud_provider_for_maps_correctly(
    ft: CSPMFindingType, expected_cloud: CloudProvider
) -> None:
    assert cloud_provider_for(ft) == expected_cloud


@pytest.mark.parametrize(
    ("ft", "expected_token"),
    [
        (CSPMFindingType.AZURE_DEFENDER, "DEFENDER"),
        (CSPMFindingType.AZURE_ACTIVITY, "ACTIVITY"),
        (CSPMFindingType.GCP_SCC, "SCC"),
        (CSPMFindingType.GCP_IAM, "IAM"),
    ],
)
def test_source_token_maps_correctly(ft: CSPMFindingType, expected_token: str) -> None:
    assert source_token(ft) == expected_token


# ---------------------------- short_resource_token -----------------------


def test_short_resource_token_azure_path() -> None:
    rid = "/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
    out = short_resource_token(rid)
    # tail 12 chars of the stripped alphanumeric
    assert len(out) == 12
    assert out.endswith("VM1") or "VM" in out


def test_short_resource_token_gcp_path() -> None:
    rid = "//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/instance-1"
    out = short_resource_token(rid)
    assert len(out) == 12


def test_short_resource_token_short_input() -> None:
    """Less than 12 chars → return as-is."""
    assert short_resource_token("vm1") == "VM1"


def test_short_resource_token_empty() -> None:
    assert short_resource_token("") == "UNKNOWN"
    assert short_resource_token("---///") == "UNKNOWN"


# ---------------------------- build_finding round-trip (re-exported) -----


def test_build_finding_round_trip_via_reexport() -> None:
    """`build_finding` is re-exported verbatim from F.3; it should accept Azure shape."""
    from datetime import UTC, datetime

    from shared.fabric.envelope import NexusEnvelope

    env = NexusEnvelope(
        correlation_id="corr_x",
        tenant_id="cust_test",
        agent_id="multi_cloud_posture@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )
    affected = [
        AffectedResource(
            cloud="azure",
            account_id="00000000-0000-0000-0000-000000000000",
            region="eastus",
            resource_type="VirtualMachine",
            resource_id="/subscriptions/aaa/vm1",
            arn="/subscriptions/aaa/vm1",
        )
    ]
    f = build_finding(
        finding_id="CSPM-AZURE-DEFENDER-001-overpermissive",
        rule_id="DEFENDER_RULE_001",
        severity=Severity.HIGH,
        title="Overly permissive IAM",
        description="x",
        affected=affected,
        detected_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        envelope=env,
    )
    assert isinstance(f, CloudPostureFinding)
    assert f.finding_id == "CSPM-AZURE-DEFENDER-001-overpermissive"
    assert f.severity == Severity.HIGH


def test_findings_report_aggregates_re_exported_findings() -> None:
    """`FindingsReport` is re-exported; D.5 uses it verbatim."""
    from datetime import UTC, datetime

    rpt = FindingsReport(
        agent="multi_cloud_posture",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_001",
        scan_started_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 13, 12, 1, 0, tzinfo=UTC),
    )
    assert rpt.total == 0
    counts = rpt.count_by_severity()
    assert all(v == 0 for v in counts.values())
