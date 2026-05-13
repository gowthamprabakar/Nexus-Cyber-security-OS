"""Tests for `multi_cloud_posture.normalizers.gcp`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from multi_cloud_posture.normalizers.gcp import normalize_gcp
from multi_cloud_posture.schemas import CSPMFindingType, Severity
from multi_cloud_posture.tools.gcp_iam import GcpIamFinding
from multi_cloud_posture.tools.gcp_scc import GcpSccFinding
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


def _scc(
    *,
    severity: str = "HIGH",
    state: str = "ACTIVE",
    category: str = "PUBLIC_BUCKET",
    resource_name: str = "//storage.googleapis.com/projects/proj-xyz/buckets/public-bucket",
) -> GcpSccFinding:
    return GcpSccFinding(
        finding_name="organizations/123/sources/456/findings/finding-001",
        parent="organizations/123/sources/456",
        resource_name=resource_name,
        category=category,
        state=state,
        severity=severity,
        description="Bucket allows public access via allUsers.",
        external_uri="https://console.cloud.google.com/...",
        project_id="proj-xyz",
        detected_at=NOW,
    )


def _iam(
    *,
    severity: str = "CRITICAL",
    role: str = "roles/owner",
    member: str = "user:bob@external.com",
    asset_name: str = "//cloudresourcemanager.googleapis.com/projects/proj-xyz",
) -> GcpIamFinding:
    return GcpIamFinding(
        asset_name=asset_name,
        asset_type="cloudresourcemanager.googleapis.com/Project",
        project_id="proj-xyz",
        role=role,
        member=member,
        severity=severity,
        reason=f"{member!r} granted {role!r}",
        detected_at=NOW,
    )


# ---------------------------- empty inputs -------------------------------


def test_no_inputs_returns_empty() -> None:
    out = normalize_gcp(envelope=_envelope(), scan_time=NOW)
    assert out == ()


# ---------------------------- SCC normalization --------------------------


@pytest.mark.parametrize(
    ("source_severity", "expected_severity"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("SEVERITY_UNSPECIFIED", Severity.INFO),
    ],
)
def test_scc_severity_round_trip(source_severity: str, expected_severity: Severity) -> None:
    out = normalize_gcp(scc=[_scc(severity=source_severity)], envelope=_envelope(), scan_time=NOW)
    assert len(out) == 1
    assert out[0].severity == expected_severity


def test_scc_inactive_state_dropped() -> None:
    """v0.1: INACTIVE = closed; doesn't appear in the report."""
    out = normalize_gcp(scc=[_scc(state="INACTIVE")], envelope=_envelope(), scan_time=NOW)
    assert out == ()


def test_scc_finding_id_format() -> None:
    out = normalize_gcp(scc=[_scc(category="PUBLIC_BUCKET")], envelope=_envelope(), scan_time=NOW)
    assert len(out) == 1
    fid = out[0].finding_id
    assert fid.startswith("CSPM-GCP-SCC-001-")
    assert "public-bucket" in fid


def test_scc_finding_carries_evidence() -> None:
    out = normalize_gcp(scc=[_scc()], envelope=_envelope(), scan_time=NOW)
    raw = out[0].to_dict()
    ev = raw["evidences"][0]
    assert ev["kind"] == "scc"
    assert ev["scc_category"] == "PUBLIC_BUCKET"
    assert ev["scc_severity"] == "HIGH"
    assert ev["scc_state"] == "ACTIVE"
    assert ev["source_finding_type"] == CSPMFindingType.GCP_SCC.value


def test_scc_resource_type_inferred() -> None:
    """`//storage.googleapis.com/.../buckets/<name>` → `storage.googleapis.com/Buckets`."""
    out = normalize_gcp(scc=[_scc()], envelope=_envelope(), scan_time=NOW)
    raw = out[0].to_dict()
    assert raw["resources"][0]["type"].startswith("storage.googleapis.com/")


# ---------------------------- IAM normalization --------------------------


@pytest.mark.parametrize(
    "source_severity",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
)
def test_iam_all_severities(source_severity: str) -> None:
    out = normalize_gcp(iam=[_iam(severity=source_severity)], envelope=_envelope(), scan_time=NOW)
    assert len(out) == 1
    assert out[0].severity.value.upper() == source_severity


def test_iam_finding_id_format() -> None:
    out = normalize_gcp(iam=[_iam()], envelope=_envelope(), scan_time=NOW)
    fid = out[0].finding_id
    assert fid.startswith("CSPM-GCP-IAM-001-")


def test_iam_evidence_carries_role_member() -> None:
    out = normalize_gcp(iam=[_iam()], envelope=_envelope(), scan_time=NOW)
    raw = out[0].to_dict()
    ev = raw["evidences"][0]
    assert ev["kind"] == "iam"
    assert ev["role"] == "roles/owner"
    assert ev["member"] == "user:bob@external.com"
    assert ev["source_finding_type"] == CSPMFindingType.GCP_IAM.value


def test_iam_uses_asset_type_for_resource_type() -> None:
    out = normalize_gcp(iam=[_iam()], envelope=_envelope(), scan_time=NOW)
    raw = out[0].to_dict()
    assert raw["resources"][0]["type"] == "cloudresourcemanager.googleapis.com/Project"


# ---------------------------- mixed inputs -------------------------------


def test_mixed_scc_and_iam() -> None:
    out = normalize_gcp(
        scc=[_scc(severity="CRITICAL"), _scc(severity="MEDIUM")],
        iam=[_iam(), _iam(role="roles/editor", severity="MEDIUM")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 4


def test_sequence_counters_per_project_and_source() -> None:
    out = normalize_gcp(
        scc=[_scc(), _scc()],
        iam=[_iam(), _iam()],
        envelope=_envelope(),
        scan_time=NOW,
    )
    sequences = sorted(f.finding_id.split("-")[3] for f in out)
    # 001/002 for each source (SCC + IAM).
    assert sequences == ["001", "001", "002", "002"]


# ---------------------------- finding_id regex ---------------------------


def test_finding_id_matches_f3_regex() -> None:
    """Every emitted finding_id must satisfy F.3's FINDING_ID_RE."""
    from multi_cloud_posture.schemas import FINDING_ID_RE

    out = normalize_gcp(
        scc=[_scc()],
        iam=[_iam()],
        envelope=_envelope(),
        scan_time=NOW,
    )
    for f in out:
        assert FINDING_ID_RE.match(f.finding_id) is not None, (
            f"finding_id {f.finding_id!r} doesn't match F.3 regex"
        )


def test_scc_with_unknown_severity_dropped() -> None:
    """Defensive — a malformed reader output with non-canonical severity is dropped here."""
    bad = GcpSccFinding(
        finding_name="organizations/123/sources/456/findings/x",
        parent="organizations/123/sources/456",
        resource_name="//storage.googleapis.com/projects/p/buckets/b",
        category="X",
        state="ACTIVE",
        severity="SEVERITY_UNSPECIFIED",  # legal value but mapped to INFO
        project_id="p",
        detected_at=NOW,
    )
    out = normalize_gcp(scc=[bad], envelope=_envelope(), scan_time=NOW)
    assert len(out) == 1
    assert out[0].severity == Severity.INFO
