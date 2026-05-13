"""Tests for `k8s_posture.normalizers.polaris`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from k8s_posture.normalizers.polaris import normalize_polaris
from k8s_posture.schemas import FINDING_ID_RE, K8sFindingType, Severity
from k8s_posture.tools.polaris import PolarisFinding
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="k8s_posture@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )


def _polaris(
    *,
    check_id: str = "runAsRootAllowed",
    message: str = "Should not be allowed to run as root",
    severity: str = "danger",
    category: str = "Security",
    workload_kind: str = "Deployment",
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
    check_level: str = "container",
) -> PolarisFinding:
    return PolarisFinding(
        check_id=check_id,
        message=message,
        severity=severity,
        category=category,
        workload_kind=workload_kind,
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        check_level=check_level,
        detected_at=NOW,
    )


# ---------------------------- empty input ---------------------------------


def test_no_inputs_returns_empty() -> None:
    assert normalize_polaris([], envelope=_envelope(), scan_time=NOW) == ()


# ---------------------------- severity mapping ----------------------------


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("danger", Severity.HIGH),
        ("warning", Severity.MEDIUM),
    ],
)
def test_severity_mapping(severity: str, expected: Severity) -> None:
    out = normalize_polaris(
        [_polaris(severity=severity)],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 1
    assert out[0].severity == expected


# ---------------------------- finding_id format ---------------------------


def test_finding_id_starts_with_kubernetes_polaris() -> None:
    out = normalize_polaris([_polaris()], envelope=_envelope(), scan_time=NOW)
    fid = out[0].finding_id
    assert fid.startswith("CSPM-KUBERNETES-POLARIS-001-")


def test_finding_id_matches_f3_regex() -> None:
    out = normalize_polaris(
        [
            _polaris(check_id="runAsRootAllowed"),
            _polaris(check_id="privilegedEscalationAllowed"),
            _polaris(check_id="cpuLimitsMissing"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    for f in out:
        assert FINDING_ID_RE.match(f.finding_id) is not None, f.finding_id


def test_finding_id_slugifies_check_id() -> None:
    """CamelCase check_id slugifies to lowercase concatenated."""
    out = normalize_polaris(
        [_polaris(check_id="runAsRootAllowed")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    fid = out[0].finding_id
    # _slugify lowercases the camelCase but doesn't add separators between cases —
    # so "runAsRootAllowed" becomes "runasrootallowed"
    assert "runasrootallowed" in fid


# ---------------------------- sequence counter ----------------------------


def test_sequence_counter_per_namespace() -> None:
    out = normalize_polaris(
        [
            _polaris(namespace="production", check_id="check-a"),
            _polaris(namespace="production", check_id="check-b"),
            _polaris(namespace="staging", check_id="check-c"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    sequences = sorted(f.finding_id.split("-")[3] for f in out)
    # production: 001, 002; staging: 001
    assert sequences == ["001", "001", "002"]


def test_sequence_counter_default_namespace_fallback() -> None:
    """namespace='' → fallback bucket 'default'."""
    out = normalize_polaris(
        [_polaris(namespace=""), _polaris(namespace="", check_id="check-b")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    sequences = sorted(f.finding_id.split("-")[3] for f in out)
    assert sequences == ["001", "002"]


# ---------------------------- AffectedResource shape ----------------------


def test_affected_resource_container_level() -> None:
    out = normalize_polaris(
        [_polaris(check_level="container", container_name="nginx")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    raw = out[0].to_dict()
    res = raw["resources"][0]
    assert res["cloud_partition"] == "kubernetes"
    assert res["region"] == "cluster"
    assert res["owner"]["account_uid"] == "production"
    assert res["type"] == "Deployment"
    # F.3's AffectedResource.to_ocsf() maps `arn` → `uid`. The arn carries the
    # container as a fragment (#nginx); the resource_id (workload/container path)
    # is preserved on the CloudPostureFinding wrapper, not the OCSF resource dict.
    assert "#nginx" in res["uid"]
    assert "k8s://workload/production/Deployment/frontend" in res["uid"]


def test_affected_resource_workload_level_no_container() -> None:
    """workload/pod-level findings have empty container_name → no /nginx suffix."""
    out = normalize_polaris(
        [_polaris(check_level="workload", container_name="")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    raw = out[0].to_dict()
    res = raw["resources"][0]
    # arn = k8s://workload/production/Deployment/frontend (no #container)
    assert "#" not in res["uid"]


# ---------------------------- evidence shape ------------------------------


def test_evidence_carries_kind_and_source() -> None:
    out = normalize_polaris([_polaris()], envelope=_envelope(), scan_time=NOW)
    raw = out[0].to_dict()
    ev = raw["evidences"][0]
    assert ev["kind"] == "polaris"
    assert ev["source_finding_type"] == K8sFindingType.POLARIS.value
    assert ev["check_id"] == "runAsRootAllowed"
    assert ev["check_level"] == "container"
    assert ev["polaris_severity"] == "danger"
    assert ev["category"] == "Security"
    assert ev["workload_kind"] == "Deployment"
    assert ev["workload_name"] == "frontend"
    assert ev["namespace"] == "production"
    assert ev["container_name"] == "nginx"


# ---------------------------- mixed inputs --------------------------------


def test_mixed_severities_emit_correct_levels() -> None:
    out = normalize_polaris(
        [
            _polaris(severity="danger", check_id="a"),
            _polaris(severity="warning", check_id="b"),
            _polaris(severity="danger", check_id="c"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    severities = sorted(f.severity.value for f in out)
    assert severities == ["high", "high", "medium"]


def test_mixed_check_levels_all_lift() -> None:
    """All three Polaris check levels (workload / pod / container) become findings."""
    out = normalize_polaris(
        [
            _polaris(check_level="workload", container_name="", check_id="a"),
            _polaris(check_level="pod", container_name="", check_id="b"),
            _polaris(check_level="container", container_name="nginx", check_id="c"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 3
    levels = {raw["evidences"][0]["check_level"] for raw in (f.to_dict() for f in out)}
    assert levels == {"workload", "pod", "container"}
