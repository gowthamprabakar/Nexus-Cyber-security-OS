"""Tests for `k8s_posture.schemas` — re-export of F.3 + D.6 enums."""

from __future__ import annotations

import pytest
from k8s_posture.schemas import (
    FINDING_ID_RE,
    OCSF_CATEGORY_UID,
    OCSF_CLASS_NAME,
    OCSF_CLASS_UID,
    AffectedResource,
    CloudPostureFinding,
    FindingsReport,
    K8sFindingType,
    Severity,
    build_finding,
    kube_bench_severity,
    polaris_severity,
    severity_from_id,
    severity_to_id,
    short_workload_token,
    source_token,
)

# ---------------------------- re-export integrity ------------------------


def test_reexports_class_uid_2003() -> None:
    """Q1 confirmed — D.6 emits the same OCSF Compliance Finding shape as F.3 + D.5."""
    assert OCSF_CLASS_UID == 2003
    assert OCSF_CLASS_NAME == "Compliance Finding"
    assert OCSF_CATEGORY_UID == 2


def test_reexports_severity_round_trip() -> None:
    assert severity_to_id(Severity.CRITICAL) == 5
    assert severity_from_id(5) == Severity.CRITICAL


def test_reexports_finding_id_regex_accepts_k8s_ids() -> None:
    """F.3's CSPM-<CLOUD>-<SVC>-<NNN>-<context> regex requires letters-only for the
    cloud segment — D.6 uses `KUBERNETES` (not `K8S`) because the `8` digit breaks
    the `[A-Z]+` part of the regex. Documented constraint, not a bug.
    """
    assert FINDING_ID_RE.match("CSPM-KUBERNETES-CIS-001-master-1-1-1") is not None
    assert FINDING_ID_RE.match("CSPM-KUBERNETES-POLARIS-001-runasroot") is not None
    assert FINDING_ID_RE.match("CSPM-KUBERNETES-MANIFEST-001-privileged-container") is not None
    # Sanity check that K8S correctly *fails* (because of the '8' digit).
    assert FINDING_ID_RE.match("CSPM-K8S-CIS-001-x") is None


def test_reexports_affected_resource_for_k8s_workload() -> None:
    """AffectedResource works for K8s pod/workload identifiers."""
    res = AffectedResource(
        cloud="kubernetes",
        account_id="my-cluster",
        region="us-east-1",
        resource_type="Pod",
        resource_id="production/frontend-7f9d8c4b6-x2k5p",
        arn="k8s://my-cluster/production/Pod/frontend-7f9d8c4b6-x2k5p",
    )
    out = res.to_ocsf()
    assert out["cloud_partition"] == "kubernetes"
    assert out["type"] == "Pod"


# ---------------------------- K8sFindingType enum ------------------------


def test_k8s_finding_type_values() -> None:
    assert K8sFindingType.CIS.value == "cspm_k8s_cis"
    assert K8sFindingType.POLARIS.value == "cspm_k8s_polaris"
    assert K8sFindingType.MANIFEST.value == "cspm_k8s_manifest"


@pytest.mark.parametrize(
    ("ft", "expected_token"),
    [
        (K8sFindingType.CIS, "CIS"),
        (K8sFindingType.POLARIS, "POLARIS"),
        (K8sFindingType.MANIFEST, "MANIFEST"),
    ],
)
def test_source_token_maps_correctly(ft: K8sFindingType, expected_token: str) -> None:
    assert source_token(ft) == expected_token


# ---------------------------- kube-bench severity map --------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("FAIL", Severity.HIGH),
        ("fail", Severity.HIGH),
        ("WARN", Severity.MEDIUM),
        ("warn", Severity.MEDIUM),
        ("PASS", None),
        ("INFO", None),
        ("UNKNOWN", None),
        ("", None),
    ],
)
def test_kube_bench_severity_map(status: str, expected: Severity | None) -> None:
    assert kube_bench_severity(status) == expected


def test_kube_bench_severity_critical_override() -> None:
    """Upstream-flagged `severity: critical` controls promote FAIL → CRITICAL."""
    assert kube_bench_severity("FAIL", severity_marker="critical") == Severity.CRITICAL
    assert kube_bench_severity("FAIL", severity_marker="Critical") == Severity.CRITICAL
    # WARN with critical marker still upgrades — defensive.
    assert kube_bench_severity("WARN", severity_marker="critical") == Severity.CRITICAL
    # Empty / unknown marker → normal mapping.
    assert kube_bench_severity("FAIL", severity_marker="") == Severity.HIGH
    assert kube_bench_severity("FAIL", severity_marker="high") == Severity.HIGH


# ---------------------------- Polaris severity map -----------------------


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("danger", Severity.HIGH),
        ("DANGER", Severity.HIGH),
        ("Danger", Severity.HIGH),
        ("warning", Severity.MEDIUM),
        ("Warning", Severity.MEDIUM),
        ("ignore", None),
        ("unknown", None),
        ("", None),
    ],
)
def test_polaris_severity_map(severity: str, expected: Severity | None) -> None:
    assert polaris_severity(severity) == expected


# ---------------------------- short_workload_token -----------------------


def test_short_workload_token_typical_k8s_pod() -> None:
    """`production/frontend-7f9d8c4b6` → tail-12 of stripped alphanumerics."""
    out = short_workload_token("production", "frontend-7f9d8c4b6")
    assert len(out) == 12
    assert all(c.isalnum() for c in out)


def test_short_workload_token_short_input() -> None:
    """Less than 12 chars → return as-is uppercased."""
    out = short_workload_token("ns", "app")
    assert out == "NSAPP"


def test_short_workload_token_empty() -> None:
    assert short_workload_token("", "") == "UNKNOWN"
    assert short_workload_token("---", "///") == "UNKNOWN"


def test_short_workload_token_distinguishes_long_prefixed_names() -> None:
    """Two workloads sharing a long prefix should still produce different tokens."""
    a = short_workload_token("production", "very-long-shared-prefix-app-frontend")
    b = short_workload_token("production", "very-long-shared-prefix-app-backend")
    # Both 12 chars but the tail differs because the suffix differs.
    assert a != b


# ---------------------------- build_finding round-trip -------------------


def test_build_finding_round_trip_via_reexport() -> None:
    """`build_finding` is re-exported from F.3; should accept K8s shape."""
    from datetime import UTC, datetime

    from shared.fabric.envelope import NexusEnvelope

    env = NexusEnvelope(
        correlation_id="corr_x",
        tenant_id="cust_test",
        agent_id="k8s_posture@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )
    affected = [
        AffectedResource(
            cloud="kubernetes",
            account_id="my-cluster",
            region="us-east-1",
            resource_type="Pod",
            resource_id="production/frontend-pod",
            arn="k8s://my-cluster/production/Pod/frontend-pod",
        )
    ]
    f = build_finding(
        finding_id="CSPM-KUBERNETES-CIS-001-pod-spec-permissions",
        rule_id="1.1.1",
        severity=Severity.HIGH,
        title="Pod spec file permissions too permissive",
        description="x",
        affected=affected,
        detected_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        envelope=env,
    )
    assert isinstance(f, CloudPostureFinding)
    assert f.finding_id == "CSPM-KUBERNETES-CIS-001-pod-spec-permissions"
    assert f.severity == Severity.HIGH


def test_findings_report_aggregates_re_exported_findings() -> None:
    from datetime import UTC, datetime

    rpt = FindingsReport(
        agent="k8s_posture",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_001",
        scan_started_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 13, 12, 1, 0, tzinfo=UTC),
    )
    assert rpt.total == 0
    counts = rpt.count_by_severity()
    assert all(v == 0 for v in counts.values())
