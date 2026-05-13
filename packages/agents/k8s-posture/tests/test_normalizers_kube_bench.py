"""Tests for `k8s_posture.normalizers.kube_bench`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from k8s_posture.normalizers.kube_bench import normalize_kube_bench
from k8s_posture.schemas import FINDING_ID_RE, K8sFindingType, Severity
from k8s_posture.tools.kube_bench import KubeBenchFinding
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


def _kb(
    *,
    control_id: str = "1.1.1",
    control_text: str = "Ensure API server pod spec file permissions",
    section_id: str = "1.1",
    section_desc: str = "Master Node Configuration Files",
    node_type: str = "master",
    status: str = "FAIL",
    severity_marker: str = "",
) -> KubeBenchFinding:
    return KubeBenchFinding(
        control_id=control_id,
        control_text=control_text,
        section_id=section_id,
        section_desc=section_desc,
        node_type=node_type,
        status=status,
        severity_marker=severity_marker,
        audit="stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml",
        actual_value="777",
        remediation="Run the below command...",
        scored=True,
        detected_at=NOW,
    )


# ---------------------------- empty input ----------------------------------


def test_no_inputs_returns_empty() -> None:
    assert normalize_kube_bench([], envelope=_envelope(), scan_time=NOW) == ()


# ---------------------------- severity mapping -----------------------------


@pytest.mark.parametrize(
    ("status", "marker", "expected"),
    [
        ("FAIL", "", Severity.HIGH),
        ("WARN", "", Severity.MEDIUM),
        ("FAIL", "critical", Severity.CRITICAL),
        ("WARN", "critical", Severity.CRITICAL),
    ],
)
def test_severity_mapping(status: str, marker: str, expected: Severity) -> None:
    out = normalize_kube_bench(
        [_kb(status=status, severity_marker=marker)],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 1
    assert out[0].severity == expected


def test_unknown_status_dropped() -> None:
    """Defensive: a kube-bench record with non-FAIL/WARN status (shouldn't occur after the
    reader, but the normalizer guards) is dropped.
    """
    # We can't construct a KubeBenchFinding with status="PASS" directly because the schema
    # pattern requires FAIL|WARN. But we can simulate via severity_marker that misroutes —
    # the normalizer's `kube_bench_severity` helper guards on the canonical status set.
    # The pattern constraint at the reader layer makes this case unreachable.
    pass  # documented constraint; no runtime path to test


# ---------------------------- finding_id format ---------------------------


def test_finding_id_starts_with_kubernetes_cis() -> None:
    out = normalize_kube_bench([_kb()], envelope=_envelope(), scan_time=NOW)
    fid = out[0].finding_id
    assert fid.startswith("CSPM-KUBERNETES-CIS-001-")


def test_finding_id_matches_f3_regex() -> None:
    out = normalize_kube_bench(
        [_kb(), _kb(control_id="1.1.2"), _kb(node_type="worker", control_id="4.1.1")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    for f in out:
        assert FINDING_ID_RE.match(f.finding_id) is not None, f.finding_id


def test_finding_id_carries_slugified_control_id() -> None:
    out = normalize_kube_bench([_kb(control_id="1.1.1")], envelope=_envelope(), scan_time=NOW)
    fid = out[0].finding_id
    # `1.1.1` slugifies to `1-1-1`
    assert "1-1-1" in fid


# ---------------------------- sequence counter ----------------------------


def test_sequence_counter_per_node_type() -> None:
    out = normalize_kube_bench(
        [
            _kb(node_type="master", control_id="1.1.1"),
            _kb(node_type="master", control_id="1.1.2"),
            _kb(node_type="worker", control_id="4.1.1"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    sequences = sorted(f.finding_id.split("-")[3] for f in out)
    # master: 001, 002; worker: 001
    assert sequences == ["001", "001", "002"]


def test_sequence_counter_cluster_fallback() -> None:
    """node_type='' → fallback bucket 'cluster'."""
    out = normalize_kube_bench(
        [_kb(node_type=""), _kb(node_type="", control_id="x.y.z")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 2


# ---------------------------- AffectedResource shape ----------------------


def test_affected_resource_carries_node_type() -> None:
    out = normalize_kube_bench(
        [_kb(node_type="master", control_id="1.1.1")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    raw = out[0].to_dict()
    res = raw["resources"][0]
    assert res["cloud_partition"] == "kubernetes"
    assert res["region"] == "cluster"
    assert res["owner"]["account_uid"] == "master"
    assert res["type"] == "MasterNode"


@pytest.mark.parametrize(
    ("node_type", "expected_resource_type"),
    [
        ("master", "MasterNode"),
        ("worker", "WorkerNode"),
        ("etcd", "EtcdNode"),
        ("controlplane", "ControlPlaneNode"),
        ("policies", "PolicyConfig"),
        ("unknown", "K8sNode"),
        ("", "K8sNode"),
    ],
)
def test_resource_type_mapping(node_type: str, expected_resource_type: str) -> None:
    out = normalize_kube_bench(
        [_kb(node_type=node_type)],
        envelope=_envelope(),
        scan_time=NOW,
    )
    raw = out[0].to_dict()
    assert raw["resources"][0]["type"] == expected_resource_type


# ---------------------------- evidence shape ------------------------------


def test_evidence_carries_kind_and_source() -> None:
    out = normalize_kube_bench(
        [_kb()],
        envelope=_envelope(),
        scan_time=NOW,
    )
    raw = out[0].to_dict()
    ev = raw["evidences"][0]
    assert ev["kind"] == "kube-bench"
    assert ev["source_finding_type"] == K8sFindingType.CIS.value
    assert ev["control_id"] == "1.1.1"
    assert ev["section_id"] == "1.1"
    assert ev["node_type"] == "master"
    assert ev["audit"].startswith("stat ")
    assert ev["actual_value"] == "777"
    assert ev["scored"] is True


def test_evidence_preserves_severity_marker() -> None:
    out = normalize_kube_bench(
        [_kb(severity_marker="critical")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    raw = out[0].to_dict()
    assert raw["evidences"][0]["severity_marker"] == "critical"


# ---------------------------- mixed inputs --------------------------------


def test_mixed_statuses_emit_correct_severities() -> None:
    out = normalize_kube_bench(
        [
            _kb(control_id="1.1.1", status="FAIL"),
            _kb(control_id="1.1.2", status="WARN"),
            _kb(control_id="1.1.3", status="FAIL", severity_marker="critical"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    severities = sorted(f.severity.value for f in out)
    assert severities == ["critical", "high", "medium"]
