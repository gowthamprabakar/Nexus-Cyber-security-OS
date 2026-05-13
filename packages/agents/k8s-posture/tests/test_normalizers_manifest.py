"""Tests for `k8s_posture.normalizers.manifest`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from k8s_posture.normalizers.manifest import normalize_manifest
from k8s_posture.schemas import FINDING_ID_RE, K8sFindingType, Severity
from k8s_posture.tools.manifests import ManifestFinding
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


def _manifest_finding(
    *,
    rule_id: str = "run-as-root",
    rule_title: str = "Container running as root",
    severity: Severity = Severity.HIGH,
    workload_kind: str = "Deployment",
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
    manifest_path: str = "/manifests/frontend.yaml",
) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title=rule_title,
        severity=severity,
        workload_kind=workload_kind,
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        manifest_path=manifest_path,
        detected_at=NOW,
    )


# ---------------------------- empty input ---------------------------------


def test_no_inputs_returns_empty() -> None:
    assert normalize_manifest([], envelope=_envelope(), scan_time=NOW) == ()


# ---------------------------- severity preserved --------------------------


@pytest.mark.parametrize(
    "severity",
    [Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL, Severity.LOW],
)
def test_severity_preserved_from_reader(severity: Severity) -> None:
    """Reader pre-grades severity per rule (Q5); normalizer is a thin lift."""
    out = normalize_manifest(
        [_manifest_finding(severity=severity)],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 1
    assert out[0].severity == severity


# ---------------------------- finding_id format ---------------------------


def test_finding_id_starts_with_kubernetes_manifest() -> None:
    out = normalize_manifest([_manifest_finding()], envelope=_envelope(), scan_time=NOW)
    fid = out[0].finding_id
    assert fid.startswith("CSPM-KUBERNETES-MANIFEST-001-")


def test_finding_id_matches_f3_regex() -> None:
    out = normalize_manifest(
        [
            _manifest_finding(rule_id="run-as-root"),
            _manifest_finding(rule_id="missing-resource-limits"),
            _manifest_finding(rule_id="host-network"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    for f in out:
        assert FINDING_ID_RE.match(f.finding_id) is not None, f.finding_id


def test_finding_id_carries_rule_and_workload() -> None:
    out = normalize_manifest(
        [_manifest_finding(rule_id="run-as-root", workload_name="frontend")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    fid = out[0].finding_id
    assert "run-as-root" in fid
    assert "frontend" in fid


# ---------------------------- sequence counter ----------------------------


def test_sequence_counter_per_namespace_and_rule() -> None:
    """Each (namespace, rule_id) pair has its own sequence."""
    out = normalize_manifest(
        [
            _manifest_finding(namespace="prod", rule_id="run-as-root", workload_name="a"),
            _manifest_finding(namespace="prod", rule_id="run-as-root", workload_name="b"),
            _manifest_finding(namespace="prod", rule_id="host-network", workload_name="c"),
            _manifest_finding(namespace="staging", rule_id="run-as-root", workload_name="d"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    sequences = sorted(f.finding_id.split("-")[3] for f in out)
    # prod/run-as-root: 001, 002; prod/host-network: 001; staging/run-as-root: 001
    assert sequences == ["001", "001", "001", "002"]


def test_sequence_counter_default_namespace_fallback() -> None:
    """namespace='' → fallback bucket 'default'."""
    out = normalize_manifest(
        [
            _manifest_finding(namespace="", rule_id="run-as-root", workload_name="a"),
            _manifest_finding(namespace="", rule_id="run-as-root", workload_name="b"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    sequences = sorted(f.finding_id.split("-")[3] for f in out)
    assert sequences == ["001", "002"]


# ---------------------------- AffectedResource shape ----------------------


def test_affected_resource_container_level() -> None:
    out = normalize_manifest(
        [
            _manifest_finding(
                rule_id="run-as-root",
                workload_kind="Deployment",
                workload_name="frontend",
                namespace="production",
                container_name="nginx",
            )
        ],
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
    # container as a fragment (#nginx).
    assert "#nginx" in res["uid"]
    assert "k8s://manifest/production/Deployment/frontend" in res["uid"]


def test_affected_resource_pod_level_no_container() -> None:
    """Pod-level rules (e.g. host-network) have empty container_name → no #container suffix."""
    out = normalize_manifest(
        [
            _manifest_finding(
                rule_id="host-network",
                workload_kind="Deployment",
                workload_name="frontend",
                namespace="production",
                container_name="",
            )
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    raw = out[0].to_dict()
    res = raw["resources"][0]
    assert "#" not in res["uid"]
    assert res["uid"] == "k8s://manifest/production/Deployment/frontend"


# ---------------------------- evidence shape ------------------------------


def test_evidence_carries_kind_and_source() -> None:
    out = normalize_manifest(
        [_manifest_finding(manifest_path="/manifests/frontend.yaml")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    raw = out[0].to_dict()
    ev = raw["evidences"][0]
    assert ev["kind"] == "manifest"
    assert ev["source_finding_type"] == K8sFindingType.MANIFEST.value
    assert ev["rule_id"] == "run-as-root"
    assert ev["rule_title"] == "Container running as root"
    assert ev["workload_kind"] == "Deployment"
    assert ev["workload_name"] == "frontend"
    assert ev["namespace"] == "production"
    assert ev["container_name"] == "nginx"
    assert ev["manifest_path"] == "/manifests/frontend.yaml"


# ---------------------------- mixed inputs --------------------------------


def test_mixed_severities_preserved() -> None:
    out = normalize_manifest(
        [
            _manifest_finding(rule_id="run-as-root", severity=Severity.HIGH, workload_name="a"),
            _manifest_finding(
                rule_id="missing-resource-limits",
                severity=Severity.MEDIUM,
                workload_name="b",
            ),
            _manifest_finding(rule_id="host-pid", severity=Severity.HIGH, workload_name="c"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    severities = sorted(f.severity.value for f in out)
    assert severities == ["high", "high", "medium"]


def test_pod_and_container_level_rules_coexist() -> None:
    """Pod-level (host-network) and container-level (run-as-root) findings on the same
    workload both lift to distinct OCSF findings."""
    out = normalize_manifest(
        [
            _manifest_finding(
                rule_id="host-network",
                workload_name="frontend",
                container_name="",
            ),
            _manifest_finding(
                rule_id="run-as-root",
                workload_name="frontend",
                container_name="nginx",
            ),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(out) == 2
    rule_ids = {raw["evidences"][0]["rule_id"] for raw in (f.to_dict() for f in out)}
    assert rule_ids == {"host-network", "run-as-root"}
