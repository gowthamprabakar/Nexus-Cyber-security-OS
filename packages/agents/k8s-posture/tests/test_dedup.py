"""Tests for `k8s_posture.dedup.dedupe_overlapping`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from k8s_posture.dedup import dedupe_overlapping
from k8s_posture.normalizers.kube_bench import normalize_kube_bench
from k8s_posture.normalizers.manifest import normalize_manifest
from k8s_posture.normalizers.polaris import normalize_polaris
from k8s_posture.schemas import Severity
from k8s_posture.tools.kube_bench import KubeBenchFinding
from k8s_posture.tools.manifests import ManifestFinding
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
    severity: str = "danger",
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
    detected_at: datetime = NOW,
) -> PolarisFinding:
    return PolarisFinding(
        check_id=check_id,
        message="Should not be allowed to run as root",
        severity=severity,
        category="Security",
        workload_kind="Deployment",
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        check_level="container",
        detected_at=detected_at,
    )


def _manifest(
    *,
    rule_id: str = "run-as-root",
    severity: Severity = Severity.HIGH,
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
    detected_at: datetime = NOW,
) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title="Container running as root",
        severity=severity,
        workload_kind="Deployment",
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        manifest_path="/manifests/frontend.yaml",
        detected_at=detected_at,
    )


def _kb(
    *,
    control_id: str = "1.1.1",
    status: str = "FAIL",
    severity_marker: str = "",
    node_type: str = "master",
    detected_at: datetime = NOW,
) -> KubeBenchFinding:
    return KubeBenchFinding(
        control_id=control_id,
        control_text="Ensure API server pod spec file permissions",
        section_id="1.1",
        section_desc="Master Node Configuration Files",
        node_type=node_type,
        status=status,
        severity_marker=severity_marker,
        audit="stat -c %a /etc/k8s/manifests/kube-apiserver.yaml",
        actual_value="777",
        remediation="chmod 644",
        scored=True,
        detected_at=detected_at,
    )


# ---------------------------- empty input ---------------------------------


def test_empty_input_returns_empty() -> None:
    assert dedupe_overlapping([]) == ()


# ---------------------------- no duplicates -------------------------------


def test_distinct_findings_passthrough() -> None:
    """Findings with distinct keys are returned unchanged."""
    findings = normalize_polaris(
        [
            _polaris(check_id="a", workload_name="w1"),
            _polaris(check_id="b", workload_name="w2"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    out = dedupe_overlapping(findings)
    assert len(out) == 2
    assert {f.finding_id for f in out} == {f.finding_id for f in findings}


# ---------------------------- same-tool dedup -----------------------------


def test_same_tool_duplicate_within_window_collapses() -> None:
    """Two Polaris findings on the same workload+rule within 5min → one finding."""
    findings = normalize_polaris(
        [
            _polaris(check_id="runAsRootAllowed", detected_at=NOW),
            _polaris(
                check_id="runAsRootAllowed",
                detected_at=NOW + timedelta(minutes=2),
            ),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(findings) == 2  # before dedup
    out = dedupe_overlapping(findings)
    assert len(out) == 1


def test_same_tool_duplicate_outside_window_kept_separate() -> None:
    """Two Polaris findings on same workload+rule but >5min apart → both kept."""
    findings = normalize_polaris(
        [
            _polaris(check_id="runAsRootAllowed", detected_at=NOW),
            _polaris(
                check_id="runAsRootAllowed",
                detected_at=NOW + timedelta(minutes=10),
            ),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    out = dedupe_overlapping(findings)
    assert len(out) == 2


# ---------------------------- severity selection --------------------------


def test_highest_severity_wins() -> None:
    """When two findings collide, the higher severity is preserved."""
    medium = normalize_polaris(
        [_polaris(severity="warning")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    high = normalize_polaris(
        [_polaris(severity="danger")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    # Same workload + rule + bucket — should collapse.
    out = dedupe_overlapping(medium + high)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_severity_tiebreak_first_seen_wins() -> None:
    """Equal severities — first finding's ID is preserved."""
    first = normalize_polaris(
        [_polaris(severity="danger")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    second = normalize_polaris(
        [_polaris(severity="danger", detected_at=NOW + timedelta(minutes=1))],
        envelope=_envelope(),
        scan_time=NOW,
    )
    out = dedupe_overlapping(first + second)
    assert len(out) == 1
    assert out[0].finding_id == first[0].finding_id


# ---------------------------- dedup_sources evidence ----------------------


def test_dedup_records_collapsed_sources_in_evidence() -> None:
    """Survivor's evidence carries a `dedup_sources` list with collapsed finding_ids."""
    first = normalize_polaris(
        [_polaris(severity="warning")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    second = normalize_polaris(
        [_polaris(severity="danger", detected_at=NOW + timedelta(minutes=2))],
        envelope=_envelope(),
        scan_time=NOW,
    )
    out = dedupe_overlapping(first + second)
    assert len(out) == 1
    survivor = out[0].to_dict()
    evidences = survivor["evidences"]
    # original evidence + one dedup-sources evidence
    dedup_entries = [e for e in evidences if e.get("kind") == "dedup-sources"]
    assert len(dedup_entries) == 1
    sources = dedup_entries[0]["finding_ids"]
    expected_collapsed = first[0].finding_id  # the loser
    assert expected_collapsed in sources


# ---------------------------- container scoping ---------------------------


def test_distinct_containers_in_same_workload_kept_separate() -> None:
    """`run-as-root` on `nginx` vs `sidecar` containers — different keys → both kept."""
    findings = normalize_polaris(
        [
            _polaris(check_id="runAsRootAllowed", container_name="nginx"),
            _polaris(check_id="runAsRootAllowed", container_name="sidecar"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    out = dedupe_overlapping(findings)
    assert len(out) == 2


# ---------------------------- cross-namespace -----------------------------


def test_same_rule_in_different_namespaces_kept_separate() -> None:
    """A rule firing in `production` and `staging` are independent."""
    findings = normalize_polaris(
        [
            _polaris(check_id="runAsRootAllowed", namespace="production"),
            _polaris(check_id="runAsRootAllowed", namespace="staging"),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    out = dedupe_overlapping(findings)
    assert len(out) == 2


# ---------------------------- cross-tool dedup boundary -------------------


def test_kube_bench_and_polaris_do_not_collapse() -> None:
    """Different scan domains (cluster controls vs workloads) never collide."""
    kb_findings = normalize_kube_bench(
        [_kb(control_id="1.1.1")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    pol_findings = normalize_polaris(
        [_polaris(check_id="runAsRootAllowed")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    out = dedupe_overlapping(kb_findings + pol_findings)
    # Distinct resource arns + distinct rule_ids → both kept.
    assert len(out) == 2


def test_manifest_and_polaris_same_rule_keep_both_by_default() -> None:
    """Even when manifest and Polaris flag the same posture issue, rule_ids differ
    (`run-as-root` vs `runAsRootAllowed`) so v0.1 keeps both — no semantic ontology
    map is implemented yet. This documents the current behaviour."""
    man = normalize_manifest(
        [_manifest(rule_id="run-as-root")], envelope=_envelope(), scan_time=NOW
    )
    pol = normalize_polaris(
        [_polaris(check_id="runAsRootAllowed")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    out = dedupe_overlapping(man + pol)
    assert len(out) == 2


# ---------------------------- determinism ---------------------------------


def test_dedup_is_deterministic_order_preserving() -> None:
    """Survivors appear in input order (first-seen wins on ties)."""
    a = normalize_polaris(
        [_polaris(check_id="a")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    b = normalize_polaris(
        [_polaris(check_id="b")],
        envelope=_envelope(),
        scan_time=NOW,
    )
    out = dedupe_overlapping(a + b)
    assert [f.finding_id for f in out] == [a[0].finding_id, b[0].finding_id]


# ---------------------------- custom window -------------------------------


def test_custom_window_widens_collapse() -> None:
    """A 30-minute window collapses findings that 5-min would have split."""
    findings = normalize_polaris(
        [
            _polaris(check_id="x", detected_at=NOW),
            _polaris(check_id="x", detected_at=NOW + timedelta(minutes=10)),
        ],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(dedupe_overlapping(findings)) == 2  # default 5min — kept separate
    assert len(dedupe_overlapping(findings, window=timedelta(minutes=30))) == 1
