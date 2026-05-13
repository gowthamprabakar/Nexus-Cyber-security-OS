"""Tests for `k8s_posture.summarizer` — markdown renderer with per-namespace + CRITICAL pin."""

from __future__ import annotations

from datetime import UTC, datetime

from k8s_posture.normalizers.kube_bench import normalize_kube_bench
from k8s_posture.normalizers.manifest import normalize_manifest
from k8s_posture.normalizers.polaris import normalize_polaris
from k8s_posture.schemas import FindingsReport, Severity
from k8s_posture.summarizer import render_summary
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


def _empty_report() -> FindingsReport:
    return FindingsReport(
        agent="k8s_posture",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_001",
        scan_started_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 13, 12, 5, 0, tzinfo=UTC),
    )


def _kb(
    *,
    control_id: str = "1.1.1",
    status: str = "FAIL",
    severity_marker: str = "",
    node_type: str = "master",
) -> KubeBenchFinding:
    return KubeBenchFinding(
        control_id=control_id,
        control_text="Ensure API server pod spec file permissions",
        section_id="1.1",
        section_desc="Master Node Configuration Files",
        node_type=node_type,
        status=status,
        severity_marker=severity_marker,
        audit="stat -c %a /etc/k8s",
        actual_value="777",
        remediation="chmod 644",
        scored=True,
        detected_at=NOW,
    )


def _polaris(
    *,
    check_id: str = "runAsRootAllowed",
    severity: str = "danger",
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
) -> PolarisFinding:
    return PolarisFinding(
        check_id=check_id,
        message="Should not run as root",
        severity=severity,
        category="Security",
        workload_kind="Deployment",
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        check_level="container",
        detected_at=NOW,
    )


def _manifest(
    *,
    rule_id: str = "run-as-root",
    severity: Severity = Severity.HIGH,
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
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
        detected_at=NOW,
    )


def _build_report(
    *,
    kb: list[KubeBenchFinding] | None = None,
    polaris: list[PolarisFinding] | None = None,
    manifest: list[ManifestFinding] | None = None,
) -> FindingsReport:
    rpt = _empty_report()
    env = _envelope()
    if kb:
        for f in normalize_kube_bench(kb, envelope=env, scan_time=NOW):
            rpt.add_finding(f)
    if polaris:
        for f in normalize_polaris(polaris, envelope=env, scan_time=NOW):
            rpt.add_finding(f)
    if manifest:
        for f in normalize_manifest(manifest, envelope=env, scan_time=NOW):
            rpt.add_finding(f)
    return rpt


# ---------------------------- empty report --------------------------------


def test_empty_report_renders_no_findings_message() -> None:
    out = render_summary(_empty_report())
    assert "# Kubernetes Posture Scan" in out
    assert "Total findings: **0**" in out
    assert "No Kubernetes posture findings" in out
    # Headings for per-namespace/severity sections SHOULD NOT appear when empty.
    assert "## Per-namespace breakdown" not in out


# ---------------------------- header carries metadata ---------------------


def test_header_carries_customer_and_run_id() -> None:
    out = render_summary(_empty_report())
    assert "`cust_test`" in out
    assert "`run_001`" in out


# ---------------------------- per-namespace pin ---------------------------


def test_per_namespace_breakdown_pinned_above_severity() -> None:
    rpt = _build_report(polaris=[_polaris(namespace="production")])
    out = render_summary(rpt)
    ns_idx = out.index("## Per-namespace breakdown")
    sev_idx = out.index("## Severity breakdown")
    assert ns_idx < sev_idx


def test_per_namespace_lists_each_namespace_with_source_split() -> None:
    rpt = _build_report(
        polaris=[
            _polaris(namespace="production", check_id="a"),
            _polaris(namespace="staging", check_id="b"),
        ],
        manifest=[
            _manifest(namespace="production", rule_id="run-as-root", workload_name="frontend"),
        ],
    )
    out = render_summary(rpt)
    assert "**production**: 2 (CIS: 0 | Polaris: 1 | Manifest: 1)" in out
    assert "**staging**: 1 (CIS: 0 | Polaris: 1 | Manifest: 0)" in out


def test_per_namespace_includes_kube_bench_under_node_account() -> None:
    """kube-bench `account_id` is the node_type ('master' / 'worker'), not a real namespace —
    operators see those buckets in the same per-namespace pin (it's their cluster-control surface)."""
    rpt = _build_report(kb=[_kb(node_type="master", control_id="1.1.1")])
    out = render_summary(rpt)
    assert "**master**: 1 (CIS: 1 | Polaris: 0 | Manifest: 0)" in out


# ---------------------------- severity breakdown --------------------------


def test_severity_breakdown_includes_all_levels() -> None:
    rpt = _build_report(polaris=[_polaris()])
    out = render_summary(rpt)
    for level in ("Critical", "High", "Medium", "Low", "Info"):
        assert f"**{level}**:" in out


def test_severity_counts_match_findings() -> None:
    rpt = _build_report(
        polaris=[
            _polaris(severity="danger", check_id="a"),
            _polaris(severity="warning", check_id="b"),
        ]
    )
    out = render_summary(rpt)
    assert "**High**: 1" in out
    assert "**Medium**: 1" in out


# ---------------------------- source-type breakdown -----------------------


def test_source_type_breakdown_lists_three_buckets() -> None:
    rpt = _build_report(
        kb=[_kb()],
        polaris=[_polaris()],
        manifest=[_manifest()],
    )
    out = render_summary(rpt)
    assert "**cspm_k8s_cis**: 1" in out
    assert "**cspm_k8s_polaris**: 1" in out
    assert "**cspm_k8s_manifest**: 1" in out


# ---------------------------- CRITICAL pin --------------------------------


def test_critical_findings_pinned_above_per_severity_drilldown() -> None:
    rpt = _build_report(kb=[_kb(severity_marker="critical")])
    out = render_summary(rpt)
    crit_idx = out.index("## Critical findings")
    findings_idx = out.index("## Findings")
    assert crit_idx < findings_idx


def test_critical_pin_omitted_when_no_critical_findings() -> None:
    rpt = _build_report(polaris=[_polaris()])
    out = render_summary(rpt)
    assert "## Critical findings" not in out


def test_critical_pin_lists_finding_id_and_namespace() -> None:
    rpt = _build_report(kb=[_kb(severity_marker="critical", node_type="master")])
    out = render_summary(rpt)
    assert "CSPM-KUBERNETES-CIS-001" in out
    assert "Namespace: master" in out


# ---------------------------- per-severity sections -----------------------


def test_per_severity_sections_grouped_by_level() -> None:
    rpt = _build_report(
        polaris=[
            _polaris(severity="danger", check_id="a"),
            _polaris(severity="warning", check_id="b"),
        ]
    )
    out = render_summary(rpt)
    assert "### High (1)" in out
    assert "### Medium (1)" in out


def test_per_severity_section_includes_finding_id_title_namespace_resource() -> None:
    rpt = _build_report(polaris=[_polaris(namespace="production", workload_name="frontend")])
    out = render_summary(rpt)
    assert "CSPM-KUBERNETES-POLARIS-001" in out
    assert "runAsRootAllowed" in out
    assert "Namespace: production" in out
    assert "k8s://workload/production/Deployment/frontend" in out


# ---------------------------- determinism ---------------------------------


def test_render_is_deterministic() -> None:
    rpt = _build_report(
        polaris=[
            _polaris(check_id="a", namespace="z"),
            _polaris(check_id="b", namespace="a"),
        ]
    )
    out1 = render_summary(rpt)
    out2 = render_summary(rpt)
    assert out1 == out2


def test_namespaces_sorted_alphabetically() -> None:
    rpt = _build_report(
        polaris=[
            _polaris(namespace="zulu", check_id="a"),
            _polaris(namespace="alpha", check_id="b"),
            _polaris(namespace="mike", check_id="c"),
        ]
    )
    out = render_summary(rpt)
    # alpha must appear before mike must appear before zulu
    alpha_idx = out.index("**alpha**:")
    mike_idx = out.index("**mike**:")
    zulu_idx = out.index("**zulu**:")
    assert alpha_idx < mike_idx < zulu_idx
