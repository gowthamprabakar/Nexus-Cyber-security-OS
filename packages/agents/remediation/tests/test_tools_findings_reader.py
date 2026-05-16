"""Tests for `remediation.tools.findings_reader` — Stage-1 ingest.

Strategy: produce real findings.json files by round-tripping through D.6's
`normalize_manifest` → `FindingsReport.add_finding` → `model_dump_json`.
This guarantees A.1 reads whatever D.6 actually emits — if D.6 ever
changes its wire format, these tests catch the drift.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cloud_posture.schemas import FindingsReport, Severity
from k8s_posture.normalizers.manifest import normalize_manifest
from k8s_posture.tools.manifests import ManifestFinding
from remediation.tools.findings_reader import (
    FindingsReaderError,
    read_findings,
)
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)


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
    severity: Severity = Severity.HIGH,
    workload_kind: str = "Deployment",
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title=rule_id.replace("-", " ").title(),
        severity=severity,
        workload_kind=workload_kind,
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        manifest_path="cluster:///production/Deployment/frontend",
        detected_at=NOW,
    )


def _write_findings_json(
    tmp_path: Path,
    manifest_findings: list[ManifestFinding],
) -> Path:
    """Write a real findings.json by round-tripping through D.6's normalizer.

    Returns the path. Operators reading the test see the SAME bytes the
    real agent would have written.
    """
    cp_findings = normalize_manifest(
        manifest_findings,
        envelope=_envelope(),
        scan_time=NOW,
    )
    report = FindingsReport(
        agent="k8s_posture",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_001",
        scan_started_at=NOW,
        scan_completed_at=NOW,
    )
    for f in cp_findings:
        report.add_finding(f)
    path = tmp_path / "findings.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


# ---------------------------- happy path ----------------------------------


@pytest.mark.asyncio
async def test_read_findings_round_trips_a_single_manifest_finding(tmp_path: Path) -> None:
    """The findings.json A.1 reads should reconstruct the same ManifestFinding D.6 produced."""
    original = _manifest_finding(rule_id="run-as-root", workload_name="frontend")
    path = _write_findings_json(tmp_path, [original])

    result = await read_findings(path=path)
    assert len(result) == 1
    reconstructed = result[0]
    assert reconstructed.rule_id == original.rule_id
    assert reconstructed.rule_title == original.rule_title
    assert reconstructed.severity == original.severity
    assert reconstructed.workload_kind == original.workload_kind
    assert reconstructed.workload_name == original.workload_name
    assert reconstructed.namespace == original.namespace
    assert reconstructed.container_name == original.container_name


@pytest.mark.asyncio
async def test_read_findings_preserves_order(tmp_path: Path) -> None:
    findings = [
        _manifest_finding(rule_id="run-as-root", workload_name="a"),
        _manifest_finding(rule_id="missing-resource-limits", workload_name="b"),
        _manifest_finding(rule_id="image-pull-policy-not-always", workload_name="c"),
    ]
    path = _write_findings_json(tmp_path, findings)

    result = await read_findings(path=path)
    assert [f.workload_name for f in result] == ["a", "b", "c"]


@pytest.mark.asyncio
async def test_read_findings_reconstructs_severity_correctly(tmp_path: Path) -> None:
    """OCSF wraps severity as severity_id (int 1-5); the reader must un-wrap correctly."""
    path = _write_findings_json(
        tmp_path,
        [
            _manifest_finding(severity=Severity.HIGH, workload_name="hi"),
            _manifest_finding(severity=Severity.MEDIUM, workload_name="med"),
        ],
    )
    result = await read_findings(path=path)
    by_name = {f.workload_name: f for f in result}
    assert by_name["hi"].severity == Severity.HIGH
    assert by_name["med"].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_read_findings_preserves_detected_at_to_second(tmp_path: Path) -> None:
    """OCSF stores time as ms-precision int; the reader rebuilds a tz-aware datetime."""
    path = _write_findings_json(tmp_path, [_manifest_finding()])
    result = await read_findings(path=path)
    assert result[0].detected_at.tzinfo == UTC
    # ms-precision round-trip is exact through OCSF.
    assert result[0].detected_at == NOW


@pytest.mark.asyncio
async def test_read_findings_empty_report_returns_empty_tuple(tmp_path: Path) -> None:
    """A clean detect run produces a findings.json with an empty findings[] — the reader
    returns ()."""
    path = _write_findings_json(tmp_path, [])
    result = await read_findings(path=path)
    assert result == ()


# ---------------------------- string vs Path arg --------------------------


@pytest.mark.asyncio
async def test_read_findings_accepts_string_path(tmp_path: Path) -> None:
    path = _write_findings_json(tmp_path, [_manifest_finding()])
    result = await read_findings(path=str(path))  # type: ignore[arg-type]
    assert len(result) == 1


# ---------------------------- error contracts -----------------------------


@pytest.mark.asyncio
async def test_missing_file_raises_findings_reader_error(tmp_path: Path) -> None:
    with pytest.raises(FindingsReaderError, match="not found"):
        await read_findings(path=tmp_path / "does_not_exist.json")


@pytest.mark.asyncio
async def test_invalid_json_raises_findings_reader_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("not { valid json")
    with pytest.raises(FindingsReaderError, match="not valid JSON"):
        await read_findings(path=bad)


@pytest.mark.asyncio
async def test_non_object_top_level_raises(tmp_path: Path) -> None:
    """A JSON array at the top is wrong — FindingsReport is always an object."""
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2, 3]")
    with pytest.raises(FindingsReaderError, match="must be an object"):
        await read_findings(path=bad)


@pytest.mark.asyncio
async def test_missing_findings_field_raises(tmp_path: Path) -> None:
    """A top-level object without a `findings` list isn't a FindingsReport."""
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"agent": "k8s_posture", "findings": "not-a-list"}))
    with pytest.raises(FindingsReaderError, match="findings: list"):
        await read_findings(path=bad)


# ---------------------------- defensive drops -----------------------------


@pytest.mark.asyncio
async def test_findings_with_no_manifest_evidence_are_dropped(tmp_path: Path) -> None:
    """A finding lacking `evidence[*].kind == "manifest"` is silently dropped — A.1 v0.1
    only knows how to remediate manifest-source findings."""
    # Hand-craft a payload that mimics a kube-bench finding (evidence.kind = "kube-bench").
    fake_findings = {
        "agent": "k8s_posture",
        "agent_version": "0.1.0",
        "customer_id": "cust_test",
        "run_id": "run_001",
        "scan_started_at": NOW.isoformat(),
        "scan_completed_at": NOW.isoformat(),
        "findings": [
            {
                "class_uid": 2003,
                "severity_id": 4,
                "time_dt": NOW.isoformat(),
                "evidences": [
                    {
                        "kind": "kube-bench",  # not manifest → drop
                        "control_id": "1.1.1",
                    }
                ],
                "finding_info": {"uid": "CSPM-KUBERNETES-CIS-001-x"},
            }
        ],
    }
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(fake_findings))
    result = await read_findings(path=path)
    assert result == ()


@pytest.mark.asyncio
async def test_finding_with_missing_required_fields_is_dropped(tmp_path: Path) -> None:
    """A manifest evidence missing rule_id / workload_kind / etc. is silently dropped."""
    fake_findings = {
        "agent": "k8s_posture",
        "agent_version": "0.1.0",
        "customer_id": "cust_test",
        "run_id": "run_001",
        "scan_started_at": NOW.isoformat(),
        "scan_completed_at": NOW.isoformat(),
        "findings": [
            {
                "class_uid": 2003,
                "severity_id": 4,
                "time_dt": NOW.isoformat(),
                "evidences": [{"kind": "manifest"}],  # missing all fields
                "finding_info": {"uid": "CSPM-X"},
            }
        ],
    }
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(fake_findings))
    result = await read_findings(path=path)
    assert result == ()


@pytest.mark.asyncio
async def test_mixed_manifest_and_other_evidences_keeps_manifest_only(tmp_path: Path) -> None:
    """A findings.json with a mix of manifest + other-source findings only surfaces the
    manifest ones."""
    # First, write a real manifest-source finding via D.6's normalizer.
    real_path = _write_findings_json(tmp_path, [_manifest_finding(workload_name="real")])
    real_payload = json.loads(real_path.read_text())
    # Insert a fake non-manifest finding ahead of the real one.
    real_payload["findings"].insert(
        0,
        {
            "class_uid": 2003,
            "severity_id": 4,
            "time_dt": NOW.isoformat(),
            "evidences": [{"kind": "kube-bench", "control_id": "1.1.1"}],
            "finding_info": {"uid": "CSPM-KUBERNETES-CIS-001-x"},
        },
    )
    real_path.write_text(json.dumps(real_payload))

    result = await read_findings(path=real_path)
    assert len(result) == 1
    assert result[0].workload_name == "real"


# ---------------------------- async wrapper -------------------------------


@pytest.mark.asyncio
async def test_read_findings_is_async(tmp_path: Path) -> None:
    """The reader is awaitable (calls underlying sync read via asyncio.to_thread)."""
    import inspect

    sig = inspect.signature(read_findings)
    assert inspect.iscoroutinefunction(read_findings)
    assert "path" in sig.parameters
