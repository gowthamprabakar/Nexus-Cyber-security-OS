"""Tests — ``synthesis.context_bundle`` (Task 4).

Validates the Stage-2 ENRICH projection from raw sibling-OCSF dicts
into the structured `ContextBundle` that flows into the LLM call.

**Q6 invariant tests are load-bearing**: when raw D.5-style OCSF
findings carry ``evidence.matched_text`` / ``bucket_objects[].
matched_text`` / ``evidence.sample`` substrings, the bundle MUST
NOT propagate them. This is the first line of defence; the
reviewer (Task 7) is the second.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from synthesis.context_bundle import build_context_bundle
from synthesis.tools.sibling_workspace_reader import SiblingFindings


def _payload(
    *,
    uid: str = "X-1",
    severity_id: int = 4,
    title: str = "Test finding",
    desc: str = "",
    evidence: dict[str, Any] | None = None,
    compliance: dict[str, Any] | None = None,
    resources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "class_uid": 2003,
        "severity_id": severity_id,
        "finding_info": {"uid": uid, "title": title, "desc": desc},
        "evidences": [evidence] if evidence else [],
    }
    if compliance is not None:
        payload["compliance"] = compliance
    if resources is not None:
        payload["resources"] = resources
    return payload


def _now() -> datetime:
    return datetime(2026, 5, 21, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Empty-input + top-level shape
# ---------------------------------------------------------------------------


def test_empty_input_yields_empty_bundle() -> None:
    bundle = build_context_bundle(
        SiblingFindings(),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    assert bundle.investigation_conclusions == []
    assert bundle.compliance_failures == []
    assert bundle.cloud_posture_findings == []
    assert bundle.severity_counts == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    assert bundle.total_findings == 0


def test_bundle_carries_customer_and_scan_window() -> None:
    bundle = build_context_bundle(
        SiblingFindings(),
        customer_id="contoso",
        scan_window_start=datetime(2026, 1, 1, tzinfo=UTC),
        scan_window_end=datetime(2026, 1, 2, tzinfo=UTC),
    )
    assert bundle.customer_id == "contoso"
    assert bundle.scan_window_start == datetime(2026, 1, 1, tzinfo=UTC)
    assert bundle.scan_window_end == datetime(2026, 1, 2, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Per-source projection
# ---------------------------------------------------------------------------


def test_investigation_projection_surfaces_summary_and_related_ids() -> None:
    inv = _payload(
        uid="INV-1",
        title="Cross-finding investigation",
        desc="Linked CVE-2024-1 to runtime alert.",
        evidence={"related_finding_ids": ["VULN-x-CVE-2024-1", "RUNTIME-PROCESS-001"]},
    )
    bundle = build_context_bundle(
        SiblingFindings(investigation=(inv,)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    assert len(bundle.investigation_conclusions) == 1
    conclusion = bundle.investigation_conclusions[0]
    assert conclusion["finding_id"] == "INV-1"
    assert conclusion["summary"] == "Linked CVE-2024-1 to runtime alert."
    assert conclusion["related_finding_ids"] == [
        "VULN-x-CVE-2024-1",
        "RUNTIME-PROCESS-001",
    ]


def test_compliance_projection_surfaces_control_metadata() -> None:
    comp = _payload(
        uid="COMPLIANCE-CIS_AWS_V3-1_10-001-aggregated",
        title="CIS 1.10 - IAM MFA",
        severity_id=4,
        compliance={"control": "cis_aws_v3:1.10"},
        evidence={
            "contributor_count": 2,
            "control": {
                "framework": "cis_aws_v3",
                "control_id": "1.10",
                "level": "level_1",
                "required": True,
            },
        },
    )
    bundle = build_context_bundle(
        SiblingFindings(compliance=(comp,)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    f = bundle.compliance_failures[0]
    assert f["control"] == "cis_aws_v3:1.10"
    assert f["contributor_count"] == 2
    assert f["control_meta"]["control_id"] == "1.10"
    assert f["control_meta"]["level"] == "level_1"
    assert f["control_meta"]["required"] is True


def test_cloud_posture_projection_surfaces_resource_arns_and_labels() -> None:
    cspm = _payload(
        uid="CSPM-AWS-S3-001-bucket",
        title="Public S3 bucket",
        severity_id=4,
        evidence={"classifier_labels_found": ["ssn", "credit_card"]},
        resources=[
            {
                "type": "aws_s3_bucket",
                "uid": "arn:aws:s3:::company-secrets",
                "cloud_partition": "aws",
                "region": "us-east-1",
            }
        ],
    )
    bundle = build_context_bundle(
        SiblingFindings(cloud_posture=(cspm,)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    f = bundle.cloud_posture_findings[0]
    assert f["resource_arns"] == ["arn:aws:s3:::company-secrets"]
    assert f["classifier_labels_found"] == ["ssn", "credit_card"]


# ---------------------------------------------------------------------------
# Q6 INVARIANT TESTS (load-bearing)
# ---------------------------------------------------------------------------


def test_q6_matched_text_field_never_surfaces() -> None:
    """A raw D.5 finding carrying `evidence.matched_text` must NOT
    propagate that field into the context bundle. The labels DO
    surface (those are public-shape); the matched text does NOT."""
    leaky = _payload(
        uid="CSPM-AWS-S3-002-leaky",
        title="Sensitive data in untrusted location",
        severity_id=4,
        evidence={
            "classifier_labels_found": ["ssn"],
            "matched_text": "123-45-6789",  # ← MUST NOT LEAK
        },
        resources=[{"type": "aws_s3_bucket", "uid": "arn:aws:s3:::leaky"}],
    )
    bundle = build_context_bundle(
        SiblingFindings(cloud_posture=(leaky,)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    f = bundle.cloud_posture_findings[0]
    assert "matched_text" not in f, "Q6 violation: matched_text leaked into bundle"
    # Serialise the whole bundle and verify the substring never appears.
    serialized = repr(bundle)
    assert "123-45-6789" not in serialized, "Q6 violation: matched substring in bundle repr"
    assert f["classifier_labels_found"] == ["ssn"]


def test_q6_bucket_objects_matched_text_never_surfaces() -> None:
    """D.5's oversharing detector may stuff bucket-object samples
    under `evidence.bucket_objects[].matched_text`. None of those
    fields must propagate."""
    leaky = _payload(
        uid="CSPM-AWS-S3-OVERSHARE-001",
        title="S3 bucket oversharing",
        severity_id=4,
        evidence={
            "classifier_labels_found": ["aws_access_key"],
            "bucket_objects": [
                {
                    "key": "secrets/api-key.txt",
                    "matched_text": "AKIAIOSFODNN7EXAMPLE",  # ← MUST NOT LEAK
                }
            ],
        },
        resources=[{"type": "aws_s3_bucket", "uid": "arn:aws:s3:::leaky"}],
    )
    bundle = build_context_bundle(
        SiblingFindings(cloud_posture=(leaky,)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    serialized = repr(bundle)
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized
    assert "matched_text" not in serialized
    assert "bucket_objects" not in serialized


def test_q6_sample_evidence_field_never_surfaces() -> None:
    """`evidence.sample` is another D.5 leakage vector (some
    detectors stash raw byte slices here)."""
    leaky = _payload(
        uid="CSPM-AWS-S3-SAMPLE-001",
        evidence={
            "classifier_labels_found": ["jwt"],
            "sample": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.signature",
        },
    )
    bundle = build_context_bundle(
        SiblingFindings(cloud_posture=(leaky,)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    serialized = repr(bundle)
    assert "eyJhbGciOiJIUzI1NiJ9" not in serialized
    assert "signature" not in serialized
    assert "sample" not in serialized


def test_q6_finding_info_desc_not_propagated_for_cloud_posture() -> None:
    """D.5 detectors may stuff object-key fragments into
    `finding_info.desc`. Cloud-posture projection must NOT carry
    `desc` forward -- only `title`."""
    leaky = _payload(
        uid="CSPM-AWS-S3-DESC-001",
        title="Sensitive data exposure",
        desc="Bucket key 'secrets/db-password.txt' contained matched text 'P@ssw0rd123'",
        evidence={"classifier_labels_found": ["credit_card"]},
    )
    bundle = build_context_bundle(
        SiblingFindings(cloud_posture=(leaky,)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    f = bundle.cloud_posture_findings[0]
    assert "desc" not in f
    serialized = repr(bundle)
    assert "P@ssw0rd123" not in serialized
    assert "db-password" not in serialized


# ---------------------------------------------------------------------------
# Severity counts
# ---------------------------------------------------------------------------


def test_severity_counts_aggregated_across_sources() -> None:
    inv = _payload(uid="INV-1", severity_id=5)  # critical
    comp = _payload(uid="COMP-1", severity_id=4)  # high
    cspm_h = _payload(uid="CSPM-1", severity_id=4)  # high
    cspm_m = _payload(uid="CSPM-2", severity_id=3)  # medium
    bundle = build_context_bundle(
        SiblingFindings(investigation=(inv,), compliance=(comp,), cloud_posture=(cspm_h, cspm_m)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    assert bundle.severity_counts["critical"] == 1
    assert bundle.severity_counts["high"] == 2
    assert bundle.severity_counts["medium"] == 1
    assert bundle.severity_counts["low"] == 0
    assert bundle.total_findings == 4


def test_severity_id_6_collapses_to_critical() -> None:
    """OCSF Fatal (severity_id=6) collapses to critical per the
    severity-from-id table inherited from F.3."""
    fatal = _payload(uid="F-1", severity_id=6)
    bundle = build_context_bundle(
        SiblingFindings(investigation=(fatal,)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    assert bundle.severity_counts["critical"] == 1


# ---------------------------------------------------------------------------
# Top-N cap
# ---------------------------------------------------------------------------


def test_per_source_top_n_cap_applies() -> None:
    """When more than 16 cloud-posture findings exist, only top-16 by
    severity surface. Critical findings beat low; ties broken by
    finding-id alpha order."""
    findings = []
    # 20 findings: 4 critical + 16 low
    for i in range(4):
        findings.append(_payload(uid=f"CRIT-{i:02d}", severity_id=5))
    for i in range(16):
        findings.append(_payload(uid=f"LOW-{i:02d}", severity_id=2))
    bundle = build_context_bundle(
        SiblingFindings(cloud_posture=tuple(findings)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    # Top-16: all 4 critical + 12 of the 16 low (alphabetically first).
    surfaced_ids = [f["finding_id"] for f in bundle.cloud_posture_findings]
    assert len(surfaced_ids) == 16
    assert all(crit in surfaced_ids for crit in [f"CRIT-{i:02d}" for i in range(4)])
    # total_findings unchanged (it counts the raw input, not the projection)
    assert bundle.total_findings == 20


def test_investigation_top_n_cap_at_12() -> None:
    findings = tuple(_payload(uid=f"INV-{i:02d}", severity_id=4) for i in range(15))
    bundle = build_context_bundle(
        SiblingFindings(investigation=findings),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    assert len(bundle.investigation_conclusions) == 12


def test_classifier_labels_capped_per_finding() -> None:
    labels = [f"label_{i}" for i in range(12)]
    cspm = _payload(
        uid="CSPM-X",
        severity_id=4,
        evidence={"classifier_labels_found": labels},
    )
    bundle = build_context_bundle(
        SiblingFindings(cloud_posture=(cspm,)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    surfaced_labels = bundle.cloud_posture_findings[0]["classifier_labels_found"]
    assert len(surfaced_labels) == 8  # _MAX_CLASSIFIER_LABELS_PER_FINDING


# ---------------------------------------------------------------------------
# Defensive parsing
# ---------------------------------------------------------------------------


def test_classifier_labels_field_not_a_list_is_silently_dropped() -> None:
    cspm = _payload(
        uid="CSPM-X",
        evidence={"classifier_labels_found": "ssn"},  # ← wrong shape (string not list)
    )
    bundle = build_context_bundle(
        SiblingFindings(cloud_posture=(cspm,)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    assert bundle.cloud_posture_findings[0]["classifier_labels_found"] == []


def test_resource_with_missing_uid_skipped() -> None:
    cspm = _payload(
        uid="CSPM-X",
        resources=[
            {"type": "aws_s3_bucket"},  # missing uid
            {"type": "aws_s3_bucket", "uid": "arn:aws:s3:::good"},
        ],
    )
    bundle = build_context_bundle(
        SiblingFindings(cloud_posture=(cspm,)),
        customer_id="acme",
        scan_window_start=_now(),
        scan_window_end=_now(),
    )
    assert bundle.cloud_posture_findings[0]["resource_arns"] == ["arn:aws:s3:::good"]
