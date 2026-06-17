"""D.15 v0.2 Task 11 — native GCP rule engine + CIS rules (offline, mock resources)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from multi_cloud_posture.rules_gcp import GCP_CIS_RULES, GcpResource, GcpRuleEngine
from multi_cloud_posture.schemas import FINDING_ID_RE, CSPMFindingType
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 6, 9, 12, 0, 0, tzinfo=UTC)
ENGINE = GcpRuleEngine(GCP_CIS_RULES)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_gcp_native",
        tenant_id="cust_test",
        agent_id="multi_cloud_posture@0.2.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_gcp",
    )


def _r(resource_type: str, properties: dict[str, Any], rid: str = "projects/p/x/y") -> GcpResource:
    return GcpResource(
        resource_type=resource_type,
        resource_id=rid,
        project_id="proj-123",
        region="us-central1",
        properties=properties,
    )


def _fire(resource: GcpResource) -> set[str]:
    findings = ENGINE.evaluate([resource], envelope=_envelope(), scan_time=NOW)
    return {str(f.rule_id) for f in findings}


def test_engine_has_ten_rules() -> None:
    assert ENGINE.rule_count == 10


def test_bucket_public() -> None:
    assert "MCSPM-GCP-STORAGE-001" in _fire(_r("storage_bucket", {"iam_members": ["allUsers"]}))
    assert "MCSPM-GCP-STORAGE-001" in _fire(
        _r("storage_bucket", {"iam_members": ["allAuthenticatedUsers"]})
    )
    assert "MCSPM-GCP-STORAGE-001" not in _fire(
        _r("storage_bucket", {"iam_members": ["user:alice@example.com"]})
    )


def test_bucket_uniform_access() -> None:
    assert "MCSPM-GCP-STORAGE-002" in _fire(
        _r("storage_bucket", {"uniform_bucket_level_access": False})
    )
    assert "MCSPM-GCP-STORAGE-002" not in _fire(
        _r("storage_bucket", {"uniform_bucket_level_access": True})
    )


def test_sql_public_ip_and_ssl() -> None:
    assert "MCSPM-GCP-SQL-001" in _fire(_r("cloud_sql_instance", {"public_ip": True}))
    assert "MCSPM-GCP-SQL-002" in _fire(_r("cloud_sql_instance", {"require_ssl": False}))
    clean = _fire(_r("cloud_sql_instance", {"public_ip": False, "require_ssl": True}))
    assert clean == set()


def test_gce_external_ip() -> None:
    assert "MCSPM-GCP-GCE-001" in _fire(_r("compute_instance", {"has_external_ip": True}))
    assert "MCSPM-GCP-GCE-001" not in _fire(_r("compute_instance", {"has_external_ip": False}))


def test_gce_default_sa_editor() -> None:
    assert "MCSPM-GCP-GCE-002" in _fire(
        _r("compute_instance", {"default_service_account": True, "editor_role": True})
    )
    # default SA but no editor → not a violation of GCE-002
    assert "MCSPM-GCP-GCE-002" not in _fire(
        _r("compute_instance", {"default_service_account": True, "editor_role": False})
    )


def _fw(
    source_ranges: list[str], port_spec: list[str] | None, *, proto: str = "tcp"
) -> GcpResource:
    return _r(
        "firewall",
        {
            "direction": "INGRESS",
            "source_ranges": source_ranges,
            "allowed": [{"IPProtocol": proto, "ports": port_spec}],
        },
    )


def test_firewall_ssh_from_any() -> None:
    assert "MCSPM-GCP-FIREWALL-001" in _fire(_fw(["0.0.0.0/0"], ["22"]))


def test_firewall_rdp_from_any() -> None:
    assert "MCSPM-GCP-FIREWALL-002" in _fire(_fw(["0.0.0.0/0"], ["3389"]))


def test_firewall_port_range_covers_ssh() -> None:
    assert "MCSPM-GCP-FIREWALL-001" in _fire(_fw(["0.0.0.0/0"], ["20-30"]))


def test_firewall_all_ports_when_none() -> None:
    # `ports` absent => all ports allowed.
    assert "MCSPM-GCP-FIREWALL-001" in _fire(_fw(["0.0.0.0/0"], None))


def test_firewall_specific_source_is_clean() -> None:
    assert _fire(_fw(["10.0.0.0/8"], ["22"])) == set()


def test_kms_rotation() -> None:
    assert "MCSPM-GCP-KMS-001" in _fire(_r("kms_key", {}))
    assert "MCSPM-GCP-KMS-001" not in _fire(_r("kms_key", {"rotation_period": "7776000s"}))


def test_bigquery_public() -> None:
    assert "MCSPM-GCP-BIGQUERY-001" in _fire(
        _r("bigquery_dataset", {"access_members": ["allUsers"]})
    )
    assert "MCSPM-GCP-BIGQUERY-001" not in _fire(
        _r("bigquery_dataset", {"access_members": ["user:bob@example.com"]})
    )


def test_finding_shape_is_ocsf_2003_native() -> None:
    findings = ENGINE.evaluate(
        # uniform access on, so only the public-access rule (STORAGE-001) fires.
        [_r("storage_bucket", {"iam_members": ["allUsers"], "uniform_bucket_level_access": True})],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(findings) == 1
    doc = findings[0].to_dict()
    assert doc["class_uid"] == 2003
    assert FINDING_ID_RE.match(doc["finding_info"]["uid"])
    ev = doc["evidences"][0]
    assert ev["source_finding_type"] == CSPMFindingType.GCP_NATIVE.value
    assert ev["provenance"] == "Nexus-native"


def test_all_compliant_yields_no_findings() -> None:
    clean = [
        _r("storage_bucket", {"iam_members": [], "uniform_bucket_level_access": True}),
        _r("cloud_sql_instance", {"public_ip": False, "require_ssl": True}),
        _r("kms_key", {"rotation_period": "100s"}),
    ]
    assert ENGINE.evaluate(clean, envelope=_envelope(), scan_time=NOW) == []


def test_rule_only_applies_to_its_resource_type() -> None:
    assert _fire(_r("kms_key", {"rotation_period": "100s"})) == set()
