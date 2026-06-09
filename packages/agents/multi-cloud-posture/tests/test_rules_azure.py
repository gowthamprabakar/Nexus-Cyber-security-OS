"""D.5 v0.2 Task 10 — native Azure rule engine + CIS rules (offline, mock resources)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from multi_cloud_posture.rules_azure import (
    AZURE_CIS_RULES,
    AzureResource,
    AzureRuleEngine,
)
from multi_cloud_posture.schemas import FINDING_ID_RE, CSPMFindingType
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 6, 9, 12, 0, 0, tzinfo=UTC)
ENGINE = AzureRuleEngine(AZURE_CIS_RULES)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_native",
        tenant_id="cust_test",
        agent_id="multi_cloud_posture@0.2.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_native",
    )


def _r(
    resource_type: str, properties: dict[str, Any], rid: str = "/subscriptions/s/r/x"
) -> AzureResource:
    return AzureResource(
        resource_type=resource_type,
        resource_id=rid,
        subscription_id="sub-123",
        region="eastus",
        properties=properties,
    )


def _fire(resource: AzureResource) -> set[str]:
    """The set of rule_ids that fired for a resource."""
    findings = ENGINE.evaluate([resource], envelope=_envelope(), scan_time=NOW)
    return {str(f.rule_id) for f in findings}


def test_engine_has_eight_rules() -> None:
    assert ENGINE.rule_count == 8


def test_storage_public_network_access() -> None:
    assert "MCSPM-AZURE-STORAGE-001" in _fire(
        _r("storage_account", {"public_network_access": "Enabled"})
    )
    assert "MCSPM-AZURE-STORAGE-001" in _fire(
        _r("storage_account", {"allow_blob_public_access": True})
    )
    assert "MCSPM-AZURE-STORAGE-001" not in _fire(
        _r("storage_account", {"public_network_access": "Disabled"})
    )


def test_storage_secure_transfer() -> None:
    assert "MCSPM-AZURE-STORAGE-002" in _fire(
        _r("storage_account", {"enable_https_traffic_only": False})
    )
    assert "MCSPM-AZURE-STORAGE-002" not in _fire(
        _r("storage_account", {"enable_https_traffic_only": True})
    )


def test_keyvault_soft_delete_and_purge() -> None:
    fired = _fire(_r("key_vault", {"enable_soft_delete": False, "enable_purge_protection": False}))
    assert "MCSPM-AZURE-KEYVAULT-001" in fired
    assert "MCSPM-AZURE-KEYVAULT-002" in fired
    clean = _fire(_r("key_vault", {"enable_soft_delete": True, "enable_purge_protection": True}))
    assert clean == set()


def test_nsg_ssh_from_any() -> None:
    bad = _r(
        "network_security_group",
        {
            "security_rules": [
                {
                    "access": "Allow",
                    "direction": "Inbound",
                    "source_address_prefix": "*",
                    "destination_port_range": "22",
                }
            ]
        },
    )
    assert "MCSPM-AZURE-NSG-001" in _fire(bad)


def test_nsg_rdp_from_cidr_any() -> None:
    bad = _r(
        "network_security_group",
        {
            "security_rules": [
                {
                    "access": "Allow",
                    "direction": "Inbound",
                    "source_address_prefix": "0.0.0.0/0",
                    "destination_port_range": "3389",
                }
            ]
        },
    )
    assert "MCSPM-AZURE-NSG-002" in _fire(bad)


def test_nsg_port_range_covers_ssh() -> None:
    bad = _r(
        "network_security_group",
        {
            "security_rules": [
                {
                    "access": "Allow",
                    "direction": "Inbound",
                    "source_address_prefix": "Internet",
                    "destination_port_range": "20-30",
                }
            ]
        },
    )
    assert "MCSPM-AZURE-NSG-001" in _fire(bad)


def test_nsg_specific_source_is_clean() -> None:
    ok = _r(
        "network_security_group",
        {
            "security_rules": [
                {
                    "access": "Allow",
                    "direction": "Inbound",
                    "source_address_prefix": "10.0.0.0/8",
                    "destination_port_range": "22",
                }
            ]
        },
    )
    assert _fire(ok) == set()


def test_nsg_deny_is_clean() -> None:
    ok = _r(
        "network_security_group",
        {
            "security_rules": [
                {
                    "access": "Deny",
                    "direction": "Inbound",
                    "source_address_prefix": "*",
                    "destination_port_range": "22",
                }
            ]
        },
    )
    assert _fire(ok) == set()


def test_sql_public_network_access() -> None:
    assert "MCSPM-AZURE-SQL-001" in _fire(_r("sql_server", {"public_network_access": "Enabled"}))
    assert "MCSPM-AZURE-SQL-001" not in _fire(
        _r("sql_server", {"public_network_access": "Disabled"})
    )


def test_appservice_https_only() -> None:
    assert "MCSPM-AZURE-APPSERVICE-001" in _fire(_r("app_service", {"https_only": False}))
    assert "MCSPM-AZURE-APPSERVICE-001" not in _fire(_r("app_service", {"https_only": True}))


def test_rule_only_applies_to_its_resource_type() -> None:
    # a compliant key_vault must not trip the storage rules
    assert (
        _fire(_r("key_vault", {"enable_soft_delete": True, "enable_purge_protection": True}))
        == set()
    )


def test_finding_shape_is_ocsf_2003_native() -> None:
    findings = ENGINE.evaluate(
        [_r("storage_account", {"public_network_access": "Enabled"})],
        envelope=_envelope(),
        scan_time=NOW,
    )
    assert len(findings) == 1
    doc = findings[0].to_dict()
    assert doc["class_uid"] == 2003
    assert doc["category_uid"] == 2
    assert FINDING_ID_RE.match(doc["finding_info"]["uid"])
    ev = doc["evidences"][0]
    assert ev["source_finding_type"] == CSPMFindingType.AZURE_NATIVE.value
    assert ev["provenance"] == "Nexus-native"


def test_all_compliant_yields_no_findings() -> None:
    clean = [
        _r(
            "storage_account",
            {"public_network_access": "Disabled", "enable_https_traffic_only": True},
        ),
        _r("key_vault", {"enable_soft_delete": True, "enable_purge_protection": True}),
        _r("sql_server", {"public_network_access": "Disabled"}),
        _r("app_service", {"https_only": True}),
    ]
    assert ENGINE.evaluate(clean, envelope=_envelope(), scan_time=NOW) == []


def test_multiple_violations_get_distinct_finding_ids() -> None:
    resources = [
        _r("storage_account", {"public_network_access": "Enabled"}, rid="/sub/s/storage/aaaa"),
        _r("sql_server", {"public_network_access": "Enabled"}, rid="/sub/s/sql/bbbb"),
    ]
    findings = ENGINE.evaluate(resources, envelope=_envelope(), scan_time=NOW)
    uids = [f.to_dict()["finding_info"]["uid"] for f in findings]
    assert len(uids) == 2
    assert len(set(uids)) == 2  # distinct
