"""Starting CIS Microsoft Azure Foundations Benchmark rule subset (D.15 v0.2 Task 10).

**8 high-signal native rules across 5 resource types** — a *starting subset* per
Q4; the full CIS-Azure benchmark is v0.3 (WI-D3 honesty: reported as a subset, not
the whole benchmark). Each rule is a pure predicate over an `AzureResource`.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from multi_cloud_posture.rules_azure.engine import AzureNativeRule, AzureResource
from multi_cloud_posture.schemas import Severity

# Source prefixes that mean "from anywhere" in an NSG inbound rule.
_ANY_SOURCE = {"*", "0.0.0.0/0", "internet", "any"}


def _port_in_range(port: int, spec: str) -> bool:
    spec = spec.strip()
    if spec == "*":
        return True  # all ports
    if "-" in spec:
        lo, _, hi = spec.partition("-")
        try:
            return int(lo) <= port <= int(hi)
        except ValueError:
            return False
    try:
        return int(spec) == port
    except ValueError:
        return False


def _nsg_allows_port_from_any(resource: AzureResource, port: int) -> bool:
    rules: Iterable[dict[str, Any]] = resource.properties.get("security_rules", []) or []
    for r in rules:
        if str(r.get("access", "")).lower() != "allow":
            continue
        if str(r.get("direction", "")).lower() != "inbound":
            continue
        src = str(r.get("source_address_prefix", "")).strip().lower()
        if src not in _ANY_SOURCE:
            continue
        if _port_in_range(port, str(r.get("destination_port_range", ""))):
            return True
    return False


def _storage_public(r: AzureResource) -> bool:
    return str(r.properties.get("public_network_access", "")).lower() == "enabled" or bool(
        r.properties.get("allow_blob_public_access", False)
    )


AZURE_CIS_RULES: tuple[AzureNativeRule, ...] = (
    AzureNativeRule(
        rule_id="MCSPM-AZURE-STORAGE-001",
        title="Storage account allows public network access",
        description=(
            "The storage account permits access from all networks; "
            "restrict to selected networks / private endpoints."
        ),
        severity=Severity.HIGH,
        resource_type="storage_account",
        is_violation=_storage_public,
    ),
    AzureNativeRule(
        rule_id="MCSPM-AZURE-STORAGE-002",
        title="Storage account does not require secure transfer (HTTPS)",
        description="'Secure transfer required' is disabled; enable HTTPS-only access.",
        severity=Severity.MEDIUM,
        resource_type="storage_account",
        is_violation=lambda r: not r.properties.get("enable_https_traffic_only", True),
    ),
    AzureNativeRule(
        rule_id="MCSPM-AZURE-KEYVAULT-001",
        title="Key Vault soft-delete disabled",
        description=(
            "Soft-delete is disabled; enable it to protect against accidental or "
            "malicious deletion of keys and secrets."
        ),
        severity=Severity.MEDIUM,
        resource_type="key_vault",
        is_violation=lambda r: not r.properties.get("enable_soft_delete", False),
    ),
    AzureNativeRule(
        rule_id="MCSPM-AZURE-KEYVAULT-002",
        title="Key Vault purge protection disabled",
        description=(
            "Purge protection is disabled; enable it to prevent permanent deletion "
            "during the soft-delete retention window."
        ),
        severity=Severity.MEDIUM,
        resource_type="key_vault",
        is_violation=lambda r: not r.properties.get("enable_purge_protection", False),
    ),
    AzureNativeRule(
        rule_id="MCSPM-AZURE-NSG-001",
        title="Network security group allows SSH (22) from any source",
        description="An inbound rule allows TCP/22 from any source; restrict SSH to known ranges.",
        severity=Severity.HIGH,
        resource_type="network_security_group",
        is_violation=lambda r: _nsg_allows_port_from_any(r, 22),
    ),
    AzureNativeRule(
        rule_id="MCSPM-AZURE-NSG-002",
        title="Network security group allows RDP (3389) from any source",
        description="An inbound rule allows TCP/3389 from any source; restrict RDP to known ranges.",
        severity=Severity.HIGH,
        resource_type="network_security_group",
        is_violation=lambda r: _nsg_allows_port_from_any(r, 3389),
    ),
    AzureNativeRule(
        rule_id="MCSPM-AZURE-SQL-001",
        title="SQL server allows public network access",
        description=(
            "The SQL server permits public network access; disable it and use private endpoints."
        ),
        severity=Severity.HIGH,
        resource_type="sql_server",
        is_violation=lambda r: (
            str(r.properties.get("public_network_access", "")).lower() == "enabled"
        ),
    ),
    AzureNativeRule(
        rule_id="MCSPM-AZURE-APPSERVICE-001",
        title="App Service does not enforce HTTPS-only",
        description="'HTTPS Only' is disabled; enforce HTTPS to prevent cleartext access.",
        severity=Severity.MEDIUM,
        resource_type="app_service",
        is_violation=lambda r: not r.properties.get("https_only", False),
    ),
)
