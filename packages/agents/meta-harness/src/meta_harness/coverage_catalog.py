"""Attack-path coverage catalog (NEX-003a) — the DENOMINATOR for coverage %.

Coverage was always an estimate ("~15–20%") with no fixed denominator, so the number was arbitrary.
This is the finite target set of attack-path families a cloud CNAPP should detect, derived from MITRE
ATT&CK for Cloud tactics + the Wiz-style toxic-combination paths. Coverage = (families the fixture bank
actually PRODUCES) / (families in this catalog). Each family names the ``path_type`` it surfaces as on
the report card, its MITRE tactic, and whether it is BUILT yet — so the harness (NEX-003) can measure
produced-vs-catalog objectively, and the number moves only when a real family lands.

Add a family here when the roadmap commits to it (planned) BEFORE building it — the denominator is
fixed up front, never trimmed to flatter the %.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Status(str, Enum):
    BUILT = "built"  # a detector produces this family's path today
    PLANNED = "planned"  # committed in the roadmap, not yet producing


@dataclass(frozen=True, slots=True)
class Family:
    """One target attack-path family — a row of the denominator."""

    id: str
    mitre_tactic: str
    path_type: str  # the report-card path_type it surfaces as
    status: Status


#: The fixed denominator. Ordered by MITRE-ish tactic. `path_type` matches report_card / attack_paths.
CATALOG: tuple[Family, ...] = (
    # --- Exposure / initial access → data ---
    Family("public_secret", "Exfiltration", "public_secret", Status.BUILT),
    Family("public_unencrypted", "Exfiltration", "public_unencrypted", Status.BUILT),
    Family("fine_grained_data", "Collection", "fine_grained_data", Status.BUILT),
    Family("resource_based_data", "Collection", "resource_based_data", Status.BUILT),
    Family("external_trust", "Initial Access", "external_trust", Status.BUILT),
    # --- Vulnerability / exploit ---
    Family("internet_exposed_vulnerable", "Initial Access", "internet_exposed_vulnerable", Status.BUILT),
    Family("internet_exposed_host_vulnerable", "Initial Access", "internet_exposed_host_vulnerable", Status.BUILT),
    Family("privileged_vulnerable", "Privilege Escalation", "privileged_vulnerable", Status.BUILT),
    Family("crown_jewel", "Collection", "crown_jewel", Status.BUILT),
    Family("runtime_exploit_vulnerable", "Execution", "runtime_exploit_vulnerable", Status.BUILT),
    # --- Credential access ---
    Family("leaked_credential", "Credential Access", "leaked_credential", Status.BUILT),
    Family("stored_secret", "Credential Access", "stored_secret", Status.BUILT),
    # --- Privilege escalation ---
    Family("privilege_escalation", "Privilege Escalation", "privilege_escalation", Status.BUILT),
    Family("rbac_privilege_escalation", "Privilege Escalation", "rbac_privilege_escalation", Status.BUILT),
    Family("cross_account_trust", "Privilege Escalation", "cross_account_trust", Status.BUILT),
    # --- Lateral movement ---
    Family("network_lateral", "Lateral Movement", "lateral_movement", Status.BUILT),
    Family("pod_lateral", "Lateral Movement", "pod_lateral", Status.BUILT),
    Family("container_escape_cloud", "Privilege Escalation", "container_escape", Status.BUILT),
    Family("network_topology_lateral", "Lateral Movement", "network_topology_lateral", Status.BUILT),
    # --- Impact domains ---
    Family("exposed_kms_key", "Impact", "exposed_kms_key", Status.BUILT),
    Family("kms_key_access", "Credential Access", "kms_key_access", Status.BUILT),
    Family("exposed_database", "Exfiltration", "exposed_database", Status.BUILT),
    Family("exposed_ai_sensitive_data", "Collection", "exposed_ai_sensitive_data", Status.BUILT),
    Family("saas_oauth_tenant", "Initial Access", "saas_tenant", Status.BUILT),
    # --- Supply chain / provenance ---
    Family("supply_chain_sbom", "Initial Access", "supply_chain_sbom", Status.BUILT),
    Family("cicd_compromise", "Initial Access", "cicd_compromise", Status.PLANNED),
    Family("iac_misconfig_deployed", "Persistence", "iac_misconfig_deployed", Status.BUILT),
    # --- Threat presence ---
    Family("malicious_destination", "Command and Control", "malicious_destination", Status.BUILT),
)

#: The path_types the catalog considers "covered when produced".
CATALOG_PATH_TYPES: frozenset[str] = frozenset(f.path_type for f in CATALOG)


def built_families() -> tuple[Family, ...]:
    return tuple(f for f in CATALOG if f.status is Status.BUILT)


__all__ = ["CATALOG", "CATALOG_PATH_TYPES", "Family", "Status", "built_families"]
