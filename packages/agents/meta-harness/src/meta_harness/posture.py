"""Posture rollup — read-only aggregation of post-scan graph data into board data.

Pure `compute` + explicit persistence. No writes in compute; no OCSF; no graph node.
See docs/superpowers/specs/2026-07-08-posture-rollup-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from charter.memory.graph_types import NodeCategory as NC


# ---- severity bucketing (attack-path severity is an int 0-100) -------------
def bucket_of(severity: int) -> str:
    if severity >= 90:
        return "critical"
    if severity >= 75:
        return "high"
    if severity >= 50:
        return "medium"
    return "low"


# ---- domain vocabulary -----------------------------------------------------
DOMAINS: frozenset[str] = frozenset(
    {"vulnerability", "cloud", "identity", "data", "container", "appsec", "threat", "ai", "network"}
)

# path_type -> product domain (completeness enforced by test against _SEVERITY)
PATH_DOMAIN: dict[str, str] = {
    "crown_jewel": "data",
    "leaked_credential": "identity",
    "public_secret": "identity",
    "runtime_exploit_vulnerable": "threat",
    "malicious_destination": "threat",
    "exposed_database": "data",
    "lateral_movement": "network",
    "supply_chain_sbom": "appsec",
    "internet_exposed_vulnerable": "vulnerability",
    "internet_exposed_host_vulnerable": "vulnerability",
    "lateral_reachable": "network",
    "privileged_vulnerable": "vulnerability",
    "rbac_privilege_escalation": "container",
    "public_unencrypted": "data",
    "kms_key_access": "data",
    "escalation_method_to_data": "identity",
    "exposed_kms_key_over_data": "data",
    "exposed_kms_key": "data",
    "external_trust": "identity",
    "exposed_ai_sensitive_data": "ai",
    "privilege_escalation": "identity",
    "resource_based_data": "data",
    "fine_grained_data": "data",
    "iac_misconfig_deployed": "appsec",
    "cicd_compromise": "appsec",
    "stored_secret_to_data": "identity",
    "k8s_escape_to_cloud_data": "container",
    "rbac_escalation_to_cloud_data": "container",
    "serverless_lambda_exposure": "cloud",
    "imds_credential_theft": "identity",
}

# domain -> representative node categories, for coverage ("did this domain produce data?")
DOMAIN_CATEGORIES: dict[str, tuple[str, ...]] = {
    "vulnerability": (NC.CVE_FINDING.value, NC.SBOM_PACKAGE.value, NC.EXPLOIT_AVAILABILITY.value),
    "cloud": (NC.CLOUD_RESOURCE.value, NC.CLOUD_ACCOUNT.value, NC.MISCONFIGURATION_FINDING.value),
    "identity": (NC.IDENTITY.value, NC.POLICY.value, NC.SECRET.value, NC.SECRET_FINDING.value),
    "data": (NC.DATA_CLASSIFICATION.value, NC.KMS_KEY.value),
    "container": (NC.K8S_CLUSTER.value, NC.K8S_OBJECT.value, NC.CONTAINER_IMAGE.value),
    "appsec": (
        NC.CODE_REPOSITORY.value,
        NC.SAST_FINDING.value,
        NC.IAC_ARTIFACT.value,
        NC.BUILD.value,
    ),
    "threat": (NC.THREAT_INDICATOR.value, NC.THREAT_ACTOR.value, NC.PROCESS_EVENT.value),
    "ai": (NC.AI_SERVICE.value, NC.AI_MODEL.value),
    "network": (NC.NETWORK_PATH.value, NC.NETWORK_FLOW_EVENT.value),
}

FINDING_CATEGORIES: tuple[str, ...] = (
    NC.CVE_FINDING.value,
    NC.MISCONFIGURATION_FINDING.value,
    NC.SECRET_FINDING.value,
    NC.SAST_FINDING.value,
)
INVENTORY_CATEGORIES: tuple[str, ...] = (
    NC.CLOUD_RESOURCE.value,
    NC.IDENTITY.value,
    NC.DATA_CLASSIFICATION.value,
    NC.CONTAINER_IMAGE.value,
    NC.K8S_OBJECT.value,
    NC.CODE_REPOSITORY.value,
    NC.SBOM_PACKAGE.value,
    NC.AI_MODEL.value,
    NC.SAAS_TENANT.value,
)
EXPOSURE_PATH_TYPES: frozenset[str] = frozenset(
    {"internet_exposed_vulnerable", "internet_exposed_host_vulnerable", "supply_chain_sbom"}
)
EPSS_EXPLOITABLE = 0.5


# ---- data model ------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class DomainCount:
    domain: str
    critical: int
    high: int
    medium: int
    low: int
    total: int


@dataclass(frozen=True, slots=True)
class PathTypeCount:
    path_type: str
    count: int
    max_severity: int


@dataclass(frozen=True, slots=True)
class ExposureFunnel:
    exposed: int
    vulnerable: int
    kev: int
    exploitable: int


@dataclass(frozen=True, slots=True)
class Coverage:
    domains_covered: int
    domains_total: int
    domain_pct: int
    collectors_ok: int | None
    collectors_run: int | None
    collector_pct: int | None
    surfaced_findings: int
    total_findings: int
    surfaced_pct: int


@dataclass(frozen=True, slots=True)
class PostureSummary:
    tenant: str
    scan_at: str
    coverage: Coverage
    totals: dict[str, int]
    severity_distribution: dict[str, int]
    by_domain: tuple[DomainCount, ...]
    by_path_type: tuple[PathTypeCount, ...]
    exposure_funnel: ExposureFunnel
    inventory_counts: dict[str, int]
    top_paths: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class TrendPoint:
    at: str
    attack_paths: int
    critical: int
    high: int
