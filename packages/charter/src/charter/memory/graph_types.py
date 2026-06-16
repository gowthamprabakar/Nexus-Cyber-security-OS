"""Fleet-graph type catalogue (ADR-018) — node categories + edge types.

The single source of truth for the inventory-graph typology, transcribed faithfully
from the inventory catalogue (`docs/_meta/v0-4-inventory-catalogue-2026-06-16.md`,
#711). Every ``EdgeType`` member corresponds to an edge named in that catalogue's
"Edges written" sections; every ``NodeCategory`` member to a row in its consolidated
ownership matrix. No types are invented here (Layer 23 transcription discipline).

Both enums are :class:`enum.StrEnum`, so a member *is* a ``str`` — the existing
``SemanticStore.upsert_entity(entity_type=…)`` / ``add_relationship(relationship_type=…)``
call sites accept them with no signature change (ADR-018: additive, non-breaking).
The store still accepts free strings; new ``kg_writer`` s use the enum as the forward
standard, and the shared writer base (ADR-019) consumes it.

Scope (ADR-018, Stage 3 PR1): the type catalogue only. The shared ``KnowledgeGraphWriter``
base is ADR-019; ``kg_query`` + the cross-run-dedup ``UNIQUE`` constraint are later
Stage 3 PRs. This module changes no ``SemanticStore`` behaviour.
"""

from __future__ import annotations

from enum import StrEnum


class NodeCategory(StrEnum):
    """Inventory-graph node categories (catalogue consolidated ownership matrix).

    Category-level (the matrix grouping); concrete resource sub-types (e.g. a
    specific AWS resource) ride as node ``properties``/``external_id``, not as new
    categories. Canonical ownership is documented in the catalogue, not encoded here
    (kept out of PR1 scope; see ADR-019 for the writer base that enforces it).
    """

    # Cloud base infrastructure (D.3 AWS / D.5 Azure+GCP)
    CLOUD_ACCOUNT = "cloud_account"
    CLOUD_RESOURCE = "cloud_resource"
    KMS_KEY = "kms_key"
    SECRET = "secret"  # noqa: S105  node category label, not a credential
    # Kubernetes (D.6 cluster-internal; D.3/D.5 own the control-plane node)
    K8S_CLUSTER = "k8s_cluster"
    K8S_OBJECT = "k8s_object"
    # Identity (D.2)
    IDENTITY = "identity"
    POLICY = "policy"
    # Data (D.4 data-security)
    DATA_CLASSIFICATION = "data_classification"
    # Vulnerability / SBOM (D.1)
    CVE_FINDING = "cve_finding"
    SBOM_PACKAGE = "sbom_package"
    CONTAINER_IMAGE = "container_image"
    # Threat intel (D.7)
    EXPLOIT_AVAILABILITY = "exploit_availability"
    THREAT_INDICATOR = "threat_indicator"
    THREAT_ACTOR = "threat_actor"
    # Compliance (D.8)
    COMPLIANCE_REQUIREMENT = "compliance_requirement"
    COMPLIANCE_FRAMEWORK = "compliance_framework"
    # Code side (D.9 / D.14 AppSec)
    CODE_REPOSITORY = "code_repository"
    COMMIT = "commit"
    BUILD = "build"
    IAC_ARTIFACT = "iac_artifact"
    DEVELOPER = "developer"
    # SaaS (D.10 SSPM)
    SAAS_TENANT = "saas_tenant"
    OAUTH_APP = "oauth_app"
    SAAS_USER = "saas_user"
    # AI/ML (D.11 AI-SPM)
    AI_SERVICE = "ai_service"
    AI_MODEL = "ai_model"
    # Network + runtime behaviour (C.x)
    NETWORK_PATH = "network_path"
    NETWORK_FLOW_EVENT = "network_flow_event"
    PROCESS_EVENT = "process_event"
    FILE_INTEGRITY_EVENT = "file_integrity_event"
    CONTAINER_LIFECYCLE_EVENT = "container_lifecycle_event"
    AUTH_EVENT = "auth_event"
    # Findings (per detecting agent)
    MISCONFIGURATION_FINDING = "misconfiguration_finding"
    SAST_FINDING = "sast_finding"
    SECRET_FINDING = "secret_finding"  # noqa: S105  finding category label
    # Remediation (A.1-A.3) + correlation (A.4)
    REMEDIATION_ACTION = "remediation_action"
    TOXIC_COMBINATION = "toxic_combination"
    ATTACK_PATH = "attack_path"
    BLAST_RADIUS_RECORD = "blast_radius_record"


class EdgeType(StrEnum):
    """Inventory-graph relationship types (catalogue "Edges written" sections)."""

    # D.1 Vulnerability
    VULNERABLE_TO = "VULNERABLE_TO"
    CONTAINS_PACKAGE = "CONTAINS_PACKAGE"
    FIXED_IN = "FIXED_IN"
    AFFECTS = "AFFECTS"
    # D.2 Identity
    ASSUMES = "ASSUMES"
    HAS_ACCESS_TO = "HAS_ACCESS_TO"
    MEMBER_OF = "MEMBER_OF"
    ATTACHED_TO = "ATTACHED_TO"
    TRUSTS = "TRUSTS"
    ASSUMABLE_BY = "ASSUMABLE_BY"
    CAN_ESCALATE_TO = "CAN_ESCALATE_TO"
    BOUNDED_BY = "BOUNDED_BY"
    # D.3 / D.5 Cloud posture
    OWNS = "OWNS"
    CONTAINS = "CONTAINS"
    IN_SUBNET = "IN_SUBNET"
    IN_VPC = "IN_VPC"
    ENCRYPTED_BY = "ENCRYPTED_BY"
    STORES_SECRET = "STORES_SECRET"  # noqa: S105  edge type label, not a credential
    RUNS_IMAGE = "RUNS_IMAGE"
    ROUTES_TO = "ROUTES_TO"
    PEERED_WITH = "PEERED_WITH"
    LOGS_TO = "LOGS_TO"
    EXPOSED_TO = "EXPOSED_TO"
    # D.4 Data security
    CLASSIFIED_AS = "CLASSIFIED_AS"
    EXPOSES_DATA = "EXPOSES_DATA"
    # D.6 Kubernetes
    RUNS_ON = "RUNS_ON"
    USES_SERVICE_ACCOUNT = "USES_SERVICE_ACCOUNT"
    IRSA_MAPPING = "IRSA_MAPPING"
    SELECTS = "SELECTS"
    INGRESS_TO = "INGRESS_TO"
    MOUNTS = "MOUNTS"
    OWNED_BY = "OWNED_BY"
    GRANTS = "GRANTS"
    BINDS = "BINDS"
    # D.7 Threat intel
    EXPLOIT_EXISTS_FOR = "EXPLOIT_EXISTS_FOR"
    MATCHES_INDICATOR = "MATCHES_INDICATOR"
    ATTRIBUTED_TO = "ATTRIBUTED_TO"
    # D.8 Compliance
    MAPS_TO_REQUIREMENT = "MAPS_TO_REQUIREMENT"
    SATISFIES = "SATISFIES"
    VIOLATES = "VIOLATES"
    PART_OF = "PART_OF"
    # D.9 / D.14 AppSec (code-to-cloud bridge)
    BUILT_FROM = "BUILT_FROM"
    COMMITTED_BY = "COMMITTED_BY"
    DEPLOYED_VIA = "DEPLOYED_VIA"
    DEFINED_IN = "DEFINED_IN"
    TRIGGERED_BY = "TRIGGERED_BY"
    PRODUCES = "PRODUCES"
    INTRODUCED_IN = "INTRODUCED_IN"
    # D.10 SSPM
    INTEGRATED_WITH = "INTEGRATED_WITH"
    FEDERATED_FROM = "FEDERATED_FROM"
    AUTHORIZED = "AUTHORIZED"
    SSO_INTO = "SSO_INTO"
    # D.11 AI-SPM
    TRAINED_ON = "TRAINED_ON"
    SERVES_MODEL = "SERVES_MODEL"
    INFERENCES_LOGGED_TO = "INFERENCES_LOGGED_TO"
    INVOKED_BY = "INVOKED_BY"
    HOSTS_AI = "HOSTS_AI"
    EXPOSES_MODEL = "EXPOSES_MODEL"
    # C.x Network
    CAN_REACH = "CAN_REACH"
    LATERAL_PATH = "LATERAL_PATH"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    POD_CAN_REACH = "POD_CAN_REACH"
    # C.x Runtime
    EXECUTED_ON = "EXECUTED_ON"
    MODIFIED = "MODIFIED"
    EXHIBITED_BEHAVIOR = "EXHIBITED_BEHAVIOR"
    OPENED_PORT = "OPENED_PORT"
    # A.1-A.3 Remediation
    REMEDIATES = "REMEDIATES"
    TARGETS = "TARGETS"
    AUTHORIZED_BY = "AUTHORIZED_BY"
    # A.4 Meta-Harness correlation
    PART_OF_PATH = "PART_OF_PATH"
    CONTRIBUTES_TO = "CONTRIBUTES_TO"
    IN_BLAST_RADIUS = "IN_BLAST_RADIUS"


__all__ = ["EdgeType", "NodeCategory"]
