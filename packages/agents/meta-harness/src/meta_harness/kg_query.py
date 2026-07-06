"""Fleet-graph read queries — A.4 Meta-Harness `kg_query` (Stage 3 PR2).

Read-only correlation surface over the Postgres `SemanticStore`: turns the fleet inventory graph
(typed nodes + edges written by every agent `kg_writer`, ADR-018/019) into two 3-hop answers:

- **blast radius** — what is reachable *downstream* of a node (outgoing BFS). Built directly on
  `SemanticStore.neighbors` (which returns reachable entities).
- **attack path** — the actual edge chain(s) *from* one node *to* another. `neighbors` discards the
  edges that connect nodes, so this reconstructs paths in-consumer via the ADR-022 edge accessor
  `SemanticStore.get_relationships_from` (single-hop) + a depth-bounded BFS **here** (the traversal
  logic stays in the consumer, not in charter).

Depth is capped at `MAX_TRAVERSAL_DEPTH` (3, P-6) — the same cap the substrate enforces.
Tenant-scoped: every read pins `customer_id` (ADR-007). **Read-only** — this writes nothing; the
findings-as-decorations migration (`ATTACK_PATH` / `BLAST_RADIUS_RECORD` graph nodes) stays
deferred. A.4-only consumer this cycle (#718-D4).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.semantic import (
    MAX_TRAVERSAL_DEPTH,
    EntityRow,
    RelationshipRow,
    SemanticStore,
)


@dataclass(frozen=True, slots=True)
class BlastRadiusResult:
    """What is reachable downstream of `seed_entity_id` within `depth` hops (read-only)."""

    seed_entity_id: str
    depth: int
    edge_types: tuple[str, ...] | None
    reachable: tuple[EntityRow, ...]

    @property
    def count(self) -> int:
        return len(self.reachable)


@dataclass(frozen=True, slots=True)
class PathEdge:
    """One directed hop in a reconstructed attack path."""

    src_entity_id: str
    dst_entity_id: str
    relationship_type: str


@dataclass(frozen=True, slots=True)
class AttackPathResult:
    """All simple edge chains from `src_entity_id` to `dst_entity_id` within `max_depth` (read-only)."""

    src_entity_id: str
    dst_entity_id: str
    max_depth: int
    paths: tuple[tuple[PathEdge, ...], ...]

    @property
    def found(self) -> bool:
        return bool(self.paths)

    @property
    def shortest(self) -> tuple[PathEdge, ...] | None:
        """The fewest-hops path, or ``None`` when no path exists."""
        return min(self.paths, key=len) if self.paths else None


@dataclass(frozen=True, slots=True)
class ToxicCombination:
    """A public-data-exposure attack path: over-permissioned principal → public
    bucket → sensitive data. The `path` is the evidence chain (2 edges)."""

    principal_id: str
    resource_id: str
    data_classification_id: str
    path: tuple[PathEdge, PathEdge]


# Secret-type data classifications (data-security ClassifierLabel secret labels). A public
# resource exposing one of these is a publicly-readable credential — path 3 (ADR-023). The modern
# formats (private_key, provider tokens) were added after adversarial red-teaming found a leaked
# private key was classified but NOT alerted (this allowlist was blind to it).
_SECRET_DATA_TYPES = frozenset(
    {
        "aws_access_key",
        "jwt",
        "generic_api_token",
        "private_key",
        "github_token",
        "google_api_key",
        "stripe_key",
        "slack_token",
    }
)


@dataclass(frozen=True, slots=True)
class PublicSecretExposure:
    """A public resource that EXPOSES_DATA a secret-type classification (a publicly-
    readable credential). `data_type` is the secret kind (e.g. ``aws_access_key``)."""

    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class PublicUnencryptedExposure:
    """A public resource that EXPOSES_DATA sensitive data AND is unencrypted at rest —
    publicly-exposed sensitive data that isn't even encrypted (exposure + compliance
    failure). `data_type` is the exposed data kind (e.g. ``ssn``)."""

    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class ExternalTrustExposure:
    """An externally-trusted principal that HAS_ACCESS_TO a public resource EXPOSING data —
    a foreign account can assume the role and reach sensitive data (path 8). `data_type` is
    the exposed data kind (e.g. ``ssn``)."""

    principal_id: str
    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class InternetExposedVulnerableWorkload:
    """An internet-exposed workload running an image with a known CVE (path 2). The
    workload --RUNS_IMAGE--> image --VULNERABLE_TO--> CVE chain: a foreign attacker can
    reach the exposed service and exploit the vulnerable image. `severity` is the CVE's."""

    workload_id: str
    image_id: str
    cve_id: str
    severity: str
    kev_listed: bool = False  # True if the CVE is CISA KEV-listed
    epss_score: float | None = None  # EPSS probability score for this CVE (0..1)


@dataclass(frozen=True, slots=True)
class FineGrainedDataExposure:
    """A principal with a CONCRETE (non-admin) grant to a public resource exposing data —
    a least-privilege violation the admin-only seed (path 1) misses (path 4). `data_type`
    is the exposed data kind (e.g. ``ssn``)."""

    principal_id: str
    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class CrownJewelExposure:
    """The crown-jewel 4-hop (path 5): an internet-exposed workload running a vulnerable
    image whose task role can reach sensitive data. An attacker exploits the exposed +
    vulnerable workload, assumes its role, and reads the data. The single most dangerous
    pattern — exposure, exploitability, privilege, and sensitivity all on one workload."""

    workload_id: str
    image_id: str
    cve_id: str
    role_id: str
    resource_id: str
    data_classification_id: str
    data_type: str
    severity: str = ""  # the CVE's severity label (CRITICAL/HIGH/…), for worst-CVE rollup
    kev_listed: bool = False  # True if the CVE is CISA KEV-listed
    epss_score: float | None = None  # EPSS probability score for this CVE (0..1)


@dataclass(frozen=True, slots=True)
class PrivilegedVulnerableWorkload:
    """A privileged K8s pod running an image with a known CVE (path 6). The pod
    --RUNS_IMAGE--> image --VULNERABLE_TO--> CVE chain: exploit the CVE for RCE in the
    container, then escape to the node via the privileged container. `severity` is the CVE's."""

    workload_id: str
    image_id: str
    cve_id: str
    severity: str
    kev_listed: bool = False  # True if the CVE is CISA KEV-listed
    epss_score: float | None = None  # EPSS probability score for this CVE (0..1)


@dataclass(frozen=True, slots=True)
class LateralReachable:
    """A public foothold that CAN_REACH / PEERED_WITH a target which is either a vulnerable host or a
    managed datastore (derived lateral movement, Cycle 2 Task 3). Distinct from :class:`LateralMovement`
    (which uses observed ``COMMUNICATES_WITH`` edges from flow logs); this fires from *config* alone —
    before any traffic — and catches both vulnerable-host and sensitive-datastore pivot targets. The
    ``reach_kind`` records the network mechanism (``lateral_sg`` or ``vpc_peering``); ``impact``
    distinguishes the threat model (``vulnerable_host`` vs ``sensitive_resource``). Read-only."""

    foothold_id: str
    target_id: str
    reach_kind: str  # "lateral_sg" | "vpc_peering" (from edge property "method")
    impact: str  # "vulnerable_host" | "sensitive_resource"
    cve_id: str = ""
    severity: str = ""


@dataclass(frozen=True, slots=True)
class LateralMovement:
    """A public-facing foothold with an OBSERVED network flow to an internal host that carries a
    known CVE (path #14). The foothold endpoint is ``OWNED_BY`` a public resource and
    ``COMMUNICATES_WITH`` a dst endpoint ``OWNED_BY`` a target resource that is ``VULNERABLE_TO``
    a CVE — a perimeter breach pivoting laterally to a soft internal target. This uses observed
    flow edges, NOT derived reachability (CAN_REACH, Stage 3). ``severity`` is the target CVE's."""

    foothold_id: str
    target_id: str
    cve_id: str
    severity: str
    kev_listed: bool = False  # True if the CVE is CISA KEV-listed
    epss_score: float | None = None  # EPSS probability score for this CVE (0..1)


@dataclass(frozen=True, slots=True)
class HostVulnerableWorkload:
    """An internet-exposed compute host (EC2/VM) with a known OS-package CVE (path #15). The
    instance node is_public AND carries a DIRECT ``VULNERABLE_TO`` edge (host/AMI scan, not a
    container ``RUNS_IMAGE`` hop) — a reachable host-OS RCE. ``severity`` is the CVE's label."""

    host_id: str
    cve_id: str
    severity: str
    kev_listed: bool = False  # True if the CVE is CISA KEV-listed
    epss_score: float | None = None  # EPSS probability score for this CVE (0..1)


@dataclass(frozen=True, slots=True)
class RbacPrivilegeEscalation:
    """A K8s ServiceAccount bound to a cluster-admin-equivalent RBAC role (path #20). The SA
    --BINDS--> role node whose ``is_admin`` property is True (wildcard verbs on wildcard
    resources). Whoever controls the SA can do anything in the cluster — a privilege-escalation
    path to full cluster control. ``role_name`` is the bound role's name for the headline."""

    subject_id: str
    role_id: str
    subject_name: str
    role_name: str


@dataclass(frozen=True, slots=True)
class RbacEscalationToCloudData:
    """A K8s ServiceAccount that is BOTH cluster-admin AND reaches sensitive cloud data via IRSA
    (cross-domain intersection: k8s-posture + identity, path P4a).

    Walk: ``K8S_OBJECT{service-account} --BINDS--> K8S_OBJECT{is_admin=True}``
    AND ``K8S_OBJECT{service-account} --IRSA_MAPPING--> IDENTITY(cloud role)
    --HAS_ACCESS_TO--> CLOUD_RESOURCE --EXPOSES_DATA--> DATA_CLASSIFICATION``.
    The SA has full cluster control (admin binding) PLUS a cloud-data breach path (IRSA).
    ``admin_role_id`` is the K8S_OBJECT role with ``is_admin=True``; ``cloud_role_id`` is the
    cloud IAM IDENTITY the SA maps to. Read-only."""

    subject_id: str
    admin_role_id: str
    cloud_role_id: str
    resource_id: str
    data_classification_id: str
    data_type: str
    role_name: str


@dataclass(frozen=True, slots=True)
class ExposedAiWithSensitiveData:
    """An internet-exposed AI service whose training-data bucket is public + sensitive
    (path 10). The service EXPOSES_MODEL to the internet AND HAS_ACCESS_TO a bucket that
    EXPOSES_DATA — a leaked model plus exposed training data. `data_type` is the data kind."""

    service_id: str
    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class ExposedKmsKey:
    """A KMS key whose key policy is internet-open (path #21) — the encryption boundary is open."""

    resource_id: str


@dataclass(frozen=True, slots=True)
class ExposedKmsKeyOverData:
    """A public KMS key that ALSO protects classified data (path P4b).

    The encryption boundary is internet-open AND it guards sensitive data — the combination
    is worse than either leg alone: an attacker who reaches the public key policy can now
    decrypt the classified data it protects.

    Walk: ``CLOUD_RESOURCE{kind=kms-key, is_public=True} --EXPOSES_DATA--> DATA_CLASSIFICATION``."""

    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class ExposedDatabase:
    """A publicly-accessible managed database (path #19) — an internet-facing data store. The
    resource itself is the finding; a managed DB is sensitive-by-assumption."""

    resource_id: str
    engine: str


@dataclass(frozen=True, slots=True)
class CicdCompromise:
    """A live resource deployed from a repo that holds a leaked credential (NEX-304). An attacker with
    the leaked pipeline credential can poison the deploy → the production resource is compromised."""

    resource_id: str
    repo_id: str


@dataclass(frozen=True, slots=True)
class KmsKeyAccess:
    """A principal that can use a KMS key which protects sensitive data (NEX-202a). Compromising the
    principal → decrypt the data. The key's impact is modelled via EXPOSES_DATA (the spike reframe)."""

    principal_id: str
    kms_key_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class LeakedCredentialToData:
    """An IAM credential committed in source code that can reach sensitive data (cross-domain:
    appsec + identity, path #17). A user OWNS a SECRET (access key) that is DEFINED_IN a repo
    (leaked) AND HAS_ACCESS_TO a public resource EXPOSING data — a live credential, in code,
    that grants the data. ``credential_id`` is the access key ID (non-secret)."""

    principal_id: str
    credential_id: str
    repo_id: str
    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class K8sEscapeToCloudData:
    """A privileged K8s pod that escapes to its node and reaches sensitive data via an
    IRSA-mapped cloud IAM role (cross-domain: k8s-posture + identity, path C-2).

    Walk: ``K8S_OBJECT{privileged} --USES_SERVICE_ACCOUNT--> K8S_OBJECT(service-account)
    --IRSA_MAPPING--> IDENTITY(cloud IAM role) --HAS_ACCESS_TO--> CLOUD_RESOURCE
    --EXPOSES_DATA--> DATA_CLASSIFICATION``.
    ``pod_id`` is the privileged pod; ``service_account_id`` the SA it runs as;
    ``role_id`` the cloud IAM role the SA maps to. Read-only."""

    pod_id: str
    service_account_id: str
    role_id: str
    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class StoredSecretToData:
    """A workload that STORES_SECRET an embedded credential whose owning identity can reach
    sensitive data (cross-domain: cloud-posture + identity, path W6).

    Walk: ``CLOUD_RESOURCE --STORES_SECRET--> SECRET --OWNED_BY--> IDENTITY
    --HAS_ACCESS_TO--> CLOUD_RESOURCE --EXPOSES_DATA--> DATA_CLASSIFICATION``.
    ``secret_id`` is the secret node (the embedded key), ``principal_id`` is the IAM identity
    that owns it. Read-only."""

    workload_id: str
    secret_id: str
    principal_id: str
    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class PrivilegeEscalationToData:
    """A principal that can reach sensitive data by ASSUMING another role (privilege escalation),
    without any direct grant of its own (path #13). The principal ASSUMES a role that HAS_ACCESS_TO
    a public resource EXPOSING data — the principal escalates to the role to reach the data."""

    principal_id: str
    role_id: str
    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class EscalationMethodToData:
    """A principal that grants itself another identity's privileges via a privesc METHOD, then
    reaches sensitive data (cross-domain: identity + data-security, path C-3).

    Walk: ``IDENTITY --CAN_ESCALATE_TO--> IDENTITY(target) --HAS_ACCESS_TO--> CLOUD_RESOURCE
    --EXPOSES_DATA--> DATA_CLASSIFICATION``.
    Distinct from :class:`PrivilegeEscalationToData` (which walks ``ASSUMES`` — a role the
    principal is *allowed* to assume); this walks ``CAN_ESCALATE_TO`` — a *method* (e.g.
    ``iam:AttachUserPolicy`` / ``PassRole`` / ``CreatePolicyVersion``) by which the principal
    can grant itself the target's privileges. ``method`` is the privesc technique name
    captured from the edge's ``method`` / ``via_action`` property. Read-only."""

    principal_id: str
    target_id: str
    method: str
    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class IacMisconfigDeployed:
    """A live cloud resource deployed from infrastructure-as-code that has a misconfiguration
    (cross-domain: cloud-posture/data-security + appsec). The resource DEPLOYED_VIA an IAC_ARTIFACT
    (which appsec writes only for a misconfigured IaC file) DEFINED_IN a repo — the code-to-cloud
    root cause: the live resource's misconfiguration is traceable to the exact repo + file."""

    resource_id: str
    artifact_id: str
    artifact_ref: str
    repo_id: str


@dataclass(frozen=True, slots=True)
class RuntimeExploitVulnerableWorkload:
    """An active runtime detection firing ON a workload running a vulnerable image (cross-domain:
    runtime + vulnerability). A runtime event EXECUTED_ON a host that RUNS_IMAGE a VULNERABLE_TO
    image — suspicious behaviour on a known-vulnerable workload, i.e. likely active exploitation."""

    host_id: str
    event_id: str
    image_id: str
    cve_id: str
    severity: str
    kev_listed: bool = False  # True if the CVE is CISA KEV-listed
    epss_score: float | None = None  # EPSS probability score for this CVE (0..1)


@dataclass(frozen=True, slots=True)
class MaliciousDestinationExposure:
    """An owned cloud resource communicating with a known-malicious IP (cross-domain: network +
    threat-intel). The endpoint OWNED_BY the resource COMMUNICATES_WITH a destination that
    MATCHES_INDICATOR a threat-intel IOC — active C2/exfil signal on the account's own resource.

    ``actor_id`` / ``actor_name`` carry threat-actor attribution when the IOC is linked to a known
    intrusion-set (e.g. "APT29").  Population is operator-feed-dependent: both fields default to
    ``""`` (absent → no attribution, title/evidence unchanged).
    """

    resource_id: str
    destination_id: str
    indicator_id: str
    indicator_value: str
    actor_id: str = ""
    actor_name: str = ""


@dataclass(frozen=True, slots=True)
class ResourceBasedDataExposure:
    """A principal granted access by a resource's OWN policy (an S3 bucket policy) to a public
    resource exposing sensitive data — access invisible to IAM-side grant resolution (gap #7).
    `principal_arn` is the named grantee from the bucket policy; `data_type` the exposed kind."""

    principal_arn: str
    resource_id: str
    data_classification_id: str
    data_type: str


@dataclass(frozen=True, slots=True)
class SupplyChainSbom:
    """A public workload running an image whose SBOM package has a CVE (supply-chain, NEX-305).

    Package-level attribution over :class:`InternetExposedVulnerableWorkload` (which stops at
    image→CVE): the full chain is ``public workload --RUNS_IMAGE--> image
    --CONTAINS_PACKAGE--> SBOM_PACKAGE --VULNERABLE_TO--> CVE``.
    ``package_name`` names the specific dependency to bump — remediation granularity."""

    workload_id: str
    image_id: str
    package_name: str
    cve_id: str
    severity: str
    kev_listed: bool = False
    epss_score: float | None = None


def _validate_depth(depth: int) -> int:
    if depth < 1 or depth > MAX_TRAVERSAL_DEPTH:
        raise ValueError(f"depth must be in [1, {MAX_TRAVERSAL_DEPTH}], got {depth}")
    return depth


def _float_or_none(value: object) -> float | None:
    """Return ``float(value)`` when value is a number, else None.

    CVE properties stored as int/float are both valid; None/missing stays None.
    """
    if isinstance(value, (int, float)):
        return float(value)
    return None


class KgQuery:
    """Tenant-scoped read-only correlation queries over the fleet graph.

    Mirrors the agent `kg_writer` shape: constructed with `(SemanticStore, customer_id)`; every
    read pins the tenant. No writes.
    """

    def __init__(self, semantic_store: SemanticStore, customer_id: str) -> None:
        self._semantic_store = semantic_store
        self._customer_id = customer_id

    async def blast_radius(
        self,
        *,
        entity_id: str,
        edge_types: tuple[str, ...] | None = None,
        depth: int = MAX_TRAVERSAL_DEPTH,
    ) -> BlastRadiusResult:
        """Entities reachable downstream of `entity_id` within `depth` outgoing hops.

        Pure consumer of `SemanticStore.neighbors` — no new charter dependency.
        """
        depth = _validate_depth(depth)
        reachable = await self._semantic_store.neighbors(
            tenant_id=self._customer_id,
            entity_id=entity_id,
            depth=depth,
            edge_types=edge_types,
        )
        return BlastRadiusResult(
            seed_entity_id=entity_id,
            depth=depth,
            edge_types=edge_types,
            reachable=tuple(reachable),
        )

    async def attack_path(
        self,
        *,
        src_entity_id: str,
        dst_entity_id: str,
        edge_types: tuple[str, ...] | None = None,
        max_depth: int = MAX_TRAVERSAL_DEPTH,
    ) -> AttackPathResult:
        """All simple edge chains from `src` to `dst` within `max_depth` hops.

        Depth-bounded BFS over the ADR-022 `get_relationships_from` edge accessor — the path
        reconstruction lives here (the consumer), not in charter. Cycles are excluded (a node
        never repeats within a single path). Returns an empty result when src == dst.
        """
        max_depth = _validate_depth(max_depth)
        if src_entity_id == dst_entity_id:
            return AttackPathResult(src_entity_id, dst_entity_id, max_depth, ())

        paths: list[tuple[PathEdge, ...]] = []
        # Seed: 1-edge paths out of src.
        frontier: list[tuple[PathEdge, ...]] = []
        for edge in await self._edges_from(src_entity_id, edge_types):
            step = PathEdge(edge.src_entity_id, edge.dst_entity_id, edge.relationship_type)
            if edge.dst_entity_id == dst_entity_id:
                paths.append((step,))
            else:
                frontier.append((step,))

        # Expand one hop at a time until the depth cap. `current_len` is the edge-count of the
        # paths currently in `frontier`.
        current_len = 1
        while frontier and current_len < max_depth:
            next_frontier: list[tuple[PathEdge, ...]] = []
            for path in frontier:
                tail = path[-1].dst_entity_id
                visited = {src_entity_id, *(e.dst_entity_id for e in path)}
                for edge in await self._edges_from(tail, edge_types):
                    if edge.dst_entity_id in visited:
                        continue  # no cycles within a single path
                    step = PathEdge(edge.src_entity_id, edge.dst_entity_id, edge.relationship_type)
                    extended = (*path, step)
                    if edge.dst_entity_id == dst_entity_id:
                        paths.append(extended)
                    else:
                        next_frontier.append(extended)
            frontier = next_frontier
            current_len += 1

        return AttackPathResult(src_entity_id, dst_entity_id, max_depth, tuple(paths))

    async def find_public_data_exposure(
        self, *, over_permissioned_principal_ids: Sequence[str]
    ) -> list[ToxicCombination]:
        """Find principal --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data paths.

        EXPOSES_DATA is only written for public buckets, so its presence proves both
        the public and sensitive-data legs. Read-only; seeded by the caller with the
        over-permissioned principals (from identity's OVERPRIVILEGE findings).
        """
        hits: list[ToxicCombination] = []
        for principal_id in over_permissioned_principal_ids:
            for access in await self._edges_from(principal_id, (EdgeType.HAS_ACCESS_TO.value,)):
                bucket_id = access.dst_entity_id
                for expose in await self._edges_from(bucket_id, (EdgeType.EXPOSES_DATA.value,)):
                    hits.append(
                        ToxicCombination(
                            principal_id=principal_id,
                            resource_id=bucket_id,
                            data_classification_id=expose.dst_entity_id,
                            path=(
                                PathEdge(principal_id, bucket_id, access.relationship_type),
                                PathEdge(bucket_id, expose.dst_entity_id, expose.relationship_type),
                            ),
                        )
                    )
        return hits

    async def find_public_secret_exposure(self) -> list[PublicSecretExposure]:
        """Find public resources that EXPOSES_DATA a secret-type classification.

        EXPOSES_DATA is written only for public buckets, so its presence proves the
        resource is public; we keep only edges to a SECRET data-type — a publicly-readable
        credential. Read-only; enumerates the tenant's CLOUD_RESOURCE nodes (no seed)."""
        hits: list[PublicSecretExposure] = []
        resources = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        for resource in resources:
            for expose in await self._edges_from(
                resource.entity_id, (EdgeType.EXPOSES_DATA.value,)
            ):
                dc = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                )
                if dc is None:
                    continue
                data_type = str(dc.properties.get("data_type", ""))
                if data_type in _SECRET_DATA_TYPES:
                    hits.append(
                        PublicSecretExposure(
                            resource_id=resource.entity_id,
                            data_classification_id=dc.entity_id,
                            data_type=data_type,
                        )
                    )
        return hits

    async def find_public_unencrypted_exposure(self) -> list[PublicUnencryptedExposure]:
        """Find UNENCRYPTED public resources that EXPOSES_DATA sensitive data.

        EXPOSES_DATA is written only for public buckets (the public + has-data legs);
        we additionally keep only resources explicitly marked ``is_encrypted=False`` —
        publicly-exposed sensitive data that isn't even encrypted at rest. Read-only;
        enumerates the tenant's CLOUD_RESOURCE nodes (no seed)."""
        hits: list[PublicUnencryptedExposure] = []
        resources = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        for resource in resources:
            if resource.properties.get("is_encrypted") is not False:
                continue
            for expose in await self._edges_from(
                resource.entity_id, (EdgeType.EXPOSES_DATA.value,)
            ):
                dc = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                )
                if dc is None:
                    continue
                hits.append(
                    PublicUnencryptedExposure(
                        resource_id=resource.entity_id,
                        data_classification_id=dc.entity_id,
                        data_type=str(dc.properties.get("data_type", "")),
                    )
                )
        return hits

    async def find_external_trust_exposure(self) -> list[ExternalTrustExposure]:
        """Find externally-trusted principals with HAS_ACCESS_TO a public resource exposing data.

        Self-seeded (no caller list): enumerates IDENTITY nodes marked ``external_trust=True``
        (identity's offline trust-policy analysis), follows HAS_ACCESS_TO to a resource, then
        EXPOSES_DATA (written only for public buckets) to a data classification. A foreign
        account assuming the role reaches that sensitive data. Read-only."""
        hits: list[ExternalTrustExposure] = []
        principals = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.IDENTITY.value
        )
        for principal in principals:
            if principal.properties.get("external_trust") is not True:
                continue
            for access in await self._edges_from(
                principal.entity_id, (EdgeType.HAS_ACCESS_TO.value,)
            ):
                for expose in await self._edges_from(
                    access.dst_entity_id, (EdgeType.EXPOSES_DATA.value,)
                ):
                    dc = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                    )
                    if dc is None:
                        continue
                    hits.append(
                        ExternalTrustExposure(
                            principal_id=principal.entity_id,
                            resource_id=access.dst_entity_id,
                            data_classification_id=dc.entity_id,
                            data_type=str(dc.properties.get("data_type", "")),
                        )
                    )
        return hits

    async def find_internet_exposed_vulnerable_workload(
        self,
    ) -> list[InternetExposedVulnerableWorkload]:
        """Find internet-exposed workloads running an image with a known CVE (path 2).

        The mechanism-② join: enumerates ``is_public`` CLOUD_RESOURCE workloads (cloud-posture
        ECS), follows ``RUNS_IMAGE`` to the image node, then ``VULNERABLE_TO`` (written by
        vulnerability onto the SAME image node, keyed by image ref) to each CVE. One hit per
        (exposed workload, CVE). Read-only; self-seeded (no caller list)."""
        hits: list[InternetExposedVulnerableWorkload] = []
        resources = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        for workload in resources:
            if workload.properties.get("is_public") is not True:
                continue
            for runs in await self._edges_from(workload.entity_id, (EdgeType.RUNS_IMAGE.value,)):
                for vuln in await self._edges_from(
                    runs.dst_entity_id, (EdgeType.VULNERABLE_TO.value,)
                ):
                    cve = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=vuln.dst_entity_id
                    )
                    if cve is None:
                        continue
                    hits.append(
                        InternetExposedVulnerableWorkload(
                            workload_id=workload.entity_id,
                            image_id=runs.dst_entity_id,
                            cve_id=cve.external_id,
                            severity=str(cve.properties.get("severity", "")),
                            kev_listed=bool(cve.properties.get("kev", False)),
                            epss_score=_float_or_none(cve.properties.get("epss_score")),
                        )
                    )
        return hits

    async def find_fine_grained_data_exposure(self) -> list[FineGrainedDataExposure]:
        """Find principals with a HAS_ACCESS_TO grant to a public resource exposing data.

        Self-seeded (no caller list): enumerates IDENTITY nodes, follows HAS_ACCESS_TO to a
        resource, then EXPOSES_DATA (written only for public buckets) to a data classification.
        Unlike :meth:`find_public_data_exposure` (caller-seeded with admin principals), this
        surfaces fine-grained least-privilege violations — a non-admin principal with specific
        access to sensitive public data (path 4). Read-only."""
        hits: list[FineGrainedDataExposure] = []
        principals = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.IDENTITY.value
        )
        for principal in principals:
            for access in await self._edges_from(
                principal.entity_id, (EdgeType.HAS_ACCESS_TO.value,)
            ):
                for expose in await self._edges_from(
                    access.dst_entity_id, (EdgeType.EXPOSES_DATA.value,)
                ):
                    dc = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                    )
                    if dc is None:
                        continue
                    hits.append(
                        FineGrainedDataExposure(
                            principal_id=principal.entity_id,
                            resource_id=access.dst_entity_id,
                            data_classification_id=dc.entity_id,
                            data_type=str(dc.properties.get("data_type", "")),
                        )
                    )
        return hits

    async def find_kms_key_access(self) -> list[KmsKeyAccess]:
        """Find a principal that can use a KMS key which protects sensitive data (NEX-202a).

        Self-seeded: IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE(kind=kms-key) --EXPOSES_DATA--> data.
        Per the NEX-202 spike, a KMS key's impact is modelled as EXPOSES_DATA to the data it protects,
        so no new sink/walker is needed — this just filters the access-to-data shape to KMS keys, giving
        the distinct ``kms_key_access`` family (compromise the principal → decrypt the crown data)."""
        hits: list[KmsKeyAccess] = []
        for principal in await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.IDENTITY.value
        ):
            for access in await self._edges_from(
                principal.entity_id, (EdgeType.HAS_ACCESS_TO.value,)
            ):
                key = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=access.dst_entity_id
                )
                if key is None or key.properties.get("kind") != "kms-key":
                    continue
                for expose in await self._edges_from(
                    access.dst_entity_id, (EdgeType.EXPOSES_DATA.value,)
                ):
                    dc = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                    )
                    if dc is None:
                        continue
                    hits.append(
                        KmsKeyAccess(
                            principal_id=principal.entity_id,
                            kms_key_id=access.dst_entity_id,
                            data_classification_id=dc.entity_id,
                            data_type=str(dc.properties.get("data_type", "")),
                        )
                    )
        return hits

    async def find_crown_jewel_exposure(self) -> list[CrownJewelExposure]:
        """Find the crown-jewel 4-hop: exposed + vulnerable workload whose role reaches data.

        Assembles every leg built for paths 2 and 4 on one pivot — the workload:
        ``is_public`` workload that ``RUNS_IMAGE`` a ``VULNERABLE_TO`` image AND ``ASSUMES`` a
        role with ``HAS_ACCESS_TO`` a resource that ``EXPOSES_DATA``. One hit per
        (CVE, reachable sensitive resource) pair. Read-only; self-seeded."""
        hits: list[CrownJewelExposure] = []
        resources = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        for workload in resources:
            if workload.properties.get("is_public") is not True:
                continue
            cves = await self._vulnerable_images(workload.entity_id)
            if not cves:
                continue
            reachable = await self._role_reachable_data(workload.entity_id)
            for image_id, cve in cves:
                for role_id, resource_id, dc in reachable:
                    hits.append(
                        CrownJewelExposure(
                            workload_id=workload.entity_id,
                            image_id=image_id,
                            cve_id=cve.external_id,
                            role_id=role_id,
                            resource_id=resource_id,
                            data_classification_id=dc.entity_id,
                            data_type=str(dc.properties.get("data_type", "")),
                            severity=str(cve.properties.get("severity", "")),
                            kev_listed=bool(cve.properties.get("kev", False)),
                            epss_score=_float_or_none(cve.properties.get("epss_score")),
                        )
                    )
        return hits

    async def _vulnerable_images(self, workload_id: str) -> list[tuple[str, EntityRow]]:
        """(image_id, CVE row) for each CVE on an image the workload RUNS_IMAGE."""
        out: list[tuple[str, EntityRow]] = []
        for runs in await self._edges_from(workload_id, (EdgeType.RUNS_IMAGE.value,)):
            for vuln in await self._edges_from(runs.dst_entity_id, (EdgeType.VULNERABLE_TO.value,)):
                cve = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=vuln.dst_entity_id
                )
                if cve is not None:
                    out.append((runs.dst_entity_id, cve))
        return out

    async def _role_reachable_data(self, workload_id: str) -> list[tuple[str, str, EntityRow]]:
        """(role_id, resource_id, data row) the workload's ASSUMES-role can reach via data."""
        out: list[tuple[str, str, EntityRow]] = []
        for assumes in await self._edges_from(workload_id, (EdgeType.ASSUMES.value,)):
            role_id = assumes.dst_entity_id
            for access in await self._edges_from(role_id, (EdgeType.HAS_ACCESS_TO.value,)):
                for expose in await self._edges_from(
                    access.dst_entity_id, (EdgeType.EXPOSES_DATA.value,)
                ):
                    dc = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                    )
                    if dc is not None:
                        out.append((role_id, access.dst_entity_id, dc))
        return out

    async def find_privileged_vulnerable_workload(self) -> list[PrivilegedVulnerableWorkload]:
        """Find privileged K8s pods running an image with a known CVE (path 6).

        Self-seeded: enumerates ``privileged`` K8S_OBJECT pods, follows ``RUNS_IMAGE`` to the
        image node, then ``VULNERABLE_TO`` (written by vulnerability onto the same image node)
        to each CVE. A privileged container can escape to the node, so a CVE in its image is a
        node-compromise path. Read-only."""
        hits: list[PrivilegedVulnerableWorkload] = []
        pods = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.K8S_OBJECT.value
        )
        for pod in pods:
            if pod.properties.get("privileged") is not True:
                continue
            for runs in await self._edges_from(pod.entity_id, (EdgeType.RUNS_IMAGE.value,)):
                for vuln in await self._edges_from(
                    runs.dst_entity_id, (EdgeType.VULNERABLE_TO.value,)
                ):
                    cve = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=vuln.dst_entity_id
                    )
                    if cve is None:
                        continue
                    hits.append(
                        PrivilegedVulnerableWorkload(
                            workload_id=pod.entity_id,
                            image_id=runs.dst_entity_id,
                            cve_id=cve.external_id,
                            severity=str(cve.properties.get("severity", "")),
                            kev_listed=bool(cve.properties.get("kev", False)),
                            epss_score=_float_or_none(cve.properties.get("epss_score")),
                        )
                    )
        return hits

    async def find_internet_exposed_host_vulnerable(self) -> list[HostVulnerableWorkload]:
        """Find internet-exposed compute hosts (EC2/VM) with a known OS-package CVE (path #15).

        Self-seeded: enumerates CLOUD_RESOURCE nodes that are ``is_public`` and follows a DIRECT
        ``VULNERABLE_TO`` edge to a CVE. Distinct from the container path: there the CVE hangs off
        the image node via ``RUNS_IMAGE``; here the host scan (``trivy vm/rootfs``, keyed by the
        instance ARN) records the CVE on the instance node itself. An exposed host with an OS RCE.
        Read-only."""
        hits: list[HostVulnerableWorkload] = []
        resources = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        for host in resources:
            if host.properties.get("is_public") is not True:
                continue
            for vuln in await self._edges_from(host.entity_id, (EdgeType.VULNERABLE_TO.value,)):
                cve = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=vuln.dst_entity_id
                )
                if cve is None:
                    continue
                hits.append(
                    HostVulnerableWorkload(
                        host_id=host.entity_id,
                        cve_id=cve.external_id,
                        severity=str(cve.properties.get("severity", "")),
                        kev_listed=bool(cve.properties.get("kev", False)),
                        epss_score=_float_or_none(cve.properties.get("epss_score")),
                    )
                )
        return hits

    async def find_rbac_privilege_escalation(self) -> list[RbacPrivilegeEscalation]:
        """Find K8s ServiceAccounts bound to a cluster-admin-equivalent RBAC role (path #20).

        Self-seeded: enumerates K8S_OBJECT service-accounts, follows ``BINDS`` to the role node,
        and emits a hit when that role's ``is_admin`` property is True (k8s-posture marks a role
        admin when a rule grants wildcard verbs on wildcard resources). A bound cluster-admin SA
        is a privilege-escalation path to full cluster control. Read-only."""
        hits: list[RbacPrivilegeEscalation] = []
        objects = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.K8S_OBJECT.value
        )
        for sa in objects:
            if sa.properties.get("kind") != "service-account":
                continue
            for binds in await self._edges_from(sa.entity_id, (EdgeType.BINDS.value,)):
                role = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=binds.dst_entity_id
                )
                if role is None or role.properties.get("is_admin") is not True:
                    continue
                hits.append(
                    RbacPrivilegeEscalation(
                        subject_id=sa.entity_id,
                        role_id=role.entity_id,
                        subject_name=str(sa.properties.get("name", "")),
                        role_name=str(role.properties.get("name", "")),
                    )
                )
        return hits

    async def find_rbac_escalation_to_cloud_data(
        self,
    ) -> list[RbacEscalationToCloudData]:
        """Find service accounts that are BOTH cluster-admin AND reach cloud data via IRSA (P4a).

        Intersection: enumerates K8S_OBJECT service-accounts, checks for (a) a ``BINDS`` edge to
        a K8S_OBJECT with ``is_admin=True`` (the cluster-admin leg), AND (b) an ``IRSA_MAPPING``
        edge to an IDENTITY that ``HAS_ACCESS_TO`` a resource that ``EXPOSES_DATA`` to a
        DATA_CLASSIFICATION (the cloud-data leg). A SA satisfying BOTH legs is a higher-severity
        finding: full cluster control plus a direct cloud-data breach path. Read-only."""
        hits: list[RbacEscalationToCloudData] = []
        objects = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.K8S_OBJECT.value
        )
        for sa in objects:
            if sa.properties.get("kind") != "service-account":
                continue

            # Leg A: find all is_admin bindings for this SA.
            admin_binds: list[tuple[str, str]] = []  # (role_entity_id, role_name)
            for binds in await self._edges_from(sa.entity_id, (EdgeType.BINDS.value,)):
                role = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=binds.dst_entity_id
                )
                if role is None or role.properties.get("is_admin") is not True:
                    continue
                admin_binds.append((role.entity_id, str(role.properties.get("name", ""))))
            if not admin_binds:
                continue  # fast path: no admin binding → skip IRSA walk

            # Leg B: follow IRSA_MAPPING → HAS_ACCESS_TO → EXPOSES_DATA.
            for irsa in await self._edges_from(sa.entity_id, (EdgeType.IRSA_MAPPING.value,)):
                cloud_role_id = irsa.dst_entity_id
                for access in await self._edges_from(
                    cloud_role_id, (EdgeType.HAS_ACCESS_TO.value,)
                ):
                    for expose in await self._edges_from(
                        access.dst_entity_id, (EdgeType.EXPOSES_DATA.value,)
                    ):
                        dc = await self._semantic_store.get_entity(
                            tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                        )
                        if dc is None:
                            continue
                        for admin_role_id, role_name in admin_binds:
                            hits.append(
                                RbacEscalationToCloudData(
                                    subject_id=sa.entity_id,
                                    admin_role_id=admin_role_id,
                                    cloud_role_id=cloud_role_id,
                                    resource_id=access.dst_entity_id,
                                    data_classification_id=dc.entity_id,
                                    data_type=str(dc.properties.get("data_type", "")),
                                    role_name=role_name,
                                )
                            )
        return hits

    async def find_exposed_ai_with_sensitive_data(self) -> list[ExposedAiWithSensitiveData]:
        """Find internet-exposed AI services whose training-data bucket is public + sensitive.

        Self-seeded: enumerates AI_SERVICE nodes that ``EXPOSES_MODEL`` to the internet sentinel
        AND ``HAS_ACCESS_TO`` a bucket that ``EXPOSES_DATA`` (written only for public buckets).
        A leaked/abusable model plus exposed sensitive training data (path 10). Read-only."""
        hits: list[ExposedAiWithSensitiveData] = []
        services = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.AI_SERVICE.value
        )
        for svc in services:
            exposed = await self._edges_from(svc.entity_id, (EdgeType.EXPOSES_MODEL.value,))
            if not exposed:
                continue
            for access in await self._edges_from(svc.entity_id, (EdgeType.HAS_ACCESS_TO.value,)):
                for expose in await self._edges_from(
                    access.dst_entity_id, (EdgeType.EXPOSES_DATA.value,)
                ):
                    dc = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                    )
                    if dc is None:
                        continue
                    hits.append(
                        ExposedAiWithSensitiveData(
                            service_id=svc.entity_id,
                            resource_id=access.dst_entity_id,
                            data_classification_id=dc.entity_id,
                            data_type=str(dc.properties.get("data_type", "")),
                        )
                    )
        return hits

    async def find_resource_based_data_exposure(self) -> list[ResourceBasedDataExposure]:
        """Find principals granted access by a resource's OWN policy to public sensitive data.

        Self-seeded: enumerates CLOUD_RESOURCE nodes carrying a ``policy_readers`` property
        (named principals granted S3 read by the bucket policy, written by data-security), and
        for each sensitive classification the bucket ``CONTAINS`` emits one hit per (principal,
        data classification). Uses ``CONTAINS`` (written for any sensitive bucket), not
        ``EXPOSES_DATA`` (public-only) — a resource-based grant exposes data to the named
        principal whether or not the bucket is internet-public (gap #7). Read-only."""
        hits: list[ResourceBasedDataExposure] = []
        resources = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        for resource in resources:
            readers = resource.properties.get("policy_readers") or []
            if not readers:
                continue
            for expose in await self._edges_from(resource.entity_id, (EdgeType.CONTAINS.value,)):
                dc = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                )
                if dc is None:
                    continue
                for principal_arn in readers:
                    hits.append(
                        ResourceBasedDataExposure(
                            principal_arn=str(principal_arn),
                            resource_id=resource.entity_id,
                            data_classification_id=dc.entity_id,
                            data_type=str(dc.properties.get("data_type", "")),
                        )
                    )
        return hits

    async def find_exposed_kms_key(self) -> list[ExposedKmsKey]:
        """Find KMS keys with an internet-open key policy (path #21). Self-seeded: a CLOUD_RESOURCE
        with ``kind=kms-key`` and ``is_public``. Read-only."""
        return [
            ExposedKmsKey(r.entity_id)
            for r in await self._semantic_store.list_entities_by_type(
                tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
            )
            if r.properties.get("kind") == "kms-key" and r.properties.get("is_public") is True
        ]

    async def find_exposed_kms_key_over_data(self) -> list[ExposedKmsKeyOverData]:
        """Find public KMS keys that ALSO protect classified data (path P4b).

        Intersection of two legs already written offline:
        - Leg A: CLOUD_RESOURCE{kind=kms-key, is_public=True}  (the exposure)
        - Leg B: kms-key --EXPOSES_DATA--> DATA_CLASSIFICATION  (the protected-data edge,
          written by cloud-posture ``record_kms_protected_data``, read by ``find_kms_key_access``)

        A key that matches BOTH legs is a higher-severity finding than a bare public key:
        the encryption boundary is internet-open AND it guards classified data. Read-only."""
        hits: list[ExposedKmsKeyOverData] = []
        for r in await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        ):
            if r.properties.get("kind") != "kms-key" or r.properties.get("is_public") is not True:
                continue
            for expose in await self._edges_from(r.entity_id, (EdgeType.EXPOSES_DATA.value,)):
                dc = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                )
                if dc is None:
                    continue
                hits.append(
                    ExposedKmsKeyOverData(
                        resource_id=r.entity_id,
                        data_classification_id=dc.entity_id,
                        data_type=str(dc.properties.get("data_type", "")),
                    )
                )
        return hits

    async def find_exposed_database(self) -> list[ExposedDatabase]:
        """Find publicly-accessible managed databases (path #19). Self-seeded: a CLOUD_RESOURCE with
        ``kind=rds-instance`` and ``is_public`` — an internet-facing data store. Read-only."""
        hits: list[ExposedDatabase] = []
        for r in await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        ):
            if r.properties.get("kind") == "rds-instance" and r.properties.get("is_public") is True:
                hits.append(ExposedDatabase(r.entity_id, str(r.properties.get("engine", ""))))
        return hits

    async def find_leaked_credential_to_data(self) -> list[LeakedCredentialToData]:
        """Find an IAM credential committed in source code that can reach sensitive data (#17).

        The cross-domain join (appsec + identity over the access-key-id key): enumerates IDENTITY
        principals, follows ``OWNS`` to a SECRET (access key) that is ``DEFINED_IN`` a repo — the
        leaked-in-code signal (appsec) — AND the principal's ``HAS_ACCESS_TO`` → resource →
        ``EXPOSES_DATA`` → data. A live credential, in code, that grants the data. Read-only."""
        hits: list[LeakedCredentialToData] = []
        principals = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.IDENTITY.value
        )
        for principal in principals:
            leaked: list[tuple[str, str]] = []  # (credential_id_node, repo_id_node)
            for owns in await self._edges_from(principal.entity_id, (EdgeType.OWNS.value,)):
                for defined in await self._edges_from(
                    owns.dst_entity_id, (EdgeType.DEFINED_IN.value,)
                ):
                    leaked.append((owns.dst_entity_id, defined.dst_entity_id))
            if not leaked:
                continue
            for access in await self._edges_from(
                principal.entity_id, (EdgeType.HAS_ACCESS_TO.value,)
            ):
                for expose in await self._edges_from(
                    access.dst_entity_id, (EdgeType.EXPOSES_DATA.value,)
                ):
                    dc = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                    )
                    if dc is None:
                        continue
                    for cred_id, repo_id in leaked:
                        hits.append(
                            LeakedCredentialToData(
                                principal_id=principal.entity_id,
                                credential_id=cred_id,
                                repo_id=repo_id,
                                resource_id=access.dst_entity_id,
                                data_classification_id=dc.entity_id,
                                data_type=str(dc.properties.get("data_type", "")),
                            )
                        )
        return hits

    async def find_stored_secret_to_data(self) -> list[StoredSecretToData]:
        """Find a workload with an embedded credential whose owner can reach sensitive data (W6).

        Cross-domain join (cloud-posture + identity): enumerates CLOUD_RESOURCE nodes, follows
        ``STORES_SECRET`` to a SECRET node (the embedded long-lived credential), then ``OWNED_BY``
        to the IDENTITY principal that owns it, then ``HAS_ACCESS_TO`` to a resource, then
        ``EXPOSES_DATA`` to a DATA_CLASSIFICATION. A running workload hard-codes a key whose owner
        can reach sensitive data — blast radius for the embedded credential. Read-only.

        **Scope note (intentionally broad):** this detector fires for ANY CLOUD_RESOURCE that stores
        a secret — public or private.  A non-public workload is a real threat: an attacker who gains
        access to the workload (via a vulnerability, supply-chain, or lateral movement) immediately
        inherits the embedded credential's blast radius.  The ``NAMED_SHAPES`` entry for this
        detector carries ``public_resource`` as its source marker only to suppress the generic-engine
        duplicate path — the generic walker starts from *graph sources* (nodes with no inbound edges
        within the tenant), and for the stored-secret shape, that starting node happens to be a public
        resource.  Do NOT narrow ``list_entities_by_type`` to ``is_public=True`` here."""
        hits: list[StoredSecretToData] = []
        workloads = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        for workload in workloads:
            for stores in await self._edges_from(
                workload.entity_id, (EdgeType.STORES_SECRET.value,)
            ):
                secret_id = stores.dst_entity_id
                for owned in await self._edges_from(secret_id, (EdgeType.OWNED_BY.value,)):
                    principal_id = owned.dst_entity_id
                    for access in await self._edges_from(
                        principal_id, (EdgeType.HAS_ACCESS_TO.value,)
                    ):
                        for expose in await self._edges_from(
                            access.dst_entity_id, (EdgeType.EXPOSES_DATA.value,)
                        ):
                            dc = await self._semantic_store.get_entity(
                                tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                            )
                            if dc is None:
                                continue
                            hits.append(
                                StoredSecretToData(
                                    workload_id=workload.entity_id,
                                    secret_id=secret_id,
                                    principal_id=principal_id,
                                    resource_id=access.dst_entity_id,
                                    data_classification_id=dc.entity_id,
                                    data_type=str(dc.properties.get("data_type", "")),
                                )
                            )
        return hits

    async def find_k8s_escape_to_cloud_data(self) -> list[K8sEscapeToCloudData]:
        """Find privileged K8s pods whose IRSA-mapped cloud IAM role can reach sensitive data (C-2).

        Cross-domain join (k8s-posture + identity): enumerates K8S_OBJECT pods where
        ``privileged=True``, follows ``USES_SERVICE_ACCOUNT`` to the SA node, then
        ``IRSA_MAPPING`` to the cloud IAM IDENTITY, then ``HAS_ACCESS_TO`` to a resource,
        then ``EXPOSES_DATA`` to a DATA_CLASSIFICATION. A privileged pod can escape to its
        node and exploit the SA's IRSA role to reach sensitive data. Read-only."""
        hits: list[K8sEscapeToCloudData] = []
        pods = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.K8S_OBJECT.value
        )
        for pod in pods:
            if pod.properties.get("privileged") is not True:
                continue
            for uses in await self._edges_from(
                pod.entity_id, (EdgeType.USES_SERVICE_ACCOUNT.value,)
            ):
                service_account_id = uses.dst_entity_id
                for irsa in await self._edges_from(
                    service_account_id, (EdgeType.IRSA_MAPPING.value,)
                ):
                    role_id = irsa.dst_entity_id
                    for access in await self._edges_from(role_id, (EdgeType.HAS_ACCESS_TO.value,)):
                        for expose in await self._edges_from(
                            access.dst_entity_id, (EdgeType.EXPOSES_DATA.value,)
                        ):
                            dc = await self._semantic_store.get_entity(
                                tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                            )
                            if dc is None:
                                continue
                            hits.append(
                                K8sEscapeToCloudData(
                                    pod_id=pod.entity_id,
                                    service_account_id=service_account_id,
                                    role_id=role_id,
                                    resource_id=access.dst_entity_id,
                                    data_classification_id=dc.entity_id,
                                    data_type=str(dc.properties.get("data_type", "")),
                                )
                            )
        return hits

    async def find_privilege_escalation_to_data(self) -> list[PrivilegeEscalationToData]:
        """Find a principal that reaches sensitive data by assuming another role (path #13).

        Self-seeded: enumerates IDENTITY nodes, follows ``ASSUMES`` to another IDENTITY (a role —
        the internal role-assumption edge identity writes from trust policies), then the assumed
        role's ``HAS_ACCESS_TO`` → resource → ``EXPOSES_DATA`` → data. The principal has no direct
        grant (else it is a fine-grained finding); it escalates via the role. Read-only."""
        hits: list[PrivilegeEscalationToData] = []
        principals = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.IDENTITY.value
        )
        for principal in principals:
            for assume in await self._edges_from(principal.entity_id, (EdgeType.ASSUMES.value,)):
                role_id = assume.dst_entity_id
                if role_id == principal.entity_id:
                    continue
                for access in await self._edges_from(role_id, (EdgeType.HAS_ACCESS_TO.value,)):
                    for expose in await self._edges_from(
                        access.dst_entity_id, (EdgeType.EXPOSES_DATA.value,)
                    ):
                        dc = await self._semantic_store.get_entity(
                            tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                        )
                        if dc is None:
                            continue
                        hits.append(
                            PrivilegeEscalationToData(
                                principal_id=principal.entity_id,
                                role_id=role_id,
                                resource_id=access.dst_entity_id,
                                data_classification_id=dc.entity_id,
                                data_type=str(dc.properties.get("data_type", "")),
                            )
                        )
        return hits

    async def find_escalation_method_to_data(self) -> list[EscalationMethodToData]:
        """Find a principal that uses a privesc METHOD to grant itself another identity's privileges
        and then reach sensitive data (path C-3).

        Self-seeded: enumerates IDENTITY nodes, follows ``CAN_ESCALATE_TO`` to a target IDENTITY
        (capturing the edge's ``method``/``via_action`` property — the privesc technique name),
        then the TARGET's ``HAS_ACCESS_TO`` → resource → ``EXPOSES_DATA`` → data. Distinct from
        :meth:`find_privilege_escalation_to_data` (which walks ``ASSUMES`` — allowed role
        assumption); this surfaces the ~20 AWS/cloud privesc methods (PassRole,
        CreatePolicyVersion, self_grant_admin, …) written as ``CAN_ESCALATE_TO`` edges by the
        identity agent. Read-only."""
        hits: list[EscalationMethodToData] = []
        principals = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.IDENTITY.value
        )
        for principal in principals:
            for escalate in await self._edges_from(
                principal.entity_id, (EdgeType.CAN_ESCALATE_TO.value,)
            ):
                target_id = escalate.dst_entity_id
                if target_id == principal.entity_id:
                    continue
                # Capture the privesc method from the edge properties. Identity writes both
                # ``method`` (the technique name) and ``via_action`` (the IAM action); prefer
                # ``method`` for the human-readable label, fall back to ``via_action``.
                method = str(
                    escalate.properties.get("method") or escalate.properties.get("via_action") or ""
                )
                for access in await self._edges_from(target_id, (EdgeType.HAS_ACCESS_TO.value,)):
                    for expose in await self._edges_from(
                        access.dst_entity_id, (EdgeType.EXPOSES_DATA.value,)
                    ):
                        dc = await self._semantic_store.get_entity(
                            tenant_id=self._customer_id, entity_id=expose.dst_entity_id
                        )
                        if dc is None:
                            continue
                        hits.append(
                            EscalationMethodToData(
                                principal_id=principal.entity_id,
                                target_id=target_id,
                                method=method,
                                resource_id=access.dst_entity_id,
                                data_classification_id=dc.entity_id,
                                data_type=str(dc.properties.get("data_type", "")),
                            )
                        )
        return hits

    async def find_resource_from_misconfigured_iac(self) -> list[IacMisconfigDeployed]:
        """Find a live cloud resource deployed from infrastructure-as-code with a misconfiguration.

        The mechanism-② cross-domain join (cloud + appsec / code-to-cloud): enumerates CLOUD_RESOURCE
        nodes, follows ``DEPLOYED_VIA`` (the resolver-written provenance bridge) to an IAC_ARTIFACT
        node (appsec writes one only for a misconfigured IaC file), then ``DEFINED_IN`` to the repo.
        The live resource's misconfiguration is traceable to the exact repo + file. Read-only."""
        hits: list[IacMisconfigDeployed] = []
        resources = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        for resource in resources:
            for dep in await self._edges_from(resource.entity_id, (EdgeType.DEPLOYED_VIA.value,)):
                artifact = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=dep.dst_entity_id
                )
                if artifact is None:
                    continue
                repos = await self._edges_from(dep.dst_entity_id, (EdgeType.DEFINED_IN.value,))
                hits.append(
                    IacMisconfigDeployed(
                        resource_id=resource.entity_id,
                        artifact_id=dep.dst_entity_id,
                        artifact_ref=artifact.external_id,
                        repo_id=repos[0].dst_entity_id if repos else "",
                    )
                )
        return hits

    async def find_cicd_compromise(self) -> list[CicdCompromise]:
        """Find a live resource deployed from a repo that holds a LEAKED credential (NEX-304).

        Reuses the code-to-cloud chain in its natural direction (no reverse edge — the NEX-203 insight):
        resource --DEPLOYED_VIA--> IAC_ARTIFACT --DEFINED_IN--> repo, where the repo also has a leaked
        SECRET (``SECRET{leaked} --DEFINED_IN--> repo``). An attacker with that leaked pipeline
        credential can poison the deploy, so the production resource's supply chain is compromised.
        Read-only."""
        compromised_repos: set[str] = set()
        for secret in await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.SECRET.value
        ):
            if secret.properties.get("leaked") is True:
                for d in await self._edges_from(secret.entity_id, (EdgeType.DEFINED_IN.value,)):
                    compromised_repos.add(d.dst_entity_id)
        if not compromised_repos:
            return []
        hits: list[CicdCompromise] = []
        for resource in await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        ):
            for dep in await self._edges_from(resource.entity_id, (EdgeType.DEPLOYED_VIA.value,)):
                for repo_edge in await self._edges_from(
                    dep.dst_entity_id, (EdgeType.DEFINED_IN.value,)
                ):
                    if repo_edge.dst_entity_id in compromised_repos:
                        hits.append(
                            CicdCompromise(
                                resource_id=resource.entity_id, repo_id=repo_edge.dst_entity_id
                            )
                        )
        return hits

    async def find_runtime_exploit_on_vulnerable_workload(
        self,
    ) -> list[RuntimeExploitVulnerableWorkload]:
        """Find an active runtime detection on a workload running a vulnerable image (cross-domain).

        The mechanism-② cross-domain join (runtime + vulnerability over the image-ref bridge):
        enumerates runtime L6 event nodes (PROCESS_EVENT / FILE_INTEGRITY_EVENT), follows
        ``EXECUTED_ON`` to the host, ``RUNS_IMAGE`` (the resolver-written bridge) to the image, then
        ``VULNERABLE_TO`` to each CVE. One hit per (event, CVE) — suspicious behaviour on a
        known-vulnerable workload, i.e. likely active exploitation. Read-only; self-seeded."""
        hits: list[RuntimeExploitVulnerableWorkload] = []
        for category in (NodeCategory.PROCESS_EVENT, NodeCategory.FILE_INTEGRITY_EVENT):
            events = await self._semantic_store.list_entities_by_type(
                tenant_id=self._customer_id, entity_type=category.value
            )
            for event in events:
                for ex in await self._edges_from(event.entity_id, (EdgeType.EXECUTED_ON.value,)):
                    for runs in await self._edges_from(
                        ex.dst_entity_id, (EdgeType.RUNS_IMAGE.value,)
                    ):
                        for vuln in await self._edges_from(
                            runs.dst_entity_id, (EdgeType.VULNERABLE_TO.value,)
                        ):
                            cve = await self._semantic_store.get_entity(
                                tenant_id=self._customer_id, entity_id=vuln.dst_entity_id
                            )
                            if cve is None:
                                continue
                            hits.append(
                                RuntimeExploitVulnerableWorkload(
                                    host_id=ex.dst_entity_id,
                                    event_id=event.entity_id,
                                    image_id=runs.dst_entity_id,
                                    cve_id=cve.external_id,
                                    severity=str(cve.properties.get("severity", "")),
                                    kev_listed=bool(cve.properties.get("kev", False)),
                                    epss_score=_float_or_none(cve.properties.get("epss_score")),
                                )
                            )
        return hits

    async def find_resource_contacting_malicious_ip(
        self,
    ) -> list[MaliciousDestinationExposure]:
        """Find an owned cloud resource communicating with a known-malicious IP (cross-domain).

        The mechanism-② cross-domain join (network + threat-intel): enumerates network-endpoint
        nodes that are ``OWNED_BY`` a cloud resource (the IP→instance bridge), follows
        ``COMMUNICATES_WITH`` to a destination endpoint, then ``MATCHES_INDICATOR`` (the IP→IOC
        bridge) to a threat-intel IOC. One hit per (owning resource, malicious destination). An
        active C2/exfil signal on the account's own resource. Read-only; self-seeded."""
        hits: list[MaliciousDestinationExposure] = []
        resources = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        for endpoint in resources:
            if endpoint.properties.get("kind") != "network-endpoint":
                continue
            owners = await self._edges_from(endpoint.entity_id, (EdgeType.OWNED_BY.value,))
            if not owners:
                continue
            for comm in await self._edges_from(
                endpoint.entity_id, (EdgeType.COMMUNICATES_WITH.value,)
            ):
                for match in await self._edges_from(
                    comm.dst_entity_id, (EdgeType.MATCHES_INDICATOR.value,)
                ):
                    ioc = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=match.dst_entity_id
                    )
                    if ioc is None:
                        continue
                    actor_id = str(ioc.properties.get("actor_id", ""))
                    actor_name = str(ioc.properties.get("actor_name", ""))
                    for owner in owners:
                        hits.append(
                            MaliciousDestinationExposure(
                                resource_id=owner.dst_entity_id,
                                destination_id=comm.dst_entity_id,
                                indicator_id=ioc.entity_id,
                                indicator_value=str(ioc.properties.get("value", "")),
                                actor_id=actor_id,
                                actor_name=actor_name,
                            )
                        )
        return hits

    async def find_lateral_movement_via_reachability(self) -> list[LateralReachable]:
        """Derived (config-based) lateral movement: a public foothold that CAN_REACH / PEERED_WITH a
        target which is either a vulnerable host or a managed datastore.

        Distinct from :meth:`find_lateral_movement_to_vulnerable_host` (which uses observed
        ``COMMUNICATES_WITH`` edges from flow logs); this fires from security-group / VPC-peering
        config alone — before any traffic is seen — and covers both vulnerable-host and
        sensitive-datastore pivot targets.  ``impact="sensitive_resource"`` when the target is
        a managed datastore (``kind`` in ``{"rds-instance", "kms-key"}``);
        ``impact="vulnerable_host"`` when the target carries a ``VULNERABLE_TO`` CVE.  A target
        that matches BOTH emits two hits (one per threat model). Read-only; self-seeded.
        """
        hits: list[LateralReachable] = []
        for foothold in await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        ):
            if foothold.properties.get("is_public") is not True:
                continue
            for reach in await self._edges_from(
                foothold.entity_id, (EdgeType.CAN_REACH.value, EdgeType.PEERED_WITH.value)
            ):
                if reach.dst_entity_id == foothold.entity_id:
                    continue
                target = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=reach.dst_entity_id
                )
                if target is None:
                    continue
                reach_kind = str(reach.properties.get("method", ""))
                if target.properties.get("kind") in {"rds-instance", "kms-key"}:
                    hits.append(
                        LateralReachable(
                            foothold.entity_id,
                            target.entity_id,
                            reach_kind,
                            "sensitive_resource",
                        )
                    )
                for vuln in await self._edges_from(
                    target.entity_id, (EdgeType.VULNERABLE_TO.value,)
                ):
                    cve = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=vuln.dst_entity_id
                    )
                    if cve is None:
                        continue
                    hits.append(
                        LateralReachable(
                            foothold.entity_id,
                            target.entity_id,
                            reach_kind,
                            "vulnerable_host",
                            cve.external_id,
                            str(cve.properties.get("severity", "")),
                        )
                    )
        return hits

    async def find_lateral_movement_to_vulnerable_host(self) -> list[LateralMovement]:
        """Find a public foothold with an observed flow to an internal vulnerable host (path #14).

        Self-seeded over observed network topology + the IP-ownership bridge: a network-endpoint
        ``OWNED_BY`` a public resource (the perimeter foothold) ``COMMUNICATES_WITH`` a dst endpoint
        ``OWNED_BY`` a target resource that is directly ``VULNERABLE_TO`` a CVE. The attacker
        breaches the internet-facing foothold, then pivots laterally over the observed flow to a
        soft internal target. Observed flows only — derived reachability (CAN_REACH) is Stage 3.
        Read-only."""
        hits: list[LateralMovement] = []
        resources = await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        for endpoint in resources:
            if endpoint.properties.get("kind") != "network-endpoint":
                continue
            footholds: list[str] = []
            for owner in await self._edges_from(endpoint.entity_id, (EdgeType.OWNED_BY.value,)):
                fr = await self._semantic_store.get_entity(
                    tenant_id=self._customer_id, entity_id=owner.dst_entity_id
                )
                if fr is not None and fr.properties.get("is_public") is True:
                    footholds.append(fr.entity_id)
            if not footholds:
                continue
            for comm in await self._edges_from(
                endpoint.entity_id, (EdgeType.COMMUNICATES_WITH.value,)
            ):
                for towner in await self._edges_from(
                    comm.dst_entity_id, (EdgeType.OWNED_BY.value,)
                ):
                    for vuln in await self._edges_from(
                        towner.dst_entity_id, (EdgeType.VULNERABLE_TO.value,)
                    ):
                        cve = await self._semantic_store.get_entity(
                            tenant_id=self._customer_id, entity_id=vuln.dst_entity_id
                        )
                        if cve is None:
                            continue
                        for foothold_id in footholds:
                            hits.append(
                                LateralMovement(
                                    foothold_id=foothold_id,
                                    target_id=towner.dst_entity_id,
                                    cve_id=cve.external_id,
                                    severity=str(cve.properties.get("severity", "")),
                                    kev_listed=bool(cve.properties.get("kev", False)),
                                    epss_score=_float_or_none(cve.properties.get("epss_score")),
                                )
                            )
        return hits

    async def find_supply_chain_sbom(self) -> list[SupplyChainSbom]:
        """Public workload runs an image whose SBOM package has a CVE (dependency-level supply chain).

        Package granularity over :meth:`find_internet_exposed_vulnerable_workload` (which stops at
        image→CVE): the full chain is ``public workload --RUNS_IMAGE--> image
        --CONTAINS_PACKAGE--> SBOM_PACKAGE --VULNERABLE_TO--> CVE``.
        ``package_name`` names the specific dependency to bump (Log4Shell shape).
        One hit per (public workload, package, CVE). Read-only; self-seeded (NEX-305)."""
        hits: list[SupplyChainSbom] = []
        for workload in await self._semantic_store.list_entities_by_type(
            tenant_id=self._customer_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
        ):
            if workload.properties.get("is_public") is not True:
                continue
            for runs in await self._edges_from(workload.entity_id, (EdgeType.RUNS_IMAGE.value,)):
                for contains in await self._edges_from(
                    runs.dst_entity_id, (EdgeType.CONTAINS_PACKAGE.value,)
                ):
                    pkg = await self._semantic_store.get_entity(
                        tenant_id=self._customer_id, entity_id=contains.dst_entity_id
                    )
                    if pkg is None:
                        continue
                    for vuln in await self._edges_from(
                        pkg.entity_id, (EdgeType.VULNERABLE_TO.value,)
                    ):
                        cve = await self._semantic_store.get_entity(
                            tenant_id=self._customer_id, entity_id=vuln.dst_entity_id
                        )
                        if cve is None:
                            continue
                        hits.append(
                            SupplyChainSbom(
                                workload_id=workload.entity_id,
                                image_id=runs.dst_entity_id,
                                package_name=str(pkg.properties.get("name", "")),
                                cve_id=cve.external_id,
                                severity=str(cve.properties.get("severity", "")),
                                kev_listed=bool(cve.properties.get("kev", False)),
                                epss_score=_float_or_none(cve.properties.get("epss_score")),
                            )
                        )
        return hits

    async def _edges_from(
        self, entity_id: str, edge_types: tuple[str, ...] | None
    ) -> list[RelationshipRow]:
        return await self._semantic_store.get_relationships_from(
            tenant_id=self._customer_id,
            src_entity_id=entity_id,
            edge_types=edge_types,
        )


__all__ = [
    "AttackPathResult",
    "BlastRadiusResult",
    "CrownJewelExposure",
    "EscalationMethodToData",
    "ExposedAiWithSensitiveData",
    "ExposedKmsKeyOverData",
    "ExternalTrustExposure",
    "FineGrainedDataExposure",
    "InternetExposedVulnerableWorkload",
    "K8sEscapeToCloudData",
    "KgQuery",
    "LateralReachable",
    "PathEdge",
    "PrivilegedVulnerableWorkload",
    "PublicSecretExposure",
    "PublicUnencryptedExposure",
    "RbacEscalationToCloudData",
    "RbacPrivilegeEscalation",
    "ResourceBasedDataExposure",
    "StoredSecretToData",
    "SupplyChainSbom",
    "ToxicCombination",
]
