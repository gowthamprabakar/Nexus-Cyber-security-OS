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
# resource exposing one of these is a publicly-readable credential — path 3 (ADR-023).
_SECRET_DATA_TYPES = frozenset({"aws_access_key", "jwt", "generic_api_token"})


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


@dataclass(frozen=True, slots=True)
class PrivilegedVulnerableWorkload:
    """A privileged K8s pod running an image with a known CVE (path 6). The pod
    --RUNS_IMAGE--> image --VULNERABLE_TO--> CVE chain: exploit the CVE for RCE in the
    container, then escape to the node via the privileged container. `severity` is the CVE's."""

    workload_id: str
    image_id: str
    cve_id: str
    severity: str


def _validate_depth(depth: int) -> int:
    if depth < 1 or depth > MAX_TRAVERSAL_DEPTH:
        raise ValueError(f"depth must be in [1, {MAX_TRAVERSAL_DEPTH}], got {depth}")
    return depth


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
    "ExternalTrustExposure",
    "FineGrainedDataExposure",
    "InternetExposedVulnerableWorkload",
    "KgQuery",
    "PathEdge",
    "PrivilegedVulnerableWorkload",
    "PublicSecretExposure",
    "PublicUnencryptedExposure",
    "ToxicCombination",
]
