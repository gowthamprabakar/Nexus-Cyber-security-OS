"""Attack-path coverage harness (NEX-003) — measure produced-vs-catalog, no more estimates.

Given a populated tenant graph, count which :data:`coverage_catalog.CATALOG` families the engine
actually produces, and compute ``coverage = produced / len(catalog)``. Detection signal per family is
either a **key edge** (the moat families are distinguished by their edge, e.g. ``CAN_ESCALATE_TO``) or a
named **path_type** (the pre-existing archetypes). This is deliberately measured on the raw engine
(``find_candidate_paths`` edge-signatures + ``AttackPathRanker.find_all`` path_types), NOT on the report
card — the card conflates some families into one ``path_type``, which would silently undercount.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from meta_harness.attack_paths import AttackPathRanker
from meta_harness.coverage_catalog import CATALOG, Status
from meta_harness.kg_query import KgQuery
from meta_harness.path_engine import find_candidate_paths

if TYPE_CHECKING:
    from charter.memory import SemanticStore

#: family id → the KEY EDGE that distinguishes it in a generic path's edge-signature. Families not
#: here are detected by their named ``path_type`` instead (see the catalog).
_FAMILY_KEY_EDGE: dict[str, str] = {
    "leaked_credential": "OWNED_BY",
    # stored_secret is now a NAMED detector (stored_secret_to_data) — detected by path_type,
    # not an edge signature (its shape is in NAMED_SHAPES and is filtered from generic paths).
    "privilege_escalation": "CAN_ESCALATE_TO",
    "cross_account_trust": "ASSUMES",
    "network_lateral": "CAN_REACH",
    "pod_lateral": "POD_CAN_REACH",
    "container_escape_cloud": "USES_SERVICE_ACCOUNT",
    # rbac_privilege_escalation is a NAMED detector (SA→BINDS→admin), NOT a generic-walker family —
    # BINDS is non-traversable, so it's detected by its path_type, not an edge (NEX-301 fix).
    "network_topology_lateral": "PEERED_WITH",
    "supply_chain_sbom": "CONTAINS_PACKAGE",
    # kms_key_access + exposed_database are NAMED detectors → detected by path_type, not an edge.
}


@dataclass(frozen=True, slots=True)
class CoverageReport:
    produced: frozenset[str]  # family ids actually produced by the fixture graph
    catalog_total: int
    built_total: int

    @property
    def coverage_pct(self) -> float:
        """Produced families as a % of the FULL catalog (the honest denominator)."""
        return 100.0 * len(self.produced) / self.catalog_total if self.catalog_total else 0.0

    @property
    def built_coverage_pct(self) -> float:
        """Produced as a % of families we claim are BUILT (should be ~100% on a full fixture)."""
        return 100.0 * len(self.produced) / self.built_total if self.built_total else 0.0


async def measure_coverage(store: SemanticStore, tenant: str) -> CoverageReport:
    """Measure which catalog families the graph produces (raw engine, not the report card)."""
    cands = await find_candidate_paths(store, tenant)
    edges_seen = {e for c in cands for e in c.path.edge_signature}
    path_types_seen = {
        ap.path_type for ap in await AttackPathRanker(KgQuery(store, tenant)).find_all()
    }

    produced: set[str] = set()
    for fam in CATALOG:
        key_edge = _FAMILY_KEY_EDGE.get(fam.id)
        if key_edge is not None:
            if key_edge in edges_seen:
                produced.add(fam.id)
        elif fam.path_type in path_types_seen:
            produced.add(fam.id)

    return CoverageReport(
        produced=frozenset(produced),
        catalog_total=len(CATALOG),
        built_total=sum(1 for f in CATALOG if f.status is Status.BUILT),
    )


__all__ = ["CoverageReport", "measure_coverage"]
