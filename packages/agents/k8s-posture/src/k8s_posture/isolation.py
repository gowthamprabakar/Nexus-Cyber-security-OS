"""Per-cluster scan-context isolation (D.6 v0.2 Task 14).

Per **Q3 / WI-K8** a scan targets **exactly one cluster** and must never leak context
across clusters. This is the cycle's **code-level safety invariant** (mirrors D.4's
`assert_block_authorized`): `assert_single_cluster_context` rejects a scan spanning >1
cluster, and `ClusterScanSession` binds a scan to one cluster and rejects any resource /
finding that belongs to a different one. Backstops pause-trigger #12 (cross-cluster leak).
"""

from __future__ import annotations

from collections.abc import Iterable


class CrossClusterContextError(RuntimeError):
    """A scan touched more than one cluster (Q3 single-cluster invariant violated)."""


def assert_single_cluster_context(cluster_ids: Iterable[str]) -> str:
    """Assert the given cluster ids resolve to **exactly one** non-empty cluster, and
    return it. Raises on zero clusters, an empty id, or >1 distinct cluster (WI-K8)."""
    ids = list(cluster_ids)
    if not ids:
        raise CrossClusterContextError("scan has no cluster context")
    if any(not c for c in ids):
        raise CrossClusterContextError("scan has an empty cluster id")
    distinct = set(ids)
    if len(distinct) != 1:
        raise CrossClusterContextError(
            f"scan spans {len(distinct)} clusters {sorted(distinct)} — single-cluster only (Q3/WI-K8)"
        )
    return distinct.pop()


class ClusterScanSession:
    """Binds a scan to one cluster; every resource added must belong to it (WI-K8)."""

    __slots__ = ("_cluster_id",)

    def __init__(self, cluster_id: str) -> None:
        if not cluster_id:
            raise CrossClusterContextError("cluster_id must be non-empty")
        self._cluster_id = cluster_id

    @property
    def cluster_id(self) -> str:
        return self._cluster_id

    def assert_belongs(self, resource_cluster_id: str) -> None:
        """Raise if a resource/finding from another cluster enters this scan (WI-K8)."""
        if resource_cluster_id != self._cluster_id:
            raise CrossClusterContextError(
                f"resource from cluster {resource_cluster_id!r} in a scan bound to "
                f"{self._cluster_id!r} — cross-cluster context leak forbidden (Q3/WI-K8)"
            )
