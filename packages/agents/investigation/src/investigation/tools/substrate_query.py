"""Live F.5 + F.6 substrate query integration (investigation v0.2 Task 4, WI-I16/H5).

Formalizes the substrate-query discipline the worker tools share: every F.5 memory walk + F.6
audit query is **tenant-scoped** (``assert_tenant_scoped``, WI-I16/H6) and the memory-walk depth
is capped at the H5 bound (``MAX_MEMORY_WALK_DEPTH = 3``). Also defines the **evidence-ref
namespace** — ``audit_event:`` (F.6), ``finding:`` (sibling findings), ``entity:`` (F.5) — that
the evidence-chain guard (Task 18) resolves hypotheses against. Pure + deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass

from investigation.tools.fleet_evidence_reader import TenantScopeError

#: H5: the F.5 semantic-graph walk is capped at depth 3.
MAX_MEMORY_WALK_DEPTH = 3


@dataclass(frozen=True, slots=True)
class SubstrateQuery:
    tenant_id: str
    walk_depth: int


def assert_tenant_scoped(tenant_id: str) -> None:
    """Hard guard — every substrate query must carry a tenant id (WI-I16/H6)."""
    if not tenant_id:
        raise TenantScopeError("substrate query requires a non-empty tenant_id (H6/WI-I16)")


def clamp_walk_depth(requested_depth: int) -> int:
    """Cap the memory-walk depth at the H5 bound (over-cap is clamped, not an error)."""
    return min(max(requested_depth, 0), MAX_MEMORY_WALK_DEPTH)


def build_substrate_query(
    *, tenant_id: str, requested_depth: int = MAX_MEMORY_WALK_DEPTH
) -> SubstrateQuery:
    """Build a tenant-scoped, depth-capped substrate query."""
    assert_tenant_scoped(tenant_id)
    return SubstrateQuery(tenant_id=tenant_id, walk_depth=clamp_walk_depth(requested_depth))


def audit_evidence_id(correlation_id: str) -> str:
    """An F.6 audit-event evidence ref."""
    return f"audit_event:{correlation_id}"


def finding_evidence_id(finding_uid: str) -> str:
    """A sibling-finding evidence ref."""
    return f"finding:{finding_uid}"


def entity_evidence_id(entity_id: str) -> str:
    """An F.5 entity evidence ref."""
    return f"entity:{entity_id}"
