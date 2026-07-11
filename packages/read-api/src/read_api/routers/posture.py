"""Posture router — serves the posture rollup (Endpoint 4).

Computes the ``PostureRollup`` on-demand from the current tenant graph and
returns the board data (coverage, severity distribution, per-domain scorecards,
exposure funnel, inventory counts, top paths). ``?domain=`` filters the
per-domain rows for a persona lens.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from charter.memory.semantic import SemanticStore
from fastapi import APIRouter, Depends, Query
from meta_harness.posture import PostureRollup, summary_to_dict

from read_api.deps import (
    Envelope,
    get_store,
    make_envelope,
    require_entitlement,
    require_tenant,
)

router = APIRouter(
    prefix="/posture",
    tags=["posture"],
    dependencies=[Depends(require_entitlement("posture", "read"))],
)


@router.get("", response_model=Envelope)
async def get_posture(
    domain: str | None = Query(default=None),
    tenant: str = Depends(require_tenant),
    store: SemanticStore = Depends(get_store),  # noqa: B008
) -> Envelope:
    """Current posture rollup for the tenant; ``?domain=`` filters the per-domain rows."""
    # ponytail: recomputes the full AttackPathRanker on every request, and this is
    # the default landing page — fine at dev graph sizes, a footgun at scale. Upgrade
    # path when it bites: serve the posture snapshot persisted at scan time (episodic
    # memory) instead of recomputing, or add a short per-tenant TTL cache here.
    summary = await PostureRollup(store, tenant).compute(now=datetime.now(tz=UTC))
    data: dict[str, Any] = summary_to_dict(summary)
    if domain is not None:
        rows = data.get("by_domain", [])
        data["by_domain"] = [row for row in rows if row.get("domain") == domain]
    return make_envelope(data=data, offset=None, total=None, tenant=tenant)
