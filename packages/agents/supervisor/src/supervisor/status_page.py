"""Continuous-mode status-page stub (Track D D-2).

The final D-2 activation prerequisite (audit §11): a **read-only aggregator**
for a future v0.4 dashboard. It composes the three inert D-2 surfaces — resolved
per-tenant cadence, freshness (last-refreshed per agent), and the in-process
metrics snapshot — into one JSON-serializable dict. No HTTP server, no loop, no
writes (pause trigger #25 stays clear; it only reads).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from supervisor.cadence import resolve_cadence
from supervisor.continuous_metrics import ContinuousMetrics
from supervisor.freshness import all_freshness


def build_continuous_status(
    workspace_root: Path,
    *,
    customer_id: str,
    metrics: ContinuousMetrics | None = None,
) -> dict[str, Any]:
    """Aggregate the per-tenant continuous-mode status into a JSON-ready dict.

    Pure read: resolved cadence config + freshness file + the metrics snapshot
    (a fresh all-zero counter when none is supplied — the v0.3 inert state).
    Returns the shape a v0.4 status page / dashboard will render.
    """
    snapshot = (metrics or ContinuousMetrics()).snapshot()
    cadence = resolve_cadence(workspace_root=workspace_root, customer_id=customer_id)
    freshness = {
        agent_id: ts.isoformat()
        for agent_id, ts in all_freshness(workspace_root, customer_id=customer_id).items()
    }
    return {
        "customer_id": customer_id,
        "cadence": cadence.cadence if cadence else None,
        "freshness": freshness,
        "metrics": snapshot,
    }
