"""Source-agent registry for coverage-gap reasoning (curiosity v0.2 Task 5, Q2/WI-X1).

D.12 v0.1 recognised finding-aggregates from ~4 origin agents (F.3/D.5/D.6/D.8). Q2 expands the
recognised set to all **14 closed-cycle v0.2 agents**. Per WI-X1 per-source coverage is tracked
**separately** (never a fleet total). Tenant-scoping is enforced by the reader, not here — this
module is the pure registry + a per-source bucketing helper.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

#: The 14 closed-cycle v0.2 source agents whose finding-aggregates D.12 reasons over (Q2).
SOURCE_AGENTS: tuple[str, ...] = (
    "cloud_posture",  # F.3
    "multi_cloud_posture",  # D.5
    "vulnerability",  # D.1
    "identity",  # D.2
    "threat_intel",  # D.8
    "runtime_threat",  # D.3
    "network_threat",  # D.4
    "k8s_posture",
    "compliance",
    "data_security",
    "audit",  # F.6
    "supervisor",
    "synthesis",  # D.13
    "investigation",  # D.7
)

_KNOWN: frozenset[str] = frozenset(SOURCE_AGENTS)


def is_known_source(agent_id: str) -> bool:
    """True iff ``agent_id`` is one of the 14 recognised source agents."""
    return agent_id in _KNOWN


def per_source_finding_counts(
    finding_aggregates: Iterable[Mapping[str, Any]],
) -> dict[str, int]:
    """Bucket finding-aggregate property maps by ``source_agent`` (known sources only).

    Per WI-X1 the result is a per-source breakdown, NOT a fleet total. Unknown / missing
    source_agent rows are ignored (forgiving, like the rest of the reader).
    """
    counts: dict[str, int] = {}
    for props in finding_aggregates:
        source = props.get("source_agent")
        if isinstance(source, str) and source in _KNOWN:
            counts[source] = counts.get(source, 0) + 1
    return counts
