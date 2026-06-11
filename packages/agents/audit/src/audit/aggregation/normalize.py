"""Aggregation result normalization (audit v0.2 Task 4, Q1/WI-F5).

Renders a cross-agent `AggregationResult` into a unified, time-ordered set of OCSF v1.3 API
Activity (class_uid 6003) records. Each record is produced by the unchanged
``AuditEvent.to_ocsf`` (so the 6003 wire shape — including the chain hashes in the unmapped
slot — is byte-identical, WI-F5), preserving **chain provenance** (agent id, source, entry
hash) per entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from audit.aggregation.multi_chain_query import AggregationResult


@dataclass(frozen=True, slots=True)
class AggregationReport:
    total: int
    chains_verified: int
    broken_chains: tuple[str, ...]
    records: tuple[dict[str, Any], ...]  # OCSF 6003, time-ordered, provenance-preserving

    def agents_covered(self) -> tuple[str, ...]:
        """The distinct agent ids represented in the aggregated records."""
        return tuple(sorted({r["actor"]["user"]["name"] for r in self.records}))


def normalize_aggregation(result: AggregationResult) -> AggregationReport:
    """Render an aggregation result to a unified OCSF 6003 report (provenance preserved)."""
    records = tuple(event.to_ocsf() for event in result.events)
    return AggregationReport(
        total=len(records),
        chains_verified=result.chains_verified,
        broken_chains=result.broken_chains,
        records=records,
    )
