"""Cross-agent chain query aggregator (audit v0.2 Task 3, Q1/Q6).

Runs a unified query across several agents' audit chains: each chain is **verified before
aggregation** (Q1), only events for the requested tenant are included (Q6 tenant isolation —
defense-in-depth with F.5 RLS), and the merged result is time-ordered. Per **WI-F2** a chain
that fails integrity is **flagged + excluded**, never repaired. Read-only.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from audit.chain import verify_audit_chain
from audit.schemas import AuditEvent


@dataclass(frozen=True, slots=True)
class AggregationResult:
    events: tuple[AuditEvent, ...]  # tenant-filtered, time-ordered
    chains_verified: int
    broken_chains: tuple[str, ...]  # agent ids whose chain failed integrity (excluded)


def aggregate_chains(
    chains: Mapping[str, Sequence[AuditEvent]],
    *,
    tenant_id: str,
    verify: bool = True,
) -> AggregationResult:
    """Merge events across ``chains`` (``agent_id -> events``) for one ``tenant_id``. With
    ``verify`` (default), each chain is integrity-checked first; a broken chain is flagged in
    ``broken_chains`` and excluded (WI-F2 — never repaired)."""
    merged: list[AuditEvent] = []
    broken: list[str] = []
    verified = 0
    for agent_id, events in sorted(chains.items()):
        if verify:
            verified += 1
            if not verify_audit_chain(events, sequential=True).valid:
                broken.append(agent_id)
                continue
        merged.extend(e for e in events if e.tenant_id == tenant_id)
    merged.sort(key=lambda e: (e.emitted_at, e.correlation_id))
    return AggregationResult(
        events=tuple(merged), chains_verified=verified, broken_chains=tuple(broken)
    )
