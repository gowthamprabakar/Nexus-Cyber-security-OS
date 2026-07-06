"""The analysis step of the scan loop: populated graph -> ranked answer.

Every caller was inlining ``correlate_all`` + the ranker + the candidate engine (and the CLI was
skipping ``correlate_all`` entirely, so cross-domain paths never fired). This is the one reusable
tail: given a graph the feeders have populated, run the bridge resolvers, then produce both tiers —
confirmed (named) attack paths and candidate (generic) paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from meta_harness.attack_path_writer import AttackPathWriter
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.candidate_history import (
    CandidateDelta,
    CandidateSnapshot,
    diff_candidates,
    snapshot_candidates,
)
from meta_harness.correlation import correlate_all
from meta_harness.kg_query import KgQuery
from meta_harness.ocsf_attack_path import build_incident_finding
from meta_harness.path_engine import find_candidate_paths
from meta_harness.report_card import rank_by_expected_loss

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore

    from meta_harness.attack_paths import AttackPath
    from meta_harness.path_engine import CandidatePath


@dataclass(frozen=True, slots=True)
class ScanResult:
    """A tenant's attack-path answer: confirmed (named) + candidate (generic) tiers."""

    confirmed: list[AttackPath]
    candidates: list[CandidatePath]
    ocsf_findings: list[dict[str, Any]] = field(default_factory=list)


async def analyze(
    store: SemanticStore,
    tenant_id: str,
    *,
    suppressed: frozenset[tuple[str, str, tuple[str, ...]]] = frozenset(),
    persist: bool = False,
    now: datetime | None = None,
    logging_disabled: bool = False,
) -> ScanResult:
    """Run the bridge resolvers, then rank the confirmed + candidate attack paths. Read-only-ish:
    the only writes are the idempotent cross-agent bridge edges (``correlate_all``).

    ``suppressed`` (BP4) is the set of candidate shapes an analyst dismissed — pass
    ``FeedbackLog.suppressed_signatures()`` here so dismissed noise stops resurfacing.

    ``persist`` (default ``False``) — when ``True``, persists each ranked ``AttackPath`` as a
    durable ``ATTACK_PATH`` graph node and collects OCSF 2005 Incident Findings.  The default is
    ``False`` so every existing caller and test is byte-unaffected.

    ``now`` — caller-supplied timestamp for ``first_seen`` / ``last_seen`` / OCSF time fields.
    Defaults to ``datetime.now(UTC)`` when ``persist=True`` and the caller omits it.  Ignored
    when ``persist=False``.

    ``logging_disabled`` (default False) — passed through to ``rank_by_expected_loss`` to apply
    the defense-evasion lift when the account's audit logging is off."""
    await correlate_all(store, tenant_id)
    confirmed = await AttackPathRanker(KgQuery(store, tenant_id)).find_all()
    ranked = await rank_by_expected_loss(
        confirmed, store, tenant_id, logging_disabled=logging_disabled
    )

    ocsf_findings: list[dict[str, Any]] = []
    if persist:
        stamp = now or datetime.now(UTC)
        await AttackPathWriter(store, tenant_id).persist(ranked, now=stamp)
        ocsf_findings = [
            build_incident_finding(p, el, blast, tenant_id=tenant_id, now=stamp)
            for p, el, blast in ranked
        ]

    confirmed = [t[0] for t in ranked]
    candidates = await find_candidate_paths(store, tenant_id, suppressed=suppressed)
    return ScanResult(confirmed=confirmed, candidates=candidates, ocsf_findings=ocsf_findings)


async def analyze_with_history(
    store: SemanticStore,
    tenant_id: str,
    *,
    previous: CandidateSnapshot,
    suppressed: frozenset[tuple[str, str, tuple[str, ...]]] = frozenset(),
) -> tuple[ScanResult, CandidateSnapshot, CandidateDelta]:
    """One continuous-scan step (BP7): analyze, snapshot the candidate tier, diff vs the last run.

    Returns the scan result, the new snapshot (persist it for next time), and the delta (a path that
    just APPEARED is the alert). ``previous`` is the prior run's snapshot (``CandidateSnapshot({})``
    on first run)."""
    result = await analyze(store, tenant_id, suppressed=suppressed)
    snapshot = snapshot_candidates(result.candidates)
    return result, snapshot, diff_candidates(previous, snapshot)


__all__ = ["ScanResult", "analyze", "analyze_with_history"]
