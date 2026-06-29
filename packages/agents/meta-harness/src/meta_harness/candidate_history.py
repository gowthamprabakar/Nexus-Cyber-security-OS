"""BP7 — candidate history: snapshot the candidate tier per scan, diff across runs.

Continuous operation wants more than "here are today's candidates" — it wants "a new attack path
APPEARED since the last scan" (alert) and "one we saw before is GONE" (resolved). This snapshots the
candidate list by a stable cross-run key and diffs two snapshots.

The key is the shape + the node LABELS (external_ids — ARNs/URIs, stable across runs), NOT the ULID
entity_ids (regenerated per insert). So the same real path keeps the same key across scans even if
the graph was rebuilt. Snapshots serialize (``to_dict`` / ``from_dict``) for persistence between runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from meta_harness.attack_path_report import candidate_story

if TYPE_CHECKING:
    from collections.abc import Sequence

    from meta_harness.path_engine import CandidatePath


def candidate_key(candidate: CandidatePath) -> str:
    """A stable cross-run identity for a candidate: shape + node labels (external_ids)."""
    p = candidate.path
    shape = f"{p.source_marker}|{p.sink_marker}|{','.join(p.edge_signature)}"
    return f"{shape}|{'>'.join(p.node_labels)}"


@dataclass(frozen=True, slots=True)
class CandidateSnapshot:
    """One scan's candidate tier, keyed for cross-run diffing. ``entries``: key -> {score, story}."""

    entries: dict[str, dict[str, object]]

    def keys(self) -> frozenset[str]:
        return frozenset(self.entries)

    def to_dict(self) -> dict[str, dict[str, object]]:
        return dict(self.entries)

    @classmethod
    def from_dict(cls, data: dict[str, dict[str, object]]) -> CandidateSnapshot:
        return cls(entries=dict(data))


def snapshot_candidates(candidates: Sequence[CandidatePath]) -> CandidateSnapshot:
    """Capture a scan's candidates as a keyed snapshot (with score + story for later rendering)."""
    return CandidateSnapshot(
        entries={
            candidate_key(c): {"score": c.score, "story": candidate_story(c.path)}
            for c in candidates
        }
    )


@dataclass(frozen=True, slots=True)
class CandidateDelta:
    """What changed between two candidate snapshots, by key."""

    new: tuple[str, ...]
    resolved: tuple[str, ...]
    persisting: tuple[str, ...]

    @property
    def has_new(self) -> bool:
        return bool(self.new)


def diff_candidates(previous: CandidateSnapshot, current: CandidateSnapshot) -> CandidateDelta:
    """New (appeared), resolved (gone), and persisting candidate keys between two scans."""
    prev, cur = previous.keys(), current.keys()
    return CandidateDelta(
        new=tuple(sorted(cur - prev)),
        resolved=tuple(sorted(prev - cur)),
        persisting=tuple(sorted(cur & prev)),
    )


def render_delta(delta: CandidateDelta, current: CandidateSnapshot, *, tenant_id: str) -> str:
    """A continuous-scan alert: the NEW candidate attack paths since the last scan (the headline).

    Resolved/persisting counts are noted; only NEW paths are alert-worthy detail (a path that just
    appeared is what an operator must look at). Empty new set → a clean "no new paths" line.
    """
    if not delta.has_new:
        return (
            f"No new candidate attack paths for tenant {tenant_id} "
            f"({len(delta.persisting)} unchanged, {len(delta.resolved)} resolved)."
        )
    lines = [
        f"ALERT: {len(delta.new)} new candidate attack path(s) for tenant {tenant_id} since the "
        f"last scan ({len(delta.persisting)} unchanged, {len(delta.resolved)} resolved):",
        "",
    ]
    for i, key in enumerate(delta.new, start=1):
        entry = current.entries.get(key, {})
        story = entry.get("story", key)
        score = entry.get("score", "?")
        lines.append(f"  {i}. [candidate {score}] {story}")
    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "CandidateDelta",
    "CandidateSnapshot",
    "candidate_key",
    "diff_candidates",
    "render_delta",
    "snapshot_candidates",
]
