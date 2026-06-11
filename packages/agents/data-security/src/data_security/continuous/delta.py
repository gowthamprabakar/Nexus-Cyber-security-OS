"""Delta detection across scan cycles (data-security v0.2 Task 17).

Compares two scan snapshots to surface what **changed** — newly-detected sensitive-data
findings vs **resolved** ones (data deleted, encrypted, or access tightened) — and tracks
deltas per bucket. Pure + deterministic; part of the continuous-monitoring INFRASTRUCTURE
(WI-S11). A finding is keyed ``"<source>/<label>"`` so the same label reappearing in a bucket
isn't double-counted. NOT wired into ``agent.run()`` (Phase C). Findings are keys only — the
hashes/labels carry no plaintext (WI-S8).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field


def finding_key(source: str, label: str) -> str:
    """The stable per-(bucket, classification) finding key used for deltas."""
    return f"{source}/{label}"


@dataclass(frozen=True, slots=True)
class FindingDelta:
    newly_detected: tuple[str, ...] = field(default_factory=tuple)
    resolved: tuple[str, ...] = field(default_factory=tuple)
    persisting: tuple[str, ...] = field(default_factory=tuple)

    @property
    def has_changes(self) -> bool:
        return bool(self.newly_detected or self.resolved)


def compute_delta(previous: Iterable[str], current: Iterable[str]) -> FindingDelta:
    """Diff two snapshots of sensitive-finding keys → newly-detected / resolved / persisting."""
    prev = set(previous)
    cur = set(current)
    return FindingDelta(
        newly_detected=tuple(sorted(cur - prev)),
        resolved=tuple(sorted(prev - cur)),
        persisting=tuple(sorted(cur & prev)),
    )


def per_bucket_delta(delta: FindingDelta, bucket: str) -> FindingDelta:
    """Narrow a delta to a single bucket's finding keys."""
    prefix = f"{bucket}/"
    return FindingDelta(
        newly_detected=tuple(k for k in delta.newly_detected if k.startswith(prefix)),
        resolved=tuple(k for k in delta.resolved if k.startswith(prefix)),
        persisting=tuple(k for k in delta.persisting if k.startswith(prefix)),
    )
