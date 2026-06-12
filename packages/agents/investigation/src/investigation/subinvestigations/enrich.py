"""timeline + ioc_pivot enhancements (investigation v0.2 Task 7).

Additive enrichment for two sub-investigation types — the v0.1 sub-agents + the ioc_extractor
are untouched (eval byte-identical, WI-I5):

- **timeline**: ``order_timeline`` builds a deterministic, time-ordered event sequence from the
  live F.6 audit query (Cycle-11 cross-agent aggregation), tie-broken by correlation id.
- **ioc_pivot**: ``extract_supplementary_hashes`` adds md5 (32-hex) + sha1 (40-hex) patterns
  beyond the v0.1 sha256, without disturbing the existing extractor. External enrichment is v0.3.

Pure + deterministic.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

# Hash shapes not covered by the v0.1 sha256 extractor. Anchored so a 64-hex sha256 doesn't
# partially match (word boundaries require the exact length).
_MD5_RE = re.compile(r"\b[0-9a-f]{32}\b")
_SHA1_RE = re.compile(r"\b[0-9a-f]{40}\b")


def order_timeline(events: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    """Order audit events into a deterministic timeline by ``(timestamp, correlation_id)``.

    Reads the ``emitted_at`` / ``time`` field for ordering + ``correlation_id`` for tie-breaks;
    missing fields sort first (empty string). Returns plain dicts (envelope copy)."""

    def _key(event: Mapping[str, Any]) -> tuple[str, str]:
        ts = event.get("emitted_at") or event.get("time") or ""
        corr = event.get("correlation_id") or ""
        return (str(ts), str(corr))

    return tuple(dict(e) for e in sorted(events, key=_key))


def extract_supplementary_hashes(text: str) -> dict[str, tuple[str, ...]]:
    """Extract md5 + sha1 hashes (additive to the v0.1 sha256 extractor). sha1 matches are
    excluded from the md5 set (a 40-hex never matches the 32-hex pattern, so they're disjoint)."""
    md5 = tuple(sorted(set(_MD5_RE.findall(text))))
    sha1 = tuple(sorted(set(_SHA1_RE.findall(text))))
    return {"md5": md5, "sha1": sha1}
