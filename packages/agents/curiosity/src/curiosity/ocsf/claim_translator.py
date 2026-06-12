"""CuriosityClaim -> OCSF 2004 translator (curiosity v0.2 Task 3, Q1/WI-X6).

Converts the existing ``CuriosityClaim`` envelope into an OCSF 2004 Detection Finding via the
Task-2 builder. The translation is **additive**: the CuriosityClaim on ``claims.>`` is unchanged
byte-for-byte (WI-X6), so existing claims.> consumers (D.5/D.7/D.8 v0.2 plans) are unaffected.

``coverage_gap_id`` is the deterministic id a hypothesis cites (the WI-X11 hallucination guard
resolves against it). For the v0.1 region-gap it is ``region:<region>``; M4's technique-gap +
time-gap detectors extend the namespace (``technique:<id>`` / ``time:<asset_class>``).
"""

from __future__ import annotations

from typing import Any

from curiosity.ocsf.schema import build_curiosity_finding
from curiosity.schemas import CoverageGap, CuriosityClaim


def coverage_gap_id(gap: CoverageGap) -> str:
    """The deterministic id for a detected gap — the region-gap namespace (M4 extends it)."""
    return f"region:{gap.region}"


def claim_to_ocsf(claim: CuriosityClaim) -> dict[str, Any]:
    """Render a CuriosityClaim as an OCSF 2004 Detection Finding. Additive — the source claim is
    untouched (WI-X6)."""
    hypothesis = claim.hypothesis
    gap = hypothesis.cited_gap
    return build_curiosity_finding(
        claim_id=claim.claim_id,
        title=f"Coverage gap hypothesis: {gap.region}",
        statement=hypothesis.statement,
        rationale=hypothesis.rationale,
        severity=gap.severity_hint,
        coverage_gap_id=coverage_gap_id(gap),
        probe_directive=hypothesis.probe_directive.model_dump(mode="json"),
        detected_at_ms=int(claim.emitted_at.timestamp() * 1000),
    )
