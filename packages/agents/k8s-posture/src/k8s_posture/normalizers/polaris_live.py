"""Live Polaris → OCSF 2003 normalization (D.6 v0.2 Task 6).

The live Polaris findings (Task 5) are **byte-identical** to the offline path's, so
normalizing them to the OCSF 2003 Compliance Finding wire shape requires **no live-
specific code** — this delegates to the shared `normalize_polaris`. Exposed as a named
live entry point (and proven byte-identical in tests), WI-K5-compliant.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from shared.fabric.envelope import NexusEnvelope

from k8s_posture.normalizers.polaris import normalize_polaris
from k8s_posture.schemas import CloudPostureFinding
from k8s_posture.tools.polaris import PolarisFinding


def normalize_live_polaris(
    findings: Sequence[PolarisFinding], *, envelope: NexusEnvelope, scan_time: datetime
) -> tuple[CloudPostureFinding, ...]:
    """Normalize live Polaris findings → OCSF 2003 Compliance Findings. Delegates to the
    shared normalizer — same wire shape as the offline path, no divergence (WI-K5)."""
    return normalize_polaris(findings, envelope=envelope, scan_time=scan_time)
