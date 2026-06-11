"""Live kube-bench → OCSF 2003 normalization (D.6 v0.2 Task 3).

The live kube-bench findings (Task 2) are **byte-identical** to the offline path's, so
normalizing them to the OCSF 2003 Compliance Finding wire shape requires **no live-
specific code** — this delegates to the shared `normalize_kube_bench`. Exposed as a
named live entry point (and proven byte-identical in tests) so the live scan path has a
clear, WI-K5-compliant normalization surface.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from shared.fabric.envelope import NexusEnvelope

from k8s_posture.normalizers.kube_bench import normalize_kube_bench
from k8s_posture.schemas import CloudPostureFinding
from k8s_posture.tools.kube_bench import KubeBenchFinding


def normalize_live_kube_bench(
    findings: Sequence[KubeBenchFinding], *, envelope: NexusEnvelope, scan_time: datetime
) -> tuple[CloudPostureFinding, ...]:
    """Normalize live kube-bench findings → OCSF 2003 Compliance Findings. Delegates to
    the shared normalizer — same wire shape as the offline path, no divergence (WI-K5)."""
    return normalize_kube_bench(findings, envelope=envelope, scan_time=scan_time)
