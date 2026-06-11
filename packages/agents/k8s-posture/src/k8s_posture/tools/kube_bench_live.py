"""Live kube-bench scan execution (D.6 v0.2 Task 2).

The v0.2 live counterpart to the offline ``read_kube_bench`` (which stays for the
deterministic eval). Runs kube-bench against a **running cluster** (kubeconfig-based, via
an injectable runner) and parses the JSON output with the **shared offline parser**
(`_extract_controls` + `_walk_control`) so findings are byte-identical. Per **Q3** a scan
targets a **single cluster** (kubeconfig + context); the runner is injectable so this is
unit-testable without a live cluster.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from k8s_posture.tools.kube_bench import (
    KubeBenchFinding,
    _extract_controls,
    _walk_control,
)


class KubeBenchRunner(Protocol):
    """Executes kube-bench against one cluster and returns its JSON output. The prod
    runner runs kube-bench as a Job / subprocess; tests inject a fake."""

    def run(self, *, kubeconfig: str, context: str | None = None) -> dict[str, Any]: ...


def parse_kube_bench_blob(blob: Any, *, detected_at: datetime) -> tuple[KubeBenchFinding, ...]:
    """Parse a kube-bench JSON blob → typed FAIL/WARN findings (shared offline parser).
    ``detected_at`` is caller-provided so the live path stays deterministic."""
    out: list[KubeBenchFinding] = []
    for control in _extract_controls(blob):
        out.extend(_walk_control(control, detected_at=detected_at))
    return tuple(out)


class KubeBenchLiveScanner:
    """Runs kube-bench against a single running cluster + parses the result."""

    __slots__ = ("_runner",)

    def __init__(self, runner: KubeBenchRunner) -> None:
        self._runner = runner

    def scan(
        self, *, kubeconfig: str, context: str | None = None, detected_at: datetime
    ) -> tuple[KubeBenchFinding, ...]:
        """Execute kube-bench against the cluster named by ``kubeconfig`` + ``context``
        (Q3: a single cluster) and return the parsed FAIL/WARN findings."""
        blob = self._runner.run(kubeconfig=kubeconfig, context=context)
        return parse_kube_bench_blob(blob, detected_at=detected_at)
