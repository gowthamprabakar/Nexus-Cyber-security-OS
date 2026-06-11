"""Live Polaris policy check execution (D.6 v0.2 Task 5).

The v0.2 live counterpart to the offline ``read_polaris`` (which stays for the
deterministic eval). Runs Polaris against a **running cluster** (kubeconfig-based, via an
injectable runner) and parses the JSON output with the **shared offline parser**
(`_extract_results` + `_walk_workload`) so findings are byte-identical. Per **Q3** a scan
targets a **single cluster**; the runner is injectable so this is unit-testable without a
live cluster.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from k8s_posture.tools.polaris import (
    PolarisFinding,
    _extract_results,
    _walk_workload,
)


class PolarisRunner(Protocol):
    """Executes Polaris against one cluster and returns its JSON output. The prod runner
    runs `polaris audit`; tests inject a fake."""

    def run(self, *, kubeconfig: str, context: str | None = None) -> dict[str, Any]: ...


def parse_polaris_blob(blob: Any, *, detected_at: datetime) -> tuple[PolarisFinding, ...]:
    """Parse a Polaris JSON blob → typed failing-check findings (shared offline parser).
    ``detected_at`` is caller-provided so the live path stays deterministic."""
    out: list[PolarisFinding] = []
    for workload in _extract_results(blob):
        out.extend(_walk_workload(workload, detected_at=detected_at))
    return tuple(out)


class PolarisLiveScanner:
    """Runs Polaris against a single running cluster + parses the result."""

    __slots__ = ("_runner",)

    def __init__(self, runner: PolarisRunner) -> None:
        self._runner = runner

    def scan(
        self, *, kubeconfig: str, context: str | None = None, detected_at: datetime
    ) -> tuple[PolarisFinding, ...]:
        """Run Polaris against the cluster named by ``kubeconfig`` + ``context`` (Q3: a
        single cluster) and return the parsed failing-check findings."""
        blob = self._runner.run(kubeconfig=kubeconfig, context=context)
        return parse_polaris_blob(blob, detected_at=detected_at)
