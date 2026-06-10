"""Passive behavioral baseline observation (D.3 v0.2 Task 11).

Accumulates the **normal** behavior of each workload (process names, network
connections, accessed files) from the real-time event stream. Per **Q5 / WI-R10** this
is **passive** at v0.2: it only **collects + stores** the baseline — it does **not**
detect drift or drive any finding. Active drift detection on top of this data is v0.3.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from runtime_threat.tools.falco_normalize import NormalizedFalcoEvent
from runtime_threat.tools.tracee_normalize import NormalizedTraceeEvent


@dataclass(slots=True)
class WorkloadBaseline:
    workload_id: str
    processes: set[str] = field(default_factory=set)
    connections: set[str] = field(default_factory=set)
    files: set[str] = field(default_factory=set)


class BaselineObserver:
    """Passively collects per-workload behavioral baselines. Set semantics dedupe; no
    drift detection (Q5 — the data is available for v0.3 active detection)."""

    def __init__(self) -> None:
        self._baselines: dict[str, WorkloadBaseline] = {}

    def _wb(self, workload_id: str) -> WorkloadBaseline:
        return self._baselines.setdefault(workload_id, WorkloadBaseline(workload_id))

    def observe_process(self, workload_id: str, process_name: str) -> None:
        if workload_id and process_name:
            self._wb(workload_id).processes.add(process_name)

    def observe_connection(self, workload_id: str, connection: str) -> None:
        if workload_id and connection:
            self._wb(workload_id).connections.add(connection)

    def observe_file(self, workload_id: str, path: str) -> None:
        if workload_id and path:
            self._wb(workload_id).files.add(path)

    def observe_falco(self, event: NormalizedFalcoEvent) -> None:
        """Record a Falco event's process + container context into the baseline."""
        wl = event.enrichment.container.id
        self.observe_process(wl, event.enrichment.process.name)
        fd = event.alert.output_fields.get("fd.name")
        if isinstance(fd, str):
            self.observe_file(wl, fd)

    def observe_tracee(self, event: NormalizedTraceeEvent) -> None:
        """Record a Tracee event's process + accessed-file context into the baseline."""
        wl = event.alert.container_id
        self.observe_process(wl, event.alert.process_name)
        if event.syscall.pathname:
            self.observe_file(wl, event.syscall.pathname)

    def baseline(self, workload_id: str) -> WorkloadBaseline | None:
        return self._baselines.get(workload_id)

    def workloads(self) -> tuple[str, ...]:
        return tuple(self._baselines)
