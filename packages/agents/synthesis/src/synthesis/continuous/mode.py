"""Continuous + heartbeat mode coexistence (synthesis v0.2 Task 14, Q7).

Per **Q7** both modes are available and **neither preempts the other** — HEARTBEAT (the v0.1
on-demand path) stays the default; CONTINUOUS adds the scheduler infrastructure on top. The
mode is a **selection flag only**: it governs *when* a re-synthesis happens, never *how* a
report is rendered, so both modes produce **identical** OCSF output on the same input. (Wiring
CONTINUOUS into ``agent.run()`` is the Phase C consolidated retrofit, WI-Y2.)
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from synthesis.ocsf.emission import build_synthesis_finding_json
from synthesis.schemas import SynthesisReport

MODE_CONFIG_KEY = "synthesis_monitoring_mode"


class MonitoringMode(StrEnum):
    HEARTBEAT = "heartbeat"
    CONTINUOUS = "continuous"


#: HEARTBEAT is the default — CONTINUOUS never preempts it (Q7).
DEFAULT_MODE = MonitoringMode.HEARTBEAT


def select_mode(config: Mapping[str, Any]) -> MonitoringMode:
    """Resolve the monitoring mode from a charter config flag; unknown/missing -> default."""
    raw = config.get(MODE_CONFIG_KEY)
    if isinstance(raw, str):
        try:
            return MonitoringMode(raw.lower())
        except ValueError:
            return DEFAULT_MODE
    return DEFAULT_MODE


def modes_coexist() -> bool:
    """Both modes are always available; neither preempts the other (Q7)."""
    return True


def emit_for_mode(mode: MonitoringMode, report: SynthesisReport) -> bytes:
    """Render a report's OCSF emission. The result is **mode-independent** — the mode governs
    cadence, not rendering — so HEARTBEAT and CONTINUOUS produce equal bytes on equal input."""
    del mode  # intentionally unused: rendering must not branch on the mode
    return build_synthesis_finding_json(report)
