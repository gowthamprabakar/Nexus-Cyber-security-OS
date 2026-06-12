"""Continuous + heartbeat mode coexistence (investigation v0.2 Task 21, Q6/WI-I9).

Per **Q6** both modes are available and **neither preempts the other** — HEARTBEAT (the v0.1
on-demand path, triggered by a Supervisor dispatch) stays the default; CONTINUOUS adds the
Task-20 scheduler on top. The mode is a **selection flag only**: it governs *when* an
investigation runs, never *how* the IncidentReport is rendered, so both modes produce
**byte-identical** OCSF 2005 output on the same input (WI-I5). Wiring CONTINUOUS into
``agent.run()`` is the Phase C consolidated retrofit (WI-I9). Pure + deterministic.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from investigation.schemas import IncidentReport

MODE_CONFIG_KEY = "investigation_monitoring_mode"


class MonitoringMode(StrEnum):
    HEARTBEAT = "heartbeat"
    CONTINUOUS = "continuous"


#: HEARTBEAT is the default — CONTINUOUS never preempts it (Q6).
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
    """Both modes are always available; neither preempts the other (Q6)."""
    return True


def emit_for_mode(mode: MonitoringMode, report: IncidentReport) -> dict[str, Any]:
    """Render a report's OCSF 2005 emission. The result is **mode-independent** — the mode governs
    cadence, not rendering — so HEARTBEAT and CONTINUOUS produce equal output on equal input."""
    del mode  # intentionally unused: rendering must not branch on the mode
    return report.to_ocsf()
