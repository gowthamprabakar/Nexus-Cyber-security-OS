"""Continuous + heartbeat mode coexistence (curiosity v0.2 Task 18, Q6/WI-X2).

Per **Q6** both modes are available and **neither preempts the other** — HEARTBEAT (the v0.1
on-demand path) stays the default; CONTINUOUS adds the scheduler on top. The mode is a
**selection flag only**: it governs *when* a scan runs, never *how* the OCSF 2004 findings render,
so both modes produce **byte-identical** emission on the same input (WI-X5). Wiring CONTINUOUS into
``agent.run()`` is the Phase C retrofit (WI-X2). Pure + deterministic.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from curiosity.ocsf.emission import render_curiosity_findings_json
from curiosity.schemas import CuriosityReport

MODE_CONFIG_KEY = "curiosity_monitoring_mode"


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


def emit_for_mode(mode: MonitoringMode, report: CuriosityReport) -> str:
    """Render a report's OCSF 2004 emission. The result is **mode-independent** — the mode governs
    cadence, not rendering — so HEARTBEAT and CONTINUOUS produce equal output on equal input."""
    del mode  # intentionally unused: rendering must not branch on the mode
    return render_curiosity_findings_json(report)
