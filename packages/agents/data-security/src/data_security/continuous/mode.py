"""Continuous + heartbeat mode coexistence (data-security v0.2 Task 18).

Per **WI-S11** both monitoring modes are available and **neither preempts the other** —
HEARTBEAT (the v0.1 on-demand path) stays the default; CONTINUOUS adds the scheduler + delta
infrastructure on top. The mode is a **selection flag only**: it governs *when* a re-scan
happens, never *how* data is classified, so both modes produce **identical** results on the
same input. (Wiring CONTINUOUS into ``agent.run()`` is the Phase C consolidated retrofit.)
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from data_security.classifiers.scored import ScoredClassification, classify_scored

MODE_CONFIG_KEY = "data_security_monitoring_mode"


class MonitoringMode(StrEnum):
    HEARTBEAT = "heartbeat"
    CONTINUOUS = "continuous"


#: HEARTBEAT is the default — CONTINUOUS never preempts it (WI-S11).
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
    """Both modes are always available; neither preempts the other (WI-S11)."""
    return True


def classify_for_mode(mode: MonitoringMode, text: str) -> ScoredClassification:
    """Classify content. The result is **mode-independent** — the mode governs cadence, not
    classification — so HEARTBEAT and CONTINUOUS return equal results on equal input."""
    del mode  # intentionally unused: classification must not branch on the mode
    return classify_scored(text)
