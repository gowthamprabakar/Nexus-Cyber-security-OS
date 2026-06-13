"""Continuous + heartbeat mode coexistence (remediation v0.2 Task 19, Q6/WI-A2).

Per **Q6** both modes are available and **neither preempts the other** — HEARTBEAT (the v0.1
on-demand path) stays the default; CONTINUOUS adds the scheduler on top. The mode governs *when* a
run happens, never *which tier* it runs at: a continuous run is still ``recommend`` unless the
operator opted into a higher tier via both auth layers, so H1 (default-to-recommend) is preserved
under continuous mode. Wiring CONTINUOUS into ``agent.run()`` is the Phase C retrofit (WI-A2).
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from remediation.schemas import RemediationMode

MODE_CONFIG_KEY = "remediation_monitoring_mode"


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


def tier_for_mode(mode: MonitoringMode) -> RemediationMode:
    """The default tier under a monitoring mode — ALWAYS recommend (H1 preserved).

    Continuous monitoring never auto-escalates the tier; a higher tier still requires the operator's
    dual-layer opt-in (--enable-execute + auth.yaml), regardless of HEARTBEAT vs CONTINUOUS.
    """
    del mode  # intentionally unused: the default tier never depends on the monitoring mode
    return RemediationMode.RECOMMEND
