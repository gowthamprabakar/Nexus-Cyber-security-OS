"""Continuous + heartbeat mode coexistence (compliance v0.2 Task 14).

Per **WI-C10** both monitoring modes are available and **neither preempts the other** —
HEARTBEAT (the v0.1 on-demand path) stays the default; CONTINUOUS adds the scheduler +
delta infrastructure on top. The mode is a **selection flag only**: it affects *when* a
re-scan happens, never *how* a framework is evaluated, so both modes produce **identical**
results on the same inputs. (Wiring CONTINUOUS into ``agent.run()`` is Phase C, WI-C4.)
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any

from compliance.consumption import evaluate_framework
from compliance.rollup import FrameworkRollup
from compliance.tools.cis_aws_benchmark import CisControl

MODE_CONFIG_KEY = "compliance_monitoring_mode"


class MonitoringMode(StrEnum):
    HEARTBEAT = "heartbeat"
    CONTINUOUS = "continuous"


#: HEARTBEAT is the default — CONTINUOUS never preempts it (WI-C10).
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
    """Both modes are always available; neither preempts the other (WI-C10)."""
    return True


def evaluate_for_mode(
    mode: MonitoringMode,
    framework: str,
    report: dict[str, Any],
    controls: Sequence[CisControl],
    *,
    source_agent: str,
) -> FrameworkRollup:
    """Evaluate a framework. The result is **mode-independent** — the mode governs cadence,
    not the evaluation — so HEARTBEAT and CONTINUOUS return equal rollups on equal inputs."""
    del mode  # intentionally unused: evaluation must not branch on the mode
    return evaluate_framework(framework, report, controls, source_agent=source_agent)
