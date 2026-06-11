"""NEXUS_LIVE_COMPLIANCE gated live-eval lane (compliance v0.2 Task 18).

Consumes the hoisted charter Pattern D (`charter.live_lane`). compliance is a **consumer**
(it reads sibling emitters' OCSF 2003 reports), so this single lane (Q5) gates **live
multi-emitter consumption** — its reachability probe checks that the upstream emitter
reports (F.3 / D.5 / k8s-posture) are actually present. A DISTINCT gate from every prior
cycle. The probe is injectable so it's testable without live emitter output.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from charter.live_lane import live_skip_reason, nexus_live_enabled

COMPLIANCE_LIVE_ENV = "NEXUS_LIVE_COMPLIANCE"
COMPLIANCE_LIVE_SETUP = (
    "set NEXUS_LIVE_COMPLIANCE=1 and provide live OCSF 2003 reports from the emitters "
    "(cloud_posture / multi_cloud_posture / k8s_posture) for the frameworks under test. "
    "e.g.: NEXUS_LIVE_COMPLIANCE=1 uv run pytest "
    "packages/agents/compliance/tests/integration/test_compliance_multi_emitter_e2e.py -v"
)

#: The emitter agents whose OCSF 2003 reports compliance consumes.
SOURCE_EMITTERS = ("cloud_posture", "multi_cloud_posture", "k8s_posture")


def nexus_live_compliance_enabled() -> bool:
    """True iff the live-consumption lane is enabled (`NEXUS_LIVE_COMPLIANCE=1`)."""
    return nexus_live_enabled(COMPLIANCE_LIVE_ENV)


def _probe_emitters() -> tuple[bool, str]:
    # Default probe: no emitter reports wired in a bare environment.
    return False, "no-emitter-reports"


def emitters_reachable(
    available_emitters: Iterable[str] = (),
    probe: Callable[[], tuple[bool, str]] | None = None,
) -> tuple[bool, str]:
    """Reachable iff at least one source emitter's report is available. Pass
    ``available_emitters`` (the emitters that produced a report), or an explicit ``probe``."""
    if probe is not None:
        return probe()
    present = [e for e in available_emitters if e in SOURCE_EMITTERS]
    if present:
        return True, ""
    return False, "no-emitter-reports"


def compliance_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = _probe_emitters,
) -> str | None:
    return live_skip_reason(
        COMPLIANCE_LIVE_ENV, "emitter OCSF 2003 reports", COMPLIANCE_LIVE_SETUP, probe
    )
