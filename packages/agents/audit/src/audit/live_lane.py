"""NEXUS_LIVE_AUDIT gated live-eval lane (audit v0.2 Task 15).

Consumes the charter Pattern D (`charter.live_lane`). A single env gate, ``NEXUS_LIVE_AUDIT``,
covers the live cross-agent audit aggregation, with **per-source** reachability probes over the
three Q1 source kinds (charter ``audit.jsonl`` / F.5 episodes / per-agent chains). A distinct
gate from every prior cycle. Probes are injectable so they're testable without live sources.
"""

from __future__ import annotations

from collections.abc import Callable

from charter.live_lane import live_skip_reason, nexus_live_enabled

AUDIT_LIVE_ENV = "NEXUS_LIVE_AUDIT"
AUDIT_LIVE_SETUP = (
    "set NEXUS_LIVE_AUDIT=1 and point the agent at live audit sources (charter audit.jsonl "
    "path, the F.5 episodes DB, and/or the per-agent chains). e.g.: NEXUS_LIVE_AUDIT=1 uv run "
    "pytest packages/agents/audit/tests/integration/test_audit_cross_agent_e2e.py -v"
)

#: The three Q1 source kinds the single lane covers.
AUDIT_SOURCES = ("charter_jsonl", "f5_episodes", "agent_chain")


def nexus_live_audit_enabled() -> bool:
    """True iff the live audit lane is enabled (`NEXUS_LIVE_AUDIT=1`)."""
    return nexus_live_enabled(AUDIT_LIVE_ENV)


def source_reachable(
    available_sources: tuple[str, ...] = (),
    probe: Callable[[], tuple[bool, str]] | None = None,
) -> tuple[bool, str]:
    """Reachable iff at least one known audit source is available. Pass the available source
    names, or an explicit ``probe``."""
    if probe is not None:
        return probe()
    present = [s for s in available_sources if s in AUDIT_SOURCES]
    if present:
        return True, ""
    return False, "no-audit-source-reachable"


def audit_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = lambda: (False, "no-audit-source-reachable"),
) -> str | None:
    return live_skip_reason(AUDIT_LIVE_ENV, "audit sources", AUDIT_LIVE_SETUP, probe)
