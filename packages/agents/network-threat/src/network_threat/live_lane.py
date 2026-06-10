"""NEXUS_LIVE_NETWORK_* gated live-eval lanes (D.4 v0.2 Tasks 17-18).

Consumes the hoisted charter Pattern D (`charter.live_lane`). Per **Q2** Suricata and Zeek
get **separate** lanes (per-sensor reachability, WI-N1); per **Q3** AWS VPC flow gets its
own lane (Task 18). DISTINCT gates from all prior cycles. Reachability probes are
injectable so they're testable without live sensors. Mirrors D.3's per-sensor lanes.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from charter.live_lane import live_skip_reason, nexus_live_enabled

# --------------------------- Suricata lane (Task 17) ----------------------

SURICATA_LIVE_ENV = "NEXUS_LIVE_NETWORK_SURICATA"
SURICATA_SOCKET = "/var/run/suricata/eve.sock"
SURICATA_LIVE_SETUP = (
    "set NEXUS_LIVE_NETWORK_SURICATA=1 and run Suricata writing eve.json to a socket "
    f"({SURICATA_SOCKET}). e.g.: NEXUS_LIVE_NETWORK_SURICATA=1 uv run pytest "
    "packages/agents/network-threat/tests/integration/test_network_realtime_e2e.py -v -k suricata"
)


def nexus_live_network_suricata_enabled() -> bool:
    """True iff D.4's live Suricata lane is enabled (`NEXUS_LIVE_NETWORK_SURICATA=1`)."""
    return nexus_live_enabled(SURICATA_LIVE_ENV)


def _probe_suricata() -> tuple[bool, str]:
    return (
        os.path.exists(SURICATA_SOCKET),
        "" if os.path.exists(SURICATA_SOCKET) else "socket-not-found",
    )


def suricata_reachable(probe: Callable[[], tuple[bool, str]] = _probe_suricata) -> tuple[bool, str]:
    return probe()


def network_suricata_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = suricata_reachable,
) -> str | None:
    return live_skip_reason(SURICATA_LIVE_ENV, "Suricata eve socket", SURICATA_LIVE_SETUP, probe)


# ----------------------------- Zeek lane (Task 17) ------------------------

ZEEK_LIVE_ENV = "NEXUS_LIVE_NETWORK_ZEEK"
ZEEK_SOCKET = "/var/run/zeek/broker.sock"
ZEEK_LIVE_SETUP = (
    "set NEXUS_LIVE_NETWORK_ZEEK=1 and run Zeek streaming logs over the Broker socket "
    f"({ZEEK_SOCKET}). e.g.: NEXUS_LIVE_NETWORK_ZEEK=1 uv run pytest "
    "packages/agents/network-threat/tests/integration/test_network_realtime_e2e.py -v -k zeek"
)


def nexus_live_network_zeek_enabled() -> bool:
    """True iff D.4's live Zeek lane is enabled (`NEXUS_LIVE_NETWORK_ZEEK=1`)."""
    return nexus_live_enabled(ZEEK_LIVE_ENV)


def _probe_zeek() -> tuple[bool, str]:
    return (os.path.exists(ZEEK_SOCKET), "" if os.path.exists(ZEEK_SOCKET) else "socket-not-found")


def zeek_reachable(probe: Callable[[], tuple[bool, str]] = _probe_zeek) -> tuple[bool, str]:
    return probe()


def network_zeek_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = zeek_reachable,
) -> str | None:
    return live_skip_reason(ZEEK_LIVE_ENV, "Zeek Broker socket", ZEEK_LIVE_SETUP, probe)
