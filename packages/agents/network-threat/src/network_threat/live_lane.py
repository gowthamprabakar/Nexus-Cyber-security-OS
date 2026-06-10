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


# --------------------------- AWS VPC flow lane (Task 18) ------------------

VPC_AWS_LIVE_ENV = "NEXUS_LIVE_NETWORK_VPC_AWS"
VPC_AWS_LIVE_SETUP = (
    "set NEXUS_LIVE_NETWORK_VPC_AWS=1 and configure AWS credentials (AWS_PROFILE=<profile> "
    "or the boto3 default chain) with CloudWatch Logs read access to the VPC flow log "
    "group. e.g.: AWS_PROFILE=dev NEXUS_LIVE_NETWORK_VPC_AWS=1 uv run pytest "
    "packages/agents/network-threat/tests/integration/test_network_realtime_e2e.py -v -k vpc"
)


def nexus_live_network_vpc_aws_enabled() -> bool:
    """True iff D.4's live AWS VPC-flow lane is enabled (`NEXUS_LIVE_NETWORK_VPC_AWS=1`).
    Per Q3, AWS only at v0.2 (Azure NSG flow + GCP VPC flow are v0.3)."""
    return nexus_live_enabled(VPC_AWS_LIVE_ENV)


def _probe_vpc_aws() -> tuple[bool, str]:
    """Probe live-AWS reachability via STS get_caller_identity through the CredentialResolver.
    Returns ``(ok, reason)`` where reason is a secret-free, traceback-free type name."""
    try:
        from network_threat.credentials import CredentialResolver

        CredentialResolver().client("sts").get_caller_identity()
        return True, ""
    except Exception as exc:
        return False, type(exc).__name__


def vpc_aws_reachable(probe: Callable[[], tuple[bool, str]] = _probe_vpc_aws) -> tuple[bool, str]:
    return probe()


def network_vpc_aws_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = vpc_aws_reachable,
) -> str | None:
    return live_skip_reason(VPC_AWS_LIVE_ENV, "AWS VPC flow", VPC_AWS_LIVE_SETUP, probe)
