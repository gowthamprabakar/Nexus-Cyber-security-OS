"""NEXUS_LIVE_RUNTIME_* gated live-eval lanes (D.3 v0.2 Tasks 16-17).

Consumes the hoisted charter Pattern D (`charter.live_lane`). Per **Q2** Falco and Tracee
get **separate** lanes (per-sensor reachability, WI-R1). DISTINCT gates from F.3/D.5/
D.1/D.2/D.8. Reachability probes are injectable so they're testable without live sensors.

Task 16 adds the Falco lane; Task 17 adds the Tracee lane.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from charter.live_lane import live_skip_reason, nexus_live_enabled

FALCO_LIVE_ENV = "NEXUS_LIVE_RUNTIME_FALCO"
#: Default Falco gRPC outputs unix socket — a cheap reachability proxy.
FALCO_GRPC_SOCKET = "/run/falco/falco.sock"

FALCO_LIVE_SETUP = (
    "set NEXUS_LIVE_RUNTIME_FALCO=1 and run Falco with the gRPC outputs service enabled "
    f"(unix socket at {FALCO_GRPC_SOCKET}). e.g.: NEXUS_LIVE_RUNTIME_FALCO=1 uv run pytest "
    "packages/agents/runtime-threat/tests/integration/test_runtime_realtime_e2e.py -v -k falco"
)


def nexus_live_runtime_falco_enabled() -> bool:
    """True iff D.3's live Falco lane is enabled (`NEXUS_LIVE_RUNTIME_FALCO=1`)."""
    return nexus_live_enabled(FALCO_LIVE_ENV)


def _probe_falco_socket() -> tuple[bool, str]:
    return (
        os.path.exists(FALCO_GRPC_SOCKET),
        "" if os.path.exists(FALCO_GRPC_SOCKET) else "socket-not-found",
    )


def falco_reachable(
    probe: Callable[[], tuple[bool, str]] = _probe_falco_socket,
) -> tuple[bool, str]:
    """Probe Falco gRPC reachability. Returns ``(ok, reason)`` (secret-free reason)."""
    return probe()


def runtime_falco_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = falco_reachable,
) -> str | None:
    """`None` when the Falco lane is enabled AND reachable; otherwise the `pytest.skip`
    message with setup steps."""
    return live_skip_reason(FALCO_LIVE_ENV, "Falco gRPC", FALCO_LIVE_SETUP, probe)


# --------------------------- Tracee lane (Task 17) -----------------------

TRACEE_LIVE_ENV = "NEXUS_LIVE_RUNTIME_TRACEE"
#: Default Tracee event-pipe socket — a cheap reachability proxy.
TRACEE_PIPE_SOCKET = "/var/run/tracee/tracee.sock"

TRACEE_LIVE_SETUP = (
    "set NEXUS_LIVE_RUNTIME_TRACEE=1 and run Tracee streaming events to its pipe "
    f"(socket at {TRACEE_PIPE_SOCKET}). e.g.: NEXUS_LIVE_RUNTIME_TRACEE=1 uv run pytest "
    "packages/agents/runtime-threat/tests/integration/test_runtime_realtime_e2e.py -v -k tracee"
)


def nexus_live_runtime_tracee_enabled() -> bool:
    """True iff D.3's live Tracee lane is enabled (`NEXUS_LIVE_RUNTIME_TRACEE=1`)."""
    return nexus_live_enabled(TRACEE_LIVE_ENV)


def _probe_tracee_pipe() -> tuple[bool, str]:
    return (
        os.path.exists(TRACEE_PIPE_SOCKET),
        "" if os.path.exists(TRACEE_PIPE_SOCKET) else "pipe-not-found",
    )


def tracee_reachable(
    probe: Callable[[], tuple[bool, str]] = _probe_tracee_pipe,
) -> tuple[bool, str]:
    """Probe Tracee pipe reachability. Returns ``(ok, reason)`` (secret-free reason)."""
    return probe()


def runtime_tracee_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = tracee_reachable,
) -> str | None:
    """`None` when the Tracee lane is enabled AND reachable; otherwise the `pytest.skip`
    message with setup steps. A SEPARATE gate from the Falco lane (Q2)."""
    return live_skip_reason(TRACEE_LIVE_ENV, "Tracee pipe", TRACEE_LIVE_SETUP, probe)
