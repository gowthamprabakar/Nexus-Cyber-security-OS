"""Supervisor-plus-specialists hierarchy invariant — code-level (supervisor v0.2 Task 15, WI-O8).

The H2 invariant: the supervisor (Agent #0) is the **only** source of delegations — there is no
peer-to-peer agent communication. v0.1 held this by construction (specialists have no dispatch
path); v0.2 makes it a hard, code-level guard, mirroring D.3 ``assert_authorized``, D.4
``assert_block_authorized``, data-security ``assert_privacy_contract``, and F.6
``assert_audit_readonly``. Any dispatch whose source is not ``supervisor`` raises.
"""

from __future__ import annotations

SUPERVISOR_AGENT_ID = "supervisor"


class PeerToPeerViolationError(RuntimeError):
    """Raised when a non-supervisor agent attempts to dispatch to another agent (WI-O8/H2)."""


def assert_no_peer_to_peer(source_agent: str, target_agent: str) -> None:
    """Hard guard — only the supervisor may dispatch. A non-supervisor ``source_agent`` raises.

    Per the H2 hierarchy invariant (supervisor-plus-specialists; no peer-to-peer) + ADR-007.
    """
    if source_agent != SUPERVISOR_AGENT_ID:
        raise PeerToPeerViolationError(
            f"Peer-to-peer dispatch detected — source {source_agent!r} attempting to "
            f"dispatch to {target_agent!r}. Only supervisor (Agent #0) may dispatch. "
            f"Per the H2 hierarchy invariant + ADR-007."
        )
