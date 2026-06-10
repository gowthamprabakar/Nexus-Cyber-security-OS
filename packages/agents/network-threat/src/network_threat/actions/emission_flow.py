"""Block action emission flow (D.4 v0.2 Task 16).

Wires a finding to a TTL-bounded block decision, an **audit-chain entry** per block + per
expiry, and the **Investigation handoff** flag (Q6 — D.4 sets the flag + a block ref; D.7
reviews the block decision, D.4 does not auto-escalate). The handoff/block fields attach
to evidence **only when present**, so the offline `run()`'s findings stay byte-identical
(WI-N5).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from network_threat.actions.temporary_ip_block import (
    TemporaryIpBlock,
    UnauthorizedNetworkActionError,
    request_temporary_ip_block,
)

INVESTIGATION_KEY = "investigation_recommended"
BLOCK_REF_KEY = "block_ref"

_BLOCK_SEVERITIES = frozenset({"critical", "high"})


def should_emit_block(severity: str) -> bool:
    """Only high/critical findings warrant a block proposal."""
    return severity.lower() in _BLOCK_SEVERITIES


def emit_block_for_finding(
    *, severity: str, target_ip: str, ttl_seconds: int, reason: str, requested_at: datetime
) -> TemporaryIpBlock | None:
    """Decide + build a TTL-bounded block for a finding. Returns `None` when the finding
    doesn't warrant a block (low severity) OR the target is non-blockable (private/invalid
    — the safety guard rejects it, and the safe default is no block)."""
    if not should_emit_block(severity):
        return None
    try:
        return request_temporary_ip_block(
            target_ip, ttl_seconds=ttl_seconds, reason=reason, requested_at=requested_at
        )
    except UnauthorizedNetworkActionError:
        return None


def block_audit_entry(block: TemporaryIpBlock, *, event: str) -> dict[str, Any]:
    """An audit-chain entry for a block lifecycle event (``block_emitted`` /
    ``block_expired``)."""
    return {
        "event": event,
        "action_type": block.action_type,
        "target_ip": block.target_ip,
        "ttl_seconds": block.ttl_seconds,
        "requested_at": block.requested_at,
        "expires_at": block.expires_at,
    }


def attach_block_handoff(
    evidence: dict[str, Any], *, recommended: bool, block_ref: str | None = None
) -> dict[str, Any]:
    """Return a NEW evidence dict with the Investigation handoff flag (+ block ref if any).
    D.4 sets the flag; D.7 reviews. Never mutates the input."""
    out = dict(evidence)
    out[INVESTIGATION_KEY] = recommended
    if block_ref:
        out[BLOCK_REF_KEY] = block_ref
    return out
