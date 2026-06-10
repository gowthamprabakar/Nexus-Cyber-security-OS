"""Temporary IP block auto-expiry (D.4 v0.2 Task 15).

Per **Q4 / WI-N11** every emitted IP block is **temporary** and MUST auto-expire: this
tracks active blocks, finds those past their TTL, and removes them via an injected
cloud-API remover. If a removal **fails**, the result flags an **escalation** — a block
that cannot be auto-removed is a safety violation (it would become effectively permanent).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from network_threat.actions.temporary_ip_block import TemporaryIpBlock

#: A remover applies the cloud-API removal for an expired block; returns success.
BlockRemover = Callable[[TemporaryIpBlock], bool]


def is_block_expired(block: TemporaryIpBlock, now: datetime) -> bool:
    """True once ``now`` reaches the block's ``expires_at`` (requested_at + TTL)."""
    return now >= datetime.fromisoformat(block.expires_at)


@dataclass
class ExpiryResult:
    removed: list[TemporaryIpBlock] = field(default_factory=list)
    failed: list[TemporaryIpBlock] = field(default_factory=list)

    @property
    def needs_escalation(self) -> bool:
        """True if any expired block could NOT be auto-removed (WI-N11 safety escalation)."""
        return bool(self.failed)


class BlockExpiryTracker:
    """Tracks active temporary IP blocks and auto-expires those past their TTL."""

    def __init__(self) -> None:
        self._blocks: list[TemporaryIpBlock] = []

    def register(self, block: TemporaryIpBlock) -> None:
        self._blocks.append(block)

    def active(self) -> tuple[TemporaryIpBlock, ...]:
        return tuple(self._blocks)

    def expired(self, now: datetime) -> list[TemporaryIpBlock]:
        return [b for b in self._blocks if is_block_expired(b, now)]

    def expire_due(self, now: datetime, *, remover: BlockRemover) -> ExpiryResult:
        """Remove every block past its TTL via ``remover``. Successfully-removed blocks
        leave the active set; failures stay active and flag an escalation (WI-N11)."""
        result = ExpiryResult()
        for block in self.expired(now):
            try:
                ok = remover(block)
            except Exception:  # a throwing remover is a removal failure, not a crash
                ok = False
            (result.removed if ok else result.failed).append(block)
        removed_set = set(result.removed)
        self._blocks = [b for b in self._blocks if b not in removed_set]
        return result
