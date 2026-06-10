"""D.4 v0.2 Task 15 — temporary IP block auto-expiry tests (WI-N11)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from network_threat.actions.auto_expiry import BlockExpiryTracker, is_block_expired
from network_threat.actions.temporary_ip_block import request_temporary_ip_block

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def _block(ttl: int = 300) -> object:
    return request_temporary_ip_block("8.8.8.8", ttl_seconds=ttl, reason="r", requested_at=_T)


def test_is_block_expired_before_and_after() -> None:
    b = _block(ttl=300)
    assert is_block_expired(b, _T + timedelta(seconds=299)) is False
    assert is_block_expired(b, _T + timedelta(seconds=300)) is True  # at TTL → expired


def test_register_and_active() -> None:
    t = BlockExpiryTracker()
    t.register(_block())
    assert len(t.active()) == 1


def test_expired_returns_due_blocks() -> None:
    t = BlockExpiryTracker()
    t.register(_block(ttl=60))
    t.register(_block(ttl=3600))
    assert len(t.expired(_T + timedelta(seconds=120))) == 1  # only the 60s block


def test_expire_due_removes_via_remover() -> None:
    t = BlockExpiryTracker()
    t.register(_block(ttl=60))
    removed_ips: list[str] = []

    def remover(b: object) -> bool:
        removed_ips.append(b.target_ip)  # type: ignore[attr-defined]
        return True

    result = t.expire_due(_T + timedelta(seconds=120), remover=remover)
    assert len(result.removed) == 1 and result.needs_escalation is False
    assert removed_ips == ["8.8.8.8"]
    assert t.active() == ()  # removed from active set


def test_expire_due_failure_escalates() -> None:
    t = BlockExpiryTracker()
    t.register(_block(ttl=60))
    result = t.expire_due(_T + timedelta(seconds=120), remover=lambda _b: False)
    assert len(result.failed) == 1 and result.needs_escalation is True
    assert len(t.active()) == 1  # stays active (could not be removed)


def test_expire_due_remover_exception_is_failure() -> None:
    t = BlockExpiryTracker()
    t.register(_block(ttl=60))

    def boom(_b: object) -> bool:
        raise RuntimeError("api down")

    result = t.expire_due(_T + timedelta(seconds=120), remover=boom)
    assert result.needs_escalation is True


def test_non_expired_not_touched() -> None:
    t = BlockExpiryTracker()
    t.register(_block(ttl=3600))
    result = t.expire_due(_T + timedelta(seconds=60), remover=lambda _b: True)
    assert result.removed == [] and len(t.active()) == 1
