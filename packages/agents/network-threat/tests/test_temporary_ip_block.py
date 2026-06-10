"""D.4 v0.2 Task 14 — temporary IP block action tests (Q4/WI-N8/WI-N10 safety invariant)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from network_threat.actions.temporary_ip_block import (
    AUTHORIZED_ACTION_TYPE,
    TemporaryIpBlock,
    UnauthorizedNetworkActionError,
    assert_block_authorized,
    request_temporary_ip_block,
)

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def test_request_builds_block() -> None:
    b = request_temporary_ip_block("8.8.8.8", ttl_seconds=300, reason="C2 beacon", requested_at=_T)
    assert isinstance(b, TemporaryIpBlock)
    assert b.target_ip == "8.8.8.8" and b.ttl_seconds == 300
    assert b.action_type == "temporary_ip_block" and b.is_temporary is True


def test_expires_at_is_requested_plus_ttl() -> None:
    b = request_temporary_ip_block("8.8.8.8", ttl_seconds=300, reason="r", requested_at=_T)
    assert b.requested_at == "2026-06-11T12:00:00+00:00"
    assert b.expires_at == "2026-06-11T12:05:00+00:00"  # +300s


def test_authorized_public_ip_with_valid_ttl() -> None:
    assert_block_authorized(AUTHORIZED_ACTION_TYPE, "8.8.8.8", 300)  # no raise


def test_reject_non_block_action() -> None:
    with pytest.raises(UnauthorizedNetworkActionError, match="Remediation cycle"):
        assert_block_authorized("permanent_block", "8.8.8.8", 300)


def test_reject_none_ttl_permanent() -> None:
    with pytest.raises(UnauthorizedNetworkActionError, match="never permanent"):
        assert_block_authorized(AUTHORIZED_ACTION_TYPE, "8.8.8.8", None)


def test_reject_ttl_over_one_hour() -> None:
    with pytest.raises(UnauthorizedNetworkActionError, match="never permanent"):
        assert_block_authorized(AUTHORIZED_ACTION_TYPE, "8.8.8.8", 3601)


def test_reject_zero_or_negative_ttl() -> None:
    with pytest.raises(UnauthorizedNetworkActionError):
        assert_block_authorized(AUTHORIZED_ACTION_TYPE, "8.8.8.8", 0)


def test_reject_private_rfc1918() -> None:
    for ip in ("10.0.0.5", "192.168.1.1", "172.16.0.9"):
        with pytest.raises(UnauthorizedNetworkActionError, match="private-range"):
            assert_block_authorized(AUTHORIZED_ACTION_TYPE, ip, 300)


def test_reject_loopback() -> None:
    with pytest.raises(UnauthorizedNetworkActionError, match="private-range"):
        assert_block_authorized(AUTHORIZED_ACTION_TYPE, "127.0.0.1", 300)


def test_reject_link_local() -> None:
    with pytest.raises(UnauthorizedNetworkActionError, match="private-range"):
        assert_block_authorized(AUTHORIZED_ACTION_TYPE, "169.254.1.1", 300)


def test_reject_invalid_ip() -> None:
    with pytest.raises(UnauthorizedNetworkActionError, match="invalid target IP"):
        assert_block_authorized(AUTHORIZED_ACTION_TYPE, "not-an-ip", 300)


def test_request_rejects_private_ip() -> None:
    with pytest.raises(UnauthorizedNetworkActionError):
        request_temporary_ip_block("10.0.0.5", ttl_seconds=300, reason="r", requested_at=_T)
