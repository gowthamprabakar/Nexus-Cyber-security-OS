"""curiosity v0.2 Task 16 — assert_no_claims_subscription tests (WI-X14, NEW)."""

from __future__ import annotations

import pytest
from curiosity.claims.producer_only import (
    FORBIDDEN_SUBJECT_PREFIX,
    ProducerOnlyViolationError,
    assert_no_claims_subscription,
)


def test_forbidden_prefix() -> None:
    assert FORBIDDEN_SUBJECT_PREFIX == "claims."


def test_empty_subscriptions_ok() -> None:
    assert_no_claims_subscription([])


def test_non_claims_subscriptions_ok() -> None:
    assert_no_claims_subscription(["findings.>", "events.tenant.x", "telemetry.curiosity"])


def test_claims_subscription_raises() -> None:
    with pytest.raises(ProducerOnlyViolationError, match=r"claims\.curiosity"):
        assert_no_claims_subscription(["claims.curiosity.>"])


def test_any_claims_subject_raises() -> None:
    with pytest.raises(ProducerOnlyViolationError, match=r"claims\.tenant\.x"):
        assert_no_claims_subscription(["findings.>", "claims.tenant.x"])


def test_non_subscription_subjects_ok() -> None:
    assert_no_claims_subscription(["events.>"])
