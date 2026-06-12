"""Delegation failure classification (supervisor v0.2 Task 7, Q3).

Classifies a failed delegation into **transient / permanent / timeout** so the bounded retry
policy (Task 8) can decide: transient -> retry once, permanent + timeout -> escalate. The
heuristics read the outcome status + the failure reason (error type / HTTP status / budget
exhaustion). Conservative by design: an **unknown** failure classifies as **permanent**
(escalate), never retried blindly — consistent with the H4 one-shot invariant.
"""

from __future__ import annotations

from enum import StrEnum

from supervisor.schemas import DelegationOutcome, DelegationStatus


class FailureClass(StrEnum):
    TRANSIENT = "transient"
    PERMANENT = "permanent"
    TIMEOUT = "timeout"


# Permanent markers are checked FIRST — an auth / validation / not-found error must never be
# retried even if the message also mentions something transient-sounding.
_PERMANENT_MARKERS = (
    "not found",
    "unauthorized",
    "forbidden",
    "permission",
    "invalid",
    "validation",
    "unsupported",
    "400",
    "401",
    "403",
    "404",
)
_TRANSIENT_MARKERS = (
    "connection reset",
    "connection refused",
    "temporarily",
    "temporary",
    "rate limit",
    "throttl",
    "unavailable",
    "try again",
    "429",
    "502",
    "503",
    "504",
)


def classify_failure(*, status: DelegationStatus, reason: str | None) -> FailureClass:
    """Classify a failed delegation. ``OK`` is not a failure and raises ``ValueError``."""
    if status is DelegationStatus.OK:
        raise ValueError("classify_failure called on a successful (OK) outcome")
    if status is DelegationStatus.TIMEOUT_PARTIAL:
        return FailureClass.TIMEOUT
    text = (reason or "").lower()
    if any(marker in text for marker in _PERMANENT_MARKERS):
        return FailureClass.PERMANENT
    if any(marker in text for marker in _TRANSIENT_MARKERS):
        return FailureClass.TRANSIENT
    return FailureClass.PERMANENT  # unknown -> escalate (conservative, H4)


def classify_outcome(outcome: DelegationOutcome) -> FailureClass:
    """Classify a failed ``DelegationOutcome``."""
    return classify_failure(status=outcome.status, reason=outcome.reason)
