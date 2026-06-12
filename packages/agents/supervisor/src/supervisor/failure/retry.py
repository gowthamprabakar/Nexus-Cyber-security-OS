"""Bounded retry policy (supervisor v0.2 Task 8, Q3/H4).

Per **Q3 + H4**: a **transient** failure is retried **at most once** (total attempts capped at
2 = initial + 1 retry); a **permanent** or **timeout** failure escalates immediately with no
retry. This is the *only* exception to the H4 one-shot-notification invariant. The runner is
pure orchestration over an injectable ``attempt`` callable, so it carries no dispatch internals
and stays deviation-clean (WI-O11). When a retry happens, ``RetryResult.retried`` is True — the
signal the ``supervisor.delegation.retried`` audit entry keys off (emitted in M5).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum

from supervisor.failure.classifier import FailureClass, classify_outcome
from supervisor.schemas import DelegationContract, DelegationOutcome, DelegationStatus

#: H4: initial attempt + at most one transient retry.
MAX_TOTAL_ATTEMPTS = 2


class RetryDecision(StrEnum):
    RETRY = "retry"
    ESCALATE = "escalate"


def decide_retry(failure_class: FailureClass, *, attempts_made: int) -> RetryDecision:
    """Retry only a transient failure, and only while under the attempt cap; everything else
    escalates."""
    if failure_class is FailureClass.TRANSIENT and attempts_made < MAX_TOTAL_ATTEMPTS:
        return RetryDecision.RETRY
    return RetryDecision.ESCALATE


@dataclass(frozen=True, slots=True)
class RetryResult:
    outcome: DelegationOutcome
    attempts: int
    retried: bool


async def run_with_retry(
    contract: DelegationContract,
    *,
    attempt: Callable[[DelegationContract], Awaitable[DelegationOutcome]],
) -> RetryResult:
    """Run ``attempt(contract)`` under the bounded policy: success returns immediately; a
    transient failure retries once; permanent/timeout escalate. Total attempts <= 2 (H4)."""
    outcome = await attempt(contract)
    attempts = 1
    while outcome.status is not DelegationStatus.OK and attempts < MAX_TOTAL_ATTEMPTS:
        failure_class = classify_outcome(outcome)
        if decide_retry(failure_class, attempts_made=attempts) is RetryDecision.ESCALATE:
            break
        outcome = await attempt(contract)
        attempts += 1
    return RetryResult(outcome=outcome, attempts=attempts, retried=attempts > 1)
