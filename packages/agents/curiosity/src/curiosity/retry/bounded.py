"""Bounded-retry invariant — code-level (curiosity v0.2 Task 13, WI-X10).

**Inherited from D.13** (Cycle 13; proven by D.7, Cycle 14). The Q6 reviewer may reject an
LLM-generated hypothesis (classifier-substring leakage) and trigger a retry — but **at most one**.
``assert_bounded_retry`` is the hard guard against an LLM cost spiral: more than 2 attempts (the
initial call + 1 retry) raises. Per H4 most scan windows skip the LLM entirely (no gaps), so this
guard protects the rare gap-bearing windows.
"""

from __future__ import annotations

#: The initial hypothesize call + at most one Q6 retry.
MAX_ATTEMPTS = 2


class BoundedRetryViolationError(RuntimeError):
    """Raised when the hypothesize retry budget is exceeded (WI-X10)."""


def assert_bounded_retry(attempt_count: int) -> None:
    """Hard guard — raise if ``attempt_count`` exceeds MAX_ATTEMPTS (the initial call + 1 retry).

    On exhaustion the driver keeps the last deterministic-reviewed draft rather than retrying
    again — never an unbounded retry loop.
    """
    if attempt_count > MAX_ATTEMPTS:
        raise BoundedRetryViolationError(
            f"Hypothesize attempt {attempt_count} exceeds the Q6 retry budget of {MAX_ATTEMPTS} "
            f"(initial call + 1 retry); keep the last deterministic draft (WI-X10)."
        )
