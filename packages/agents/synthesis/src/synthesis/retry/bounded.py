"""Bounded-retry invariant — code-level (synthesis v0.2 Task 16, WI-Y10/H5).

Per **H5** a synthesis run performs **at most one** Q6 retry: total attempts are capped at 2
(the initial attempt + 1 retry). On exhaustion the driver accepts the degraded draft — it never
retries again. ``assert_bounded_retry`` is the hard, code-level guard (the second of the three
LLM-agent invariants) that prevents an LLM retry loop from spiralling cost. Mirrors the
D.3/D.4/data-security/F.6/supervisor + the Task-15 categorical guard.
"""

from __future__ import annotations

#: H5: initial attempt + at most one retry.
MAX_ATTEMPTS = 2


class BoundedRetryViolationError(RuntimeError):
    """Raised when a run exceeds the H5 attempt bound (WI-Y10)."""


def assert_bounded_retry(attempt_count: int) -> None:
    """Hard guard — raise if ``attempt_count`` exceeds the H5 bound (max ``MAX_ATTEMPTS``).

    On exhaustion the driver accepts the degraded draft; it never retries beyond the bound.
    """
    if attempt_count > MAX_ATTEMPTS:
        raise BoundedRetryViolationError(
            f"Retry attempt {attempt_count} exceeds the H5 bound (max {MAX_ATTEMPTS}). "
            f"Accept the degraded draft; never retry beyond {MAX_ATTEMPTS}."
        )
