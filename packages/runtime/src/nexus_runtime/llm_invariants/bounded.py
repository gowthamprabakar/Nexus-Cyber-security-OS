"""Bounded-retry LLM invariant — shared canonical implementation (Phase D P3-2 hoist).

Per H5, an LLM-emitting agent performs **at most one** retry: total attempts are capped at
``MAX_ATTEMPTS`` (the initial attempt + 1 retry). On exhaustion the driver accepts the current
(degraded/deterministic) draft — it never retries again. ``assert_bounded_retry`` is the hard,
code-level guard that prevents an LLM retry loop from spiralling cost.

Single source of truth, hoisted from the three LLM agents (D.13 synthesis, D.7 investigation,
D.12 curiosity), which previously each carried an identical copy.
"""

from __future__ import annotations

#: H5: initial attempt + at most one retry.
MAX_ATTEMPTS = 2


class BoundedRetryViolationError(RuntimeError):
    """Raised when a run exceeds the H5 attempt bound."""


def assert_bounded_retry(attempt_count: int) -> None:
    """Hard guard — raise if ``attempt_count`` exceeds the H5 bound (max ``MAX_ATTEMPTS``).

    On exhaustion the driver accepts the current draft; it never retries beyond the bound.
    """
    if attempt_count > MAX_ATTEMPTS:
        raise BoundedRetryViolationError(
            f"Retry attempt {attempt_count} exceeds the bounded-retry cap (max {MAX_ATTEMPTS}); "
            f"accept the current draft, never retry beyond {MAX_ATTEMPTS}."
        )
