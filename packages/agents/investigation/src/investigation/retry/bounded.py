"""Bounded-retry invariant — code-level (investigation v0.2 Task 15, WI-I9).

**Inherited from D.13** (the LLM-agent template). An investigation performs **at most one**
retry per LLM call (synthesizer + per worker): total attempts capped at 2. On exhaustion the
synthesizer accepts the deterministic enumeration (H3) — it never retries again.
``assert_bounded_retry`` is the hard guard preventing an LLM retry loop from spiralling cost.
"""

from __future__ import annotations

#: Initial attempt + at most one retry.
MAX_ATTEMPTS = 2


class BoundedRetryViolationError(RuntimeError):
    """Raised when an LLM call exceeds the attempt bound (WI-I9)."""


def assert_bounded_retry(attempt_count: int) -> None:
    """Hard guard — raise if ``attempt_count`` exceeds the bound (max ``MAX_ATTEMPTS``).

    On exhaustion the synthesizer accepts the deterministic draft; it never retries beyond.
    """
    if attempt_count > MAX_ATTEMPTS:
        raise BoundedRetryViolationError(
            f"Retry attempt {attempt_count} exceeds the bound (max {MAX_ATTEMPTS}). "
            f"Accept the deterministic draft; never retry beyond {MAX_ATTEMPTS}."
        )
