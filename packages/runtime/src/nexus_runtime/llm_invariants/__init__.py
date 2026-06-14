"""Shared LLM-agent code-level invariants (Phase D P3-2 hoist).

Canonical single-source implementations of the two invariants the LLM agents (D.13 synthesis,
D.7 investigation, D.12 curiosity) previously triplicated. Pure (regex + stdlib); no charter/shared
dependency, so any agent can import them.
"""

from nexus_runtime.llm_invariants.bounded import (
    MAX_ATTEMPTS,
    BoundedRetryViolationError,
    assert_bounded_retry,
)
from nexus_runtime.llm_invariants.categorical import (
    CategoricalContractViolationError,
    assert_categorical_only,
)

__all__ = [
    "MAX_ATTEMPTS",
    "BoundedRetryViolationError",
    "CategoricalContractViolationError",
    "assert_bounded_retry",
    "assert_categorical_only",
]
