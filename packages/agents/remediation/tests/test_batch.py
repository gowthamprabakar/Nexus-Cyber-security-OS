"""remediation v0.2 Task 13 — batched-mode contract field + cap dispatcher (Q5)."""

from __future__ import annotations

from remediation.batch import (
    BATCH_MAX,
    CONTRACT_BATCH_FIELD,
    is_batched,
    resolve_batch_cap,
)
from remediation.invariants.blast_radius import HARD_CEILING


def test_batch_max_is_10() -> None:
    assert BATCH_MAX == 10


def test_default_is_single_finding() -> None:
    assert is_batched({}) is False
    assert resolve_batch_cap(5, batched=False) == 1


def test_opt_in_flag() -> None:
    assert is_batched({CONTRACT_BATCH_FIELD: True}) is True
    assert is_batched({CONTRACT_BATCH_FIELD: False}) is False


def test_batched_cap_lifts_default_to_per_run() -> None:
    # batched honours the per-run config up to BATCH_MAX.
    assert resolve_batch_cap(3, batched=True) == 3
    assert resolve_batch_cap(8, batched=True) == 8


def test_batched_cap_clamped_to_batch_max() -> None:
    # a per-run config above BATCH_MAX is clamped to 10.
    assert resolve_batch_cap(20, batched=True) == 10


def test_batched_never_exceeds_h5_ceiling() -> None:
    # even an absurd config can never exceed the H5 hard ceiling of 50 (BATCH_MAX keeps it at 10).
    assert resolve_batch_cap(10_000, batched=True) <= HARD_CEILING
    assert resolve_batch_cap(10_000, batched=True) == 10
