"""Batched multi-finding remediation — contract field + cap dispatcher (remediation v0.2 Task 13, Q5).

Default behaviour is **single-finding-per-run** (preserved). An operator opts into batched mode via
the contract field ``batched_remediation: true``; a batch then applies up to ``min(max_actions_per_
run, 10)`` actions — this lifts the single-run default of 5 but is itself bounded by the H5 hard
ceiling of 50 (``invariants.blast_radius.HARD_CEILING``). The batch-level safety primitives
(dry-run-first + atomic abort) land in Task 14. This module is the pure cap/flag resolver.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from remediation.invariants.blast_radius import HARD_CEILING

#: The contract field that opts a run into batched mode.
CONTRACT_BATCH_FIELD = "batched_remediation"

#: The batched per-run ceiling (lifts the single-run default of 5; well under the H5 cap of 50).
BATCH_MAX = 10


def is_batched(config: Mapping[str, Any]) -> bool:
    """True iff the contract opts into batched remediation (default False)."""
    return bool(config.get(CONTRACT_BATCH_FIELD, False))


def resolve_batch_cap(max_actions_per_run: int, *, batched: bool) -> int:
    """The number of actions a run may apply.

    Single-finding mode (default) -> 1. Batched mode -> ``min(max_actions_per_run, BATCH_MAX)``,
    itself clamped to the H5 hard ceiling of 50 (Q5).
    """
    if not batched:
        return 1
    return min(max_actions_per_run, BATCH_MAX, HARD_CEILING)
