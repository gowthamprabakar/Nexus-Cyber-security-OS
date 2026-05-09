"""correlation_id — ULID-based ID generator + asyncio-task-isolated contextvar.

Per ADR-004 every fabric message carries a `correlation_id` that flows from
scanner result → finding → agent reasoning → remediation → audit. The current
correlation_id is held in a `contextvars.ContextVar` so it is automatically
isolated per asyncio task.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from ulid import ULID

_CURRENT: ContextVar[str | None] = ContextVar("nexus_correlation_id", default=None)


def new_correlation_id() -> str:
    """Mint a fresh ULID. ULIDs are 26-char Crockford-base32 and k-sortable."""
    return str(ULID())


def current_correlation_id() -> str | None:
    """Return the correlation_id active for the current asyncio task / context."""
    return _CURRENT.get()


@contextmanager
def correlation_scope(correlation_id: str) -> Iterator[None]:
    """Bind `correlation_id` for the duration of the `with` block.

    Restores the previous value on exit (supports nesting).
    """
    token = _CURRENT.set(correlation_id)
    try:
        yield
    finally:
        _CURRENT.reset(token)
