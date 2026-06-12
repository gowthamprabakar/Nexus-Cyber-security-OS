"""Producer-only invariant — code-level (curiosity v0.2 Task 16, WI-X14 — NEW).

The second of D.12's **three NEW** invariants. D.12 is the **first publisher** on the ``claims.>``
substrate (ADR-012) and is **producer-only**: it publishes ``claims.curiosity.>`` and **never
subscribes** to ``claims.>``. Subscribing would create a generative feedback loop — curiosity
generates claims, reads its own claims, generates more — so the fence is a hard code-level guard,
mirroring supervisor's ``_FORBIDDEN_SUBSCRIPTIONS`` pattern (Cycle 12, WI-O10).
``assert_no_claims_subscription`` raises if any requested subscription targets ``claims.``.
"""

from __future__ import annotations

from collections.abc import Iterable

#: The forbidden subject prefix — D.12 must never subscribe to the claims substrate.
FORBIDDEN_SUBJECT_PREFIX = "claims."


class ProducerOnlyViolationError(RuntimeError):
    """Raised when D.12 attempts to subscribe to the claims.> substrate (WI-X14)."""


def assert_no_claims_subscription(subscriptions: Iterable[str]) -> None:
    """Hard guard — raise if any subscription subject targets ``claims.`` (WI-X14).

    D.12 is producer-only: it publishes claims.curiosity.> and never reads claims.> (a self-read
    would create a generative feedback loop). Called at NATS subscription setup.
    """
    forbidden = sorted(s for s in subscriptions if s.startswith(FORBIDDEN_SUBJECT_PREFIX))
    if forbidden:
        raise ProducerOnlyViolationError(
            f"D.12 attempted to subscribe to the claims substrate: {forbidden}. D.12 is "
            f"producer-only — it publishes claims.curiosity.>, never reads claims.> (WI-X14)."
        )
