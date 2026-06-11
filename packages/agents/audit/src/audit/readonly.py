"""Read-only invariant — code-level enforcement (audit v0.2 Task 13, WI-F8).

F.6 reads audit chains but **never** mutates them. v0.1 enforced this by design (the agent
simply has no write path); v0.2 makes it a hard, code-level guard — mirroring D.3
``assert_authorized``, D.4 ``assert_block_authorized``, and data-security
``assert_privacy_contract``. Any operation outside the allowed read-side set raises.

This is the institutional-integrity invariant: the auditor that other agents cannot disable
also cannot be turned into a chain-rewriter. There is deliberately no chain-mutation surface
anywhere in F.6 — this guard makes an accidental one fail loudly.
"""

from __future__ import annotations


class UnauthorizedAuditMutationError(RuntimeError):
    """Raised when an operation would mutate an audit chain — forbidden by design (WI-F8)."""


#: The only operations F.6 performs — all read-side. ``emit_finding`` writes a NEW OCSF
#: finding (e.g. a tamper alert); it never edits an existing audit chain entry.
READ_ONLY_OPERATIONS = frozenset({"read", "query", "verify", "aggregate", "filter", "emit_finding"})


def assert_audit_readonly(operation: str) -> None:
    """Hard guard — raise unless ``operation`` is one of the allowed read-side operations.

    F.6 is read-only by design + code level: audit chains MUST never be mutated; only
    audit-emit-finding (a new finding, not an edit) is allowed alongside read/query/verify/
    aggregate/filter.
    """
    if operation not in READ_ONLY_OPERATIONS:
        raise UnauthorizedAuditMutationError(
            f"Operation {operation!r} not authorized — F.6 is read-only by design. "
            f"Audit chains MUST never be mutated; allowed operations are "
            f"{sorted(READ_ONLY_OPERATIONS)}."
        )
