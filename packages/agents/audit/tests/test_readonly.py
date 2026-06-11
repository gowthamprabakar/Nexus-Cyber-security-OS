"""audit v0.2 Task 13 — read-only invariant tests (WI-F8)."""

from __future__ import annotations

import pytest
from audit.readonly import (
    READ_ONLY_OPERATIONS,
    UnauthorizedAuditMutationError,
    assert_audit_readonly,
)


@pytest.mark.parametrize("op", ["read", "query", "verify", "aggregate", "filter", "emit_finding"])
def test_allowed_operations_pass(op: str) -> None:
    assert_audit_readonly(op)  # does not raise


@pytest.mark.parametrize(
    "op",
    ["write", "delete", "update", "insert", "repair", "modify", "rewrite", "append", "truncate"],
)
def test_mutation_operations_rejected(op: str) -> None:
    with pytest.raises(UnauthorizedAuditMutationError):
        assert_audit_readonly(op)


def test_unknown_operation_rejected() -> None:
    with pytest.raises(UnauthorizedAuditMutationError):
        assert_audit_readonly("frobnicate")


def test_error_message_explains_readonly() -> None:
    with pytest.raises(UnauthorizedAuditMutationError, match="read-only by design"):
        assert_audit_readonly("delete")


def test_allowed_set_is_exactly_six() -> None:
    assert (
        frozenset({"read", "query", "verify", "aggregate", "filter", "emit_finding"})
        == READ_ONLY_OPERATIONS
    )


def test_case_sensitive() -> None:
    # "READ" is not "read" — be strict (no accidental bypass via casing).
    with pytest.raises(UnauthorizedAuditMutationError):
        assert_audit_readonly("READ")


def test_empty_operation_rejected() -> None:
    with pytest.raises(UnauthorizedAuditMutationError):
        assert_audit_readonly("")
