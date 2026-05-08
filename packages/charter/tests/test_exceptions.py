"""Tests for charter exceptions."""

from charter.exceptions import (
    BudgetExhausted,
    CharterViolation,
    ContractInvalid,
    ToolNotPermitted,
)


def test_charter_violation_is_base() -> None:
    assert issubclass(BudgetExhausted, CharterViolation)
    assert issubclass(ToolNotPermitted, CharterViolation)
    assert issubclass(ContractInvalid, CharterViolation)


def test_budget_exhausted_carries_dimension() -> None:
    err = BudgetExhausted(dimension="tokens", limit=1000, used=1500)
    assert err.dimension == "tokens"
    assert err.limit == 1000
    assert err.used == 1500
    assert "tokens" in str(err)


def test_tool_not_permitted_carries_tool_name() -> None:
    err = ToolNotPermitted(tool="aws_iam_delete_user", permitted=["aws_s3_describe"])
    assert err.tool == "aws_iam_delete_user"
    assert "aws_iam_delete_user" in str(err)


def test_contract_invalid_carries_field_path() -> None:
    err = ContractInvalid(field="budget.tokens", reason="must be positive")
    assert err.field == "budget.tokens"
    assert err.reason == "must be positive"
