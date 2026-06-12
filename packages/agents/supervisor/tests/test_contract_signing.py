"""supervisor v0.2 Task 16 — signed delegation contract tests (WI-O9)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from supervisor.contract_signing import (
    SignedDelegation,
    UnsignedContractError,
    assert_signed_contract,
    sign_contract,
    sign_delegation,
    verify_contract,
)
from supervisor.schemas import DelegationContract

_SECRET = b"supervisor-signing-key"


def _contract(*, target: str = "compliance", budget: float = 30.0) -> DelegationContract:
    return DelegationContract(
        delegation_id="d-1",
        customer_id="c-1",
        target_agent=target,
        task_id="t-1",
        budget_wall_clock_sec=budget,
        budget_max_tool_calls=100,
        created_at=datetime(2026, 6, 1, tzinfo=UTC),
    )


def test_sign_produces_hex() -> None:
    sig = sign_contract(_contract(), secret=_SECRET)
    assert len(sig) == 64 and all(c in "0123456789abcdef" for c in sig)


def test_sign_is_deterministic() -> None:
    assert sign_contract(_contract(), secret=_SECRET) == sign_contract(_contract(), secret=_SECRET)


def test_verify_valid_signature() -> None:
    c = _contract()
    assert verify_contract(c, sign_contract(c, secret=_SECRET), secret=_SECRET) is True


def test_verify_rejects_tampered_contract() -> None:
    c = _contract(budget=30.0)
    sig = sign_contract(c, secret=_SECRET)
    widened = _contract(budget=3600.0)  # someone widened the budget after signing
    assert verify_contract(widened, sig, secret=_SECRET) is False


def test_verify_rejects_wrong_secret() -> None:
    c = _contract()
    sig = sign_contract(c, secret=_SECRET)
    assert verify_contract(c, sig, secret=b"attacker-key") is False


def test_verify_rejects_empty_signature() -> None:
    assert verify_contract(_contract(), "", secret=_SECRET) is False


def test_assert_passes_for_signed() -> None:
    assert_signed_contract(sign_delegation(_contract(), secret=_SECRET), secret=_SECRET)


def test_assert_raises_for_empty_signature() -> None:
    unsigned = SignedDelegation(contract=_contract(), signature="")
    with pytest.raises(UnsignedContractError, match="Unsigned"):
        assert_signed_contract(unsigned, secret=_SECRET)


def test_assert_raises_for_tampered() -> None:
    signed = sign_delegation(_contract(budget=30.0), secret=_SECRET)
    forged = SignedDelegation(contract=_contract(budget=3600.0), signature=signed.signature)
    with pytest.raises(UnsignedContractError, match="Invalid signature"):
        assert_signed_contract(forged, secret=_SECRET)


def test_assert_raises_for_wrong_target() -> None:
    signed = sign_delegation(_contract(target="compliance"), secret=_SECRET)
    re_targeted = SignedDelegation(
        contract=_contract(target="remediation"), signature=signed.signature
    )
    with pytest.raises(UnsignedContractError):
        assert_signed_contract(re_targeted, secret=_SECRET)
