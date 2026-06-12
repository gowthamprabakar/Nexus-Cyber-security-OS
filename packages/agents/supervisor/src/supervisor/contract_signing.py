"""Signed delegation contracts — code-level invariant (supervisor v0.2 Task 16, WI-O9).

Every delegation the supervisor dispatches MUST be **signed**: the supervisor constructs the
bounded ``DelegationContract`` (the deviation: it constructs, never receives) and signs its
canonical fields with an HMAC-SHA256 so a specialist — and the F.6 audit trail — can verify the
contract was not tampered with in flight. ``assert_signed_contract`` is the hard guard
(mirroring D.3/D.4/data-security/F.6 + the Task-15 hierarchy guard): a missing or invalid
signature raises.

HMAC over a canonical field set is deterministic + tamper-evident; editing any signed field
(e.g. widening the budget or re-targeting the agent) invalidates the signature.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from supervisor.schemas import DelegationContract


class UnsignedContractError(RuntimeError):
    """Raised when a delegation contract is unsigned or its signature is invalid (WI-O9)."""


def _canonical(contract: DelegationContract) -> bytes:
    """A deterministic byte serialization of the signed fields (sorted, stable)."""
    signed_fields = {
        "delegation_id": contract.delegation_id,
        "customer_id": contract.customer_id,
        "target_agent": contract.target_agent,
        "task_id": contract.task_id,
        "budget_wall_clock_sec": contract.budget_wall_clock_sec,
        "budget_max_tool_calls": contract.budget_max_tool_calls,
        "permitted_tools": sorted(contract.permitted_tools),
    }
    return json.dumps(signed_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_contract(contract: DelegationContract, *, secret: bytes) -> str:
    """HMAC-SHA256 signature over the contract's canonical fields."""
    return hmac.new(secret, _canonical(contract), hashlib.sha256).hexdigest()


def verify_contract(contract: DelegationContract, signature: str, *, secret: bytes) -> bool:
    """True iff ``signature`` matches the contract under ``secret`` (constant-time compare)."""
    if not signature:
        return False
    expected = sign_contract(contract, secret=secret)
    return hmac.compare_digest(expected, signature)


@dataclass(frozen=True, slots=True)
class SignedDelegation:
    contract: DelegationContract
    signature: str

    def verify(self, *, secret: bytes) -> bool:
        return verify_contract(self.contract, self.signature, secret=secret)


def sign_delegation(contract: DelegationContract, *, secret: bytes) -> SignedDelegation:
    return SignedDelegation(contract=contract, signature=sign_contract(contract, secret=secret))


def assert_signed_contract(signed: SignedDelegation, *, secret: bytes) -> None:
    """Hard guard — raise unless the delegation carries a present + valid signature."""
    if not signed.signature:
        raise UnsignedContractError(
            f"Unsigned ExecutionContract for target {signed.contract.target_agent!r}. "
            f"All delegations must be signed (Charter integrity invariant, WI-O9)."
        )
    if not signed.verify(secret=secret):
        raise UnsignedContractError(
            f"Invalid signature on the ExecutionContract for target "
            f"{signed.contract.target_agent!r} — the contract was tampered with or signed "
            f"under a different key (WI-O9)."
        )
