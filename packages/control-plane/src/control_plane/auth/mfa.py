"""MFA enforcement gate.

Auth0's JWT carries an `amr` (Authentication Methods References) array
listing the factors the user satisfied during this login. We require
`"mfa"` to appear in that array for any *admin-scoped action* — every
RBAC `Action` except `READ_FINDINGS`. A read-only auditor without MFA
can still pull findings; everyone else needs MFA every login.

This is the smallest enforcement seam the FastAPI layer needs. The
charter audit chain (Task 10) emits an `mfa_required_failure` event
when this gate trips so the eval framework can grade the policy.
"""

from __future__ import annotations

from control_plane.auth.jwt_verifier import VerifiedToken
from control_plane.auth.rbac import Action


class MfaRequiredError(PermissionError):
    """The verified token is valid but lacks the MFA factor."""


def is_mfa_satisfied(token: VerifiedToken) -> bool:
    """Return True iff the token's `amr` claim includes `"mfa"`."""
    return "mfa" in token.amr


def require_mfa(token: VerifiedToken) -> None:
    """Raise `MfaRequiredError` if the token didn't satisfy MFA."""
    if not is_mfa_satisfied(token):
        raise MfaRequiredError("MFA required for this action")


def requires_mfa_for(action: Action) -> bool:
    """Return True when `action` is admin-scoped and demands MFA.

    Phase 1 policy: every action except `READ_FINDINGS` requires MFA.
    """
    return action is not Action.READ_FINDINGS


__all__ = [
    "MfaRequiredError",
    "is_mfa_satisfied",
    "require_mfa",
    "requires_mfa_for",
]
