"""Tests for `control_plane.auth.mfa`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from control_plane.auth.jwt_verifier import VerifiedToken
from control_plane.auth.mfa import (
    MfaRequiredError,
    is_mfa_satisfied,
    require_mfa,
    requires_mfa_for,
)
from control_plane.auth.rbac import Action


def _token(amr: tuple[str, ...]) -> VerifiedToken:
    return VerifiedToken(
        sub="auth0|abc",
        tenant_id="01HXYZTENANT0000000000000A",
        roles=("admin",),
        expires_at=datetime.now(UTC),
        amr=amr,
    )


# ---------------------------- predicate ---------------------------------


def test_amr_contains_mfa_is_satisfied() -> None:
    assert is_mfa_satisfied(_token(("pwd", "mfa"))) is True


def test_amr_without_mfa_is_unsatisfied() -> None:
    assert is_mfa_satisfied(_token(("pwd",))) is False


def test_empty_amr_is_unsatisfied() -> None:
    assert is_mfa_satisfied(_token(())) is False


# ---------------------------- require_mfa --------------------------------


def test_require_mfa_passes_when_satisfied() -> None:
    require_mfa(_token(("pwd", "mfa")))  # no raise


def test_require_mfa_raises_when_missing() -> None:
    with pytest.raises(MfaRequiredError):
        require_mfa(_token(("pwd",)))


def test_require_mfa_raises_when_amr_empty() -> None:
    with pytest.raises(MfaRequiredError):
        require_mfa(_token(()))


# ---------------------------- requires_mfa_for ---------------------------


def test_read_findings_does_not_require_mfa() -> None:
    assert requires_mfa_for(Action.READ_FINDINGS) is False


@pytest.mark.parametrize(
    "action",
    [a for a in Action if a is not Action.READ_FINDINGS],
)
def test_every_other_action_requires_mfa(action: Action) -> None:
    assert requires_mfa_for(action) is True
