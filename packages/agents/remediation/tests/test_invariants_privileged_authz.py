"""remediation v0.2 Task 15 — assert_privileged_action_extra_authz tests (WI-A16, NEW)."""

from __future__ import annotations

import pytest
from remediation.invariants.privileged_authz import (
    PRIVILEGED_AUTHZ_FIELD,
    PrivilegedActionAuthzError,
    assert_privileged_action_extra_authz,
)
from remediation.schemas import RemediationActionType

_PRIV = RemediationActionType.K8S_PATCH_DISABLE_PRIVILEGED_CONTAINER
_NON_PRIV = RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT


def test_privileged_with_extra_authz_ok() -> None:
    assert_privileged_action_extra_authz(_PRIV, {PRIVILEGED_AUTHZ_FIELD: True})


def test_privileged_without_extra_authz_raises() -> None:
    with pytest.raises(PrivilegedActionAuthzError, match="privileged action"):
        assert_privileged_action_extra_authz(_PRIV, {})


def test_privileged_with_field_false_raises() -> None:
    with pytest.raises(PrivilegedActionAuthzError):
        assert_privileged_action_extra_authz(_PRIV, {PRIVILEGED_AUTHZ_FIELD: False})


def test_non_privileged_always_ok() -> None:
    # non-privileged actions are gated by the H2 allowlist, not this extra field.
    assert_privileged_action_extra_authz(_NON_PRIV, {})
    assert_privileged_action_extra_authz(_NON_PRIV, {PRIVILEGED_AUTHZ_FIELD: False})
