"""remediation v0.2 Task 3 — assert_action_allowlisted tests (WI-A9/H2)."""

from __future__ import annotations

import pytest
from remediation.invariants.action_allowlist import (
    ActionNotAllowlistedError,
    assert_action_allowlisted,
)
from remediation.schemas import RemediationActionType

_RUN_AS_NON_ROOT = RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT
_RESOURCE_LIMITS = RemediationActionType.K8S_PATCH_RESOURCE_LIMITS


def test_allowlisted_ok() -> None:
    assert_action_allowlisted(_RUN_AS_NON_ROOT, [_RUN_AS_NON_ROOT.value])


def test_non_allowlisted_raises() -> None:
    with pytest.raises(ActionNotAllowlistedError, match="authorized_actions allowlist"):
        assert_action_allowlisted(_RESOURCE_LIMITS, [_RUN_AS_NON_ROOT.value])


def test_empty_allowlist_raises() -> None:
    with pytest.raises(ActionNotAllowlistedError):
        assert_action_allowlisted(_RUN_AS_NON_ROOT, [])


def test_refusal_emits_audit_entry_first() -> None:
    refused: list[RemediationActionType] = []
    with pytest.raises(ActionNotAllowlistedError):
        assert_action_allowlisted(_RESOURCE_LIMITS, [], on_refusal=refused.append)
    assert refused == [_RESOURCE_LIMITS]


def test_allowlisted_does_not_emit_refusal() -> None:
    refused: list[RemediationActionType] = []
    assert_action_allowlisted(_RUN_AS_NON_ROOT, [_RUN_AS_NON_ROOT.value], on_refusal=refused.append)
    assert refused == []
