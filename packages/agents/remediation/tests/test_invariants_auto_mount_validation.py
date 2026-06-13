"""remediation v0.2 Task 16 — assert_auto_mount_validation tests (WI-A17, NEW)."""

from __future__ import annotations

import pytest
from remediation.invariants.auto_mount_validation import (
    SA_TOKEN_PATH,
    AutoMountValidationError,
    assert_auto_mount_validation,
    detect_active_token_consumer,
)
from remediation.schemas import RemediationActionType

_AUTO = RemediationActionType.K8S_PATCH_DISABLE_AUTO_MOUNT_SA_TOKEN
_OTHER = RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT


def test_non_auto_mount_action_ignored() -> None:
    assert_auto_mount_validation(
        action_type=_OTHER, service_account_name="custom-sa", containers=[]
    )


def test_default_sa_no_consumer_ok() -> None:
    assert_auto_mount_validation(
        action_type=_AUTO, service_account_name="default", containers=[{"name": "c"}]
    )


def test_no_sa_specified_no_consumer_ok() -> None:
    assert_auto_mount_validation(action_type=_AUTO, containers=[{"name": "c"}])


def test_non_default_sa_raises() -> None:
    with pytest.raises(AutoMountValidationError, match="non-default service account"):
        assert_auto_mount_validation(action_type=_AUTO, service_account_name="api-sa")


def test_active_consumer_volume_mount_raises() -> None:
    containers = [{"name": "c", "volumeMounts": [{"mountPath": SA_TOKEN_PATH}]}]
    with pytest.raises(AutoMountValidationError, match="actively consumes"):
        assert_auto_mount_validation(action_type=_AUTO, containers=containers)


def test_active_consumer_env_raises() -> None:
    containers = [{"name": "c", "env": [{"name": "TP", "value": f"{SA_TOKEN_PATH}/token"}]}]
    with pytest.raises(AutoMountValidationError):
        assert_auto_mount_validation(action_type=_AUTO, containers=containers)


def test_detect_helper() -> None:
    assert detect_active_token_consumer([{"volumeMounts": [{"mountPath": SA_TOKEN_PATH}]}])
    assert not detect_active_token_consumer([{"name": "c"}])
    assert not detect_active_token_consumer([{"volumeMounts": [{"mountPath": "/data"}]}])
