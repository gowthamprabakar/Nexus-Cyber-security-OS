"""NEW v0.2 invariant — auto-mount-disable validation (remediation Task 16, WI-A17).

Disabling ``automountServiceAccountToken`` **breaks** a workload that actively consumes the SA
token (it talks to the API server). So the auto-mount action is refused when the workload either
(a) runs under a non-``default`` service account, or (b) has a container actively using the mounted
token (a volumeMount or env var referencing the SA-token path). ``assert_auto_mount_validation``
is the hard guard; ``detect_active_token_consumer`` is the pure detector it uses.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from remediation.schemas import RemediationActionType

#: The in-container path at which K8s projects the service-account token (a path, not a secret).
SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"  # noqa: S105 — mount path, not a secret


class AutoMountValidationError(RuntimeError):
    """Raised when auto-mount disable is attempted on an active token consumer (WI-A17)."""


def detect_active_token_consumer(containers: Iterable[Mapping[str, Any]]) -> bool:
    """True iff any container mounts or references the SA-token path (an active consumer)."""
    for container in containers:
        for mount in container.get("volumeMounts") or []:
            if SA_TOKEN_PATH in str(mount.get("mountPath", "")):
                return True
        for env in container.get("env") or []:
            if SA_TOKEN_PATH in str(env.get("value", "")):
                return True
    return False


def assert_auto_mount_validation(
    *,
    action_type: RemediationActionType,
    service_account_name: str | None = None,
    containers: Iterable[Mapping[str, Any]] = (),
) -> None:
    """Hard guard — refuse auto-mount disable on an active token consumer (WI-A17).

    Non-auto-mount actions always pass. For the auto-mount action: a non-default service account
    OR a container actively using the mounted token raises.
    """
    if action_type != RemediationActionType.K8S_PATCH_DISABLE_AUTO_MOUNT_SA_TOKEN:
        return
    if service_account_name and service_account_name != "default":
        raise AutoMountValidationError(
            f"workload runs under non-default service account {service_account_name!r}; disabling "
            f"auto-mount would break its API access — refused (WI-A17)."
        )
    if detect_active_token_consumer(containers):
        raise AutoMountValidationError(
            "a container actively consumes the mounted service-account token; disabling auto-mount "
            "would break it — refused (WI-A17)."
        )
