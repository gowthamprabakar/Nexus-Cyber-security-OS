"""NEW v0.2 invariant — privileged-action extra authorization (remediation Task 15, WI-A16).

The privileged-container disable can break a workload that legitimately needs host capabilities, so
beyond the standard ``authorized_actions`` allowlist (H2) it requires a **separate** explicit
acknowledgement: ``privileged_actions_authorized: true`` in ``auth.yaml``.
``assert_privileged_action_extra_authz`` is the hard guard: a privileged action without that extra
field raises, even if the action is in the standard allowlist.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from remediation.schemas import RemediationActionType

#: Actions whose blast radius warrants extra, separate authorization beyond the H2 allowlist.
PRIVILEGED_ACTIONS: frozenset[RemediationActionType] = frozenset(
    {RemediationActionType.K8S_PATCH_DISABLE_PRIVILEGED_CONTAINER}
)

#: The auth.yaml field that grants the extra privileged-action authorization.
PRIVILEGED_AUTHZ_FIELD = "privileged_actions_authorized"


class PrivilegedActionAuthzError(RuntimeError):
    """Raised when a privileged action lacks its extra auth.yaml authorization (WI-A16)."""


def assert_privileged_action_extra_authz(
    action_type: RemediationActionType,
    auth_yaml: Mapping[str, Any],
) -> None:
    """Hard guard — a privileged action requires ``privileged_actions_authorized: true`` (WI-A16).

    Non-privileged actions always pass here (they are gated by the standard H2 allowlist).
    """
    if action_type in PRIVILEGED_ACTIONS and not auth_yaml.get(PRIVILEGED_AUTHZ_FIELD, False):
        raise PrivilegedActionAuthzError(
            f"{action_type.value!r} is a privileged action requiring "
            f"{PRIVILEGED_AUTHZ_FIELD}: true in auth.yaml (extra authz beyond the allowlist, "
            f"WI-A16) — it can break a workload that needs host capabilities."
        )
