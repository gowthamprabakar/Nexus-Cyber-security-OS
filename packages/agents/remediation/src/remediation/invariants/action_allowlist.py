"""H2 — action-allowlist invariant (remediation v0.2 Task 3, WI-A9).

Per **H2** no action class executes unless it is explicitly allowlisted in ``auth.yaml``
(``authorized_actions``). A refused action is rejected at the AUTHZ stage **with a mandatory audit
entry** (defense in depth — every refusal is recorded, not silently dropped).
``assert_action_allowlisted`` is the hard guard: on a non-allowlisted action it invokes the
``on_refusal`` audit hook (if given) and then raises.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from remediation.schemas import RemediationActionType


class ActionNotAllowlistedError(RuntimeError):
    """Raised when an action class is not in the auth.yaml allowlist (WI-A9/H2)."""


def assert_action_allowlisted(
    action_type: RemediationActionType,
    authorized_actions: Iterable[str],
    *,
    on_refusal: Callable[[RemediationActionType], None] | None = None,
) -> None:
    """Hard guard — raise if ``action_type`` is not allowlisted (H2/WI-A9).

    ``authorized_actions`` is the ``auth.yaml`` allowlist of ``RemediationActionType`` *values*.
    On refusal the ``on_refusal`` audit hook fires FIRST (mandatory audit entry), then this raises.
    """
    if action_type.value not in set(authorized_actions):
        if on_refusal is not None:
            on_refusal(action_type)
        raise ActionNotAllowlistedError(
            f"action {action_type.value!r} is not in the auth.yaml authorized_actions allowlist; "
            f"refused at AUTHZ with an audit entry (H2/WI-A9)."
        )
