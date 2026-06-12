"""H1 — default-to-recommend invariant (remediation v0.2 Task 2, WI-A8).

Per **H1** a run is ``recommend`` (artifact-only, zero mutation) unless the operator opts into a
higher tier. The **execute** tier — the only one that mutates customer infrastructure — requires
**BOTH** opt-in layers (defense in depth, WI-A15): the ``--enable-execute`` CLI kill-switch AND
``mode_execute_authorized: true`` in ``auth.yaml``. A single source of opt-in is insufficient.
``assert_default_recommend`` is the hard guard called at the AUTHZ stage entry.
"""

from __future__ import annotations

from remediation.schemas import RemediationMode


class DefaultRecommendViolationError(RuntimeError):
    """Raised when a higher-tier run lacks its required opt-in layer(s) (WI-A8/H1)."""


def assert_default_recommend(
    mode: RemediationMode,
    *,
    enable_execute_flag: bool,
    auth_mode_authorized: bool,
) -> None:
    """Hard guard — execute requires BOTH the CLI kill-switch AND the auth.yaml field (H1/WI-A8).

    ``recommend`` (the default, non-mutating) always passes. ``execute`` requires both layers;
    the dry-run tier is gated separately by ``authz.enforce_mode`` (it is non-mutating).
    """
    if mode == RemediationMode.EXECUTE:
        if not enable_execute_flag:
            raise DefaultRecommendViolationError(
                "execute mode requires the --enable-execute CLI flag (the kill-switch); "
                "default to recommend (H1/WI-A8)."
            )
        if not auth_mode_authorized:
            raise DefaultRecommendViolationError(
                "execute mode requires mode_execute_authorized: true in auth.yaml; "
                "a single source of opt-in is insufficient (H1/WI-A15)."
            )
