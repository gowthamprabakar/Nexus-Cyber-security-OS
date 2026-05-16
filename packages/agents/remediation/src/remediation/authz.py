"""A.1 Authorization — the security model for remediation mode + action allowlist.

A.1's authorization is **deliberately decoupled** from F.1's strict
`ExecutionContract`. Instead of extending the contract schema (which would
ripple across every agent), authorization lives in a separate YAML file
that operators ship alongside `contract.yaml`. The runbook documents the
shape; this module loads it and enforces it.

**The four gates v0.1 enforces** (Stage 2 of the 7-stage pipeline):

1. **Mode gate** — `enforce_mode` raises `AuthorizationError` if the
   requested `RemediationMode` isn't enabled in the authorization. Default
   authorization (no YAML supplied) is `recommend`-only; `dry_run` and
   `execute` must be opted in.

2. **Action-class allowlist** — `filter_authorized_findings` splits the
   input findings into (authorized, refused). A finding is authorized iff
   its `rule_id` maps to a known action class AND that action class's
   `action_type.value` appears in `authorized_actions`.

3. **Blast-radius cap** — `enforce_blast_radius` raises if the count of
   authorized findings exceeds `max_actions_per_run` (default 5; capped 50).

4. **Rollback window** — exposed as `auth.rollback_window_sec` (default
   300s; capped 1800s). The validator (Task 8) reads this to know how long
   to wait before re-running the detector.

**Sample `auth.yaml`** (operators commit this alongside their contract):

```yaml
mode_recommend_authorized: true
mode_dry_run_authorized: true
mode_execute_authorized: false           # opt in explicitly to allow apply
authorized_actions:
  - remediation_k8s_patch_runAsNonRoot
  - remediation_k8s_patch_resource_limits
max_actions_per_run: 3
rollback_window_sec: 600
```
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml
from k8s_posture.tools.manifests import ManifestFinding
from pydantic import BaseModel, Field

from remediation.action_classes import lookup_action_class
from remediation.schemas import RemediationActionType, RemediationMode


class AuthorizationError(RuntimeError):
    """The supplied authorization does not permit the requested operation."""


class Authorization(BaseModel):
    """A.1 authorization config — loaded from a YAML file or built explicitly."""

    mode_recommend_authorized: bool = True
    mode_dry_run_authorized: bool = False
    mode_execute_authorized: bool = False
    authorized_actions: list[str] = Field(default_factory=list)
    max_actions_per_run: int = Field(default=5, ge=1, le=50)
    rollback_window_sec: int = Field(default=300, ge=60, le=1800)

    @classmethod
    def recommend_only(cls) -> Authorization:
        """The safest default — `recommend` mode only, empty allowlist, blast cap 5."""
        return cls()

    @classmethod
    def from_path(cls, path: Path | str) -> Authorization:
        """Load an authorization config from a YAML file."""
        raw = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(raw) or {}
        return cls.model_validate(data)


# ---------------------------- gate functions ------------------------------


def enforce_mode(auth: Authorization, mode: RemediationMode) -> None:
    """Raise `AuthorizationError` when `mode` is not authorized.

    The CLI may default `mode` to `recommend`; this gate ensures even that
    is explicit (a contrived `Authorization(mode_recommend_authorized=False)`
    refuses every run).
    """
    flag_attr = f"mode_{mode.value}_authorized"
    if not getattr(auth, flag_attr):
        raise AuthorizationError(
            f"mode={mode.value!r} not authorized "
            f"(set {flag_attr}: true in authorization.yaml to opt in)"
        )


def filter_authorized_findings(
    auth: Authorization,
    findings: Iterable[ManifestFinding],
) -> tuple[list[ManifestFinding], list[tuple[ManifestFinding, str]]]:
    """Split findings into `(authorized, refused_with_reason)`.

    A finding is **authorized** iff both:
    - Its `rule_id` maps to a v0.1 action class (`lookup_action_class != None`).
    - That action class's `action_type.value` appears in `auth.authorized_actions`.

    Anything else is refused; the refusal reason is emitted into the audit
    chain (Task 9) with `RemediationOutcome.REFUSED_UNAUTHORIZED`.
    """
    authorized_set = set(auth.authorized_actions)
    authorized: list[ManifestFinding] = []
    refused: list[tuple[ManifestFinding, str]] = []
    for finding in findings:
        action = lookup_action_class(finding.rule_id)
        if action is None:
            refused.append(
                (
                    finding,
                    f"no v0.1 action class for rule_id={finding.rule_id!r}",
                )
            )
            continue
        if action.action_type.value not in authorized_set:
            refused.append(
                (
                    finding,
                    f"action_type={action.action_type.value!r} not in authorized_actions allowlist",
                )
            )
            continue
        authorized.append(finding)
    return authorized, refused


def enforce_blast_radius(auth: Authorization, authorized_count: int) -> None:
    """Raise `AuthorizationError` if `authorized_count > auth.max_actions_per_run`.

    Stage 2 calls this *after* `filter_authorized_findings` to refuse a run
    whose authorized actions would exceed the per-run blast-radius cap. The
    refused-with-blast-radius outcome is emitted into the audit chain rather
    than executing any subset (the agent doesn't partial-apply).
    """
    if authorized_count > auth.max_actions_per_run:
        raise AuthorizationError(
            f"would generate {authorized_count} actions, "
            f"exceeds max_actions_per_run={auth.max_actions_per_run}"
        )


def authorized_action_types(auth: Authorization) -> set[RemediationActionType]:
    """Return the set of `RemediationActionType`s the authorization permits.

    Unknown strings in `auth.authorized_actions` are silently dropped (an
    unknown action class can't be authorized in any meaningful sense).
    """
    result: set[RemediationActionType] = set()
    for s in auth.authorized_actions:
        try:
            result.add(RemediationActionType(s))
        except ValueError:
            continue
    return result


__all__ = [
    "Authorization",
    "AuthorizationError",
    "authorized_action_types",
    "enforce_blast_radius",
    "enforce_mode",
    "filter_authorized_findings",
]
