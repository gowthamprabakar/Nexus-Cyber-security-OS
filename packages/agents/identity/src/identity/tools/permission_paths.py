"""Permission-path resolver — flatten simulator decisions into effective grants.

Pure-Python transformation: `(IdentityListing, SimulationDecision[]) → EffectiveGrant[]`.
No boto3 calls, no LLM. Resolves D.2 plan **Q3** (resolver scope cap):

- Users + roles + groups (covered).
- Managed + inline + group-inherited policies (covered — the simulator
  already considers them; we surface its decisions).
- Permission boundaries (covered — boundary-blocked grants come back
  from the simulator as `implicitDeny` and are dropped).
- SCPs (deferred — Phase 1 caps at single-account).
- IAM `Condition` evaluation (deferred — Phase 1 ignores conditions).

The Task 7 normalizer consumes the output of this module to produce
overprivilege / dormant / external-access findings.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from identity.tools.aws_iam import IdentityListing, SimulationDecision


@dataclass(frozen=True, slots=True)
class EffectiveGrant:
    """One (principal, action, resource) outcome from the simulator.

    `effect` is `"Allow"` for `allowed` decisions and `"Deny"` for
    `explicitDeny`. `implicitDeny` decisions are dropped — they don't
    represent active grants.
    """

    principal_arn: str
    action: str
    resource_pattern: str
    effect: Literal["Allow", "Deny"]
    source_policy_arns: tuple[str, ...]
    is_admin: bool


def resolve_effective_grants(
    listing: IdentityListing,
    simulator_results: Sequence[SimulationDecision],
) -> tuple[EffectiveGrant, ...]:
    """Flatten simulator decisions for principals in `listing` into grants.

    Decisions referencing principals not present in `listing` are dropped
    so the resolver's output stays consistent with the inventory. This
    matters because downstream (Task 7) joins on principal_arn.
    """
    known_arns = _known_principal_arns(listing)
    grants: list[EffectiveGrant] = []
    for decision in simulator_results:
        if decision.principal_arn not in known_arns:
            continue
        effect = _decision_to_effect(decision.decision)
        if effect is None:
            continue
        grants.append(
            EffectiveGrant(
                principal_arn=decision.principal_arn,
                action=decision.action,
                resource_pattern=decision.resource,
                effect=effect,
                source_policy_arns=decision.matched_statement_ids,
                is_admin=is_admin_action(decision.action),
            )
        )
    return tuple(grants)


def is_admin_action(action: str) -> bool:
    """Return True when the action grants admin-equivalent reach.

    Admin-equivalent means: a single statement that authorises every
    operation in some scope. We flag global wildcards (``*`` / ``*:*``)
    and service-wide wildcards (e.g. ``iam:*``, ``s3:*``). Service IAM
    is special-cased because *anything-iam* is privilege escalation.
    """
    if not action:
        return False
    if action in {"*", "*:*"}:
        return True
    if ":" in action:
        _, op = action.split(":", 1)
        return op == "*"
    return False


def grants_by_principal(
    grants: Sequence[EffectiveGrant],
) -> dict[str, tuple[EffectiveGrant, ...]]:
    """Group grants by principal ARN, preserving input order."""
    bucket: dict[str, list[EffectiveGrant]] = {}
    for g in grants:
        bucket.setdefault(g.principal_arn, []).append(g)
    return {arn: tuple(gs) for arn, gs in bucket.items()}


def find_admin_principals(grants: Sequence[EffectiveGrant]) -> tuple[str, ...]:
    """Return ARNs of principals with at least one Allow + admin grant.

    Order is stable (first appearance in `grants`) so callers can render
    the result deterministically.
    """
    seen: dict[str, None] = {}
    for g in grants:
        if g.effect == "Allow" and g.is_admin and g.principal_arn not in seen:
            seen[g.principal_arn] = None
    return tuple(seen)


def _known_principal_arns(listing: IdentityListing) -> frozenset[str]:
    return frozenset(
        [u.arn for u in listing.users]
        + [r.arn for r in listing.roles]
        + [g.arn for g in listing.groups]
    )


def _decision_to_effect(decision: str) -> Literal["Allow", "Deny"] | None:
    if decision == "allowed":
        return "Allow"
    if decision == "explicitDeny":
        return "Deny"
    return None


__all__ = [
    "EffectiveGrant",
    "find_admin_principals",
    "grants_by_principal",
    "is_admin_action",
    "resolve_effective_grants",
]
