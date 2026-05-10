"""AWS IAM async listing wrapper. Returns users + roles + groups + attachments.

Per ADR-005, boto3 (sync) goes through `asyncio.to_thread` so the agent
driver's TaskGroup can fan out concurrently. The single entry point
`aws_iam_list_identities` returns a frozen `IdentityListing` capturing
the principal universe for one AWS account / region.

The downstream resolver (D.2 Task 6) consumes this output to flatten
managed + inline policies into effective grants.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import boto3

# IAM SimulatePrincipalPolicy accepts at most 50 ActionNames per request.
_SIMULATE_BATCH_SIZE = 50


class IamListingError(RuntimeError):
    """boto3 raised, or the caller's session/profile is invalid."""


@dataclass(frozen=True, slots=True)
class IamUser:
    arn: str
    name: str
    user_id: str  # AIDAxxx
    create_date: datetime
    last_used_at: datetime | None
    attached_policy_arns: tuple[str, ...] = field(default_factory=tuple)
    inline_policy_names: tuple[str, ...] = field(default_factory=tuple)
    group_memberships: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class IamRole:
    arn: str
    name: str
    role_id: str  # AROAxxx
    create_date: datetime
    last_used_at: datetime | None
    assume_role_policy_document: dict[str, Any]
    attached_policy_arns: tuple[str, ...] = field(default_factory=tuple)
    inline_policy_names: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class IamGroup:
    arn: str
    name: str
    group_id: str  # AGPAxxx
    create_date: datetime
    member_user_names: tuple[str, ...] = field(default_factory=tuple)
    attached_policy_arns: tuple[str, ...] = field(default_factory=tuple)
    inline_policy_names: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class IdentityListing:
    users: tuple[IamUser, ...]
    roles: tuple[IamRole, ...]
    groups: tuple[IamGroup, ...]


async def aws_iam_list_identities(
    *,
    profile: str | None = None,
    region: str = "us-east-1",
    timeout_sec: float = 60.0,
) -> IdentityListing:
    """Return all IAM users + roles + groups + their policy attachments.

    Args:
        profile: AWS named profile (defaults to environment auth).
        region: For client construction; IAM is global but boto3 needs one.
        timeout_sec: Wall-clock timeout — raises if pagination takes longer.

    Raises:
        IamListingError: on any underlying boto3 / botocore error or timeout.
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_list_identities_sync, profile, region),
            timeout=timeout_sec,
        )
    except TimeoutError as exc:
        raise IamListingError(f"aws_iam_list_identities timed out after {timeout_sec}s") from exc
    except IamListingError:
        raise
    except Exception as exc:  # boto3 / botocore wrap
        raise IamListingError(f"aws_iam_list_identities failed: {exc}") from exc


def _list_identities_sync(profile: str | None, region: str) -> IdentityListing:
    session = (
        boto3.Session(profile_name=profile, region_name=region)
        if profile
        else boto3.Session(region_name=region)
    )
    iam = session.client("iam")

    users = _list_users(iam)
    roles = _list_roles(iam)
    groups = _list_groups(iam)

    return IdentityListing(users=tuple(users), roles=tuple(roles), groups=tuple(groups))


def _list_users(iam: Any) -> list[IamUser]:
    users: list[IamUser] = []
    for page in iam.get_paginator("list_users").paginate():
        for u in page.get("Users", []):
            name = str(u["UserName"])
            attached = _list_attached_policy_arns(
                iam, "list_attached_user_policies", "UserName", name
            )
            inline = _list_inline_policy_names(iam, "list_user_policies", "UserName", name)
            groups = _list_user_groups(iam, name)
            users.append(
                IamUser(
                    arn=str(u["Arn"]),
                    name=name,
                    user_id=str(u["UserId"]),
                    create_date=u["CreateDate"],
                    last_used_at=(
                        u.get("PasswordLastUsed")
                        if isinstance(u.get("PasswordLastUsed"), datetime)
                        else None
                    ),
                    attached_policy_arns=tuple(attached),
                    inline_policy_names=tuple(inline),
                    group_memberships=tuple(groups),
                )
            )
    return users


def _list_roles(iam: Any) -> list[IamRole]:
    roles: list[IamRole] = []
    for page in iam.get_paginator("list_roles").paginate():
        for r in page.get("Roles", []):
            name = str(r["RoleName"])
            attached = _list_attached_policy_arns(
                iam, "list_attached_role_policies", "RoleName", name
            )
            inline = _list_inline_policy_names(iam, "list_role_policies", "RoleName", name)
            last_used = r.get("RoleLastUsed", {}).get("LastUsedDate")
            roles.append(
                IamRole(
                    arn=str(r["Arn"]),
                    name=name,
                    role_id=str(r["RoleId"]),
                    create_date=r["CreateDate"],
                    last_used_at=last_used if isinstance(last_used, datetime) else None,
                    assume_role_policy_document=dict(r.get("AssumeRolePolicyDocument") or {}),
                    attached_policy_arns=tuple(attached),
                    inline_policy_names=tuple(inline),
                )
            )
    return roles


def _list_groups(iam: Any) -> list[IamGroup]:
    groups: list[IamGroup] = []
    for page in iam.get_paginator("list_groups").paginate():
        for g in page.get("Groups", []):
            name = str(g["GroupName"])
            members = [
                str(u["UserName"])
                for sub in iam.get_paginator("get_group").paginate(GroupName=name)
                for u in sub.get("Users", [])
            ]
            attached = _list_attached_policy_arns(
                iam, "list_attached_group_policies", "GroupName", name
            )
            inline = _list_inline_policy_names(iam, "list_group_policies", "GroupName", name)
            groups.append(
                IamGroup(
                    arn=str(g["Arn"]),
                    name=name,
                    group_id=str(g["GroupId"]),
                    create_date=g["CreateDate"],
                    member_user_names=tuple(members),
                    attached_policy_arns=tuple(attached),
                    inline_policy_names=tuple(inline),
                )
            )
    return groups


def _list_attached_policy_arns(
    iam: Any, paginator_name: str, principal_kw: str, principal_name: str
) -> list[str]:
    arns: list[str] = []
    for page in iam.get_paginator(paginator_name).paginate(**{principal_kw: principal_name}):
        for p in page.get("AttachedPolicies", []):
            arns.append(str(p["PolicyArn"]))
    return arns


def _list_inline_policy_names(
    iam: Any, paginator_name: str, principal_kw: str, principal_name: str
) -> list[str]:
    names: list[str] = []
    for page in iam.get_paginator(paginator_name).paginate(**{principal_kw: principal_name}):
        for n in page.get("PolicyNames", []):
            names.append(str(n))
    return names


def _list_user_groups(iam: Any, user_name: str) -> list[str]:
    groups: list[str] = []
    for page in iam.get_paginator("list_groups_for_user").paginate(UserName=user_name):
        for g in page.get("Groups", []):
            groups.append(str(g["GroupName"]))
    return groups


# ===================== aws_iam_simulate_principal_policy ==================


@dataclass(frozen=True, slots=True)
class SimulationDecision:
    """One (principal, action, resource) decision row.

    `decision` is the IAM `EvalDecision` string: ``allowed`` /
    ``explicitDeny`` / ``implicitDeny``. `matched_statement_ids`
    contains the `SourcePolicyId` of every statement that matched
    (empty for implicit-deny).
    """

    principal_arn: str
    action: str
    resource: str
    decision: str
    matched_statement_ids: tuple[str, ...] = field(default_factory=tuple)


async def aws_iam_simulate_principal_policy(
    *,
    principal_arn: str,
    actions: Sequence[str],
    resources: Sequence[str] = ("*",),
    profile: str | None = None,
    region: str = "us-east-1",
    timeout_sec: float = 60.0,
) -> tuple[SimulationDecision, ...]:
    """Run IAM SimulatePrincipalPolicy against a principal and return decisions.

    Actions are batched into chunks of 50 (the IAM API limit). Each
    (action, resource) pair becomes one `SimulationDecision`.

    Args:
        principal_arn: IAM principal (User or Role ARN) to simulate against.
        actions: IAM actions to evaluate (e.g. ``"s3:GetObject"``). May be
            longer than 50; the wrapper batches.
        resources: Resource ARNs to evaluate against. Defaults to ``("*",)``.
        profile: AWS named profile (defaults to environment auth).
        region: For client construction; IAM is global but boto3 needs one.
        timeout_sec: Wall-clock timeout — raises if simulation runs long.

    Raises:
        IamListingError: on any underlying boto3/botocore error or timeout.
    """
    if not actions:
        return ()
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                _simulate_principal_policy_sync,
                principal_arn,
                tuple(actions),
                tuple(resources) or ("*",),
                profile,
                region,
            ),
            timeout=timeout_sec,
        )
    except TimeoutError as exc:
        raise IamListingError(
            f"aws_iam_simulate_principal_policy timed out after {timeout_sec}s"
        ) from exc
    except IamListingError:
        raise
    except Exception as exc:
        raise IamListingError(f"aws_iam_simulate_principal_policy failed: {exc}") from exc


def _simulate_principal_policy_sync(
    principal_arn: str,
    actions: tuple[str, ...],
    resources: tuple[str, ...],
    profile: str | None,
    region: str,
) -> tuple[SimulationDecision, ...]:
    session = (
        boto3.Session(profile_name=profile, region_name=region)
        if profile
        else boto3.Session(region_name=region)
    )
    iam = session.client("iam")

    decisions: list[SimulationDecision] = []
    for batch_start in range(0, len(actions), _SIMULATE_BATCH_SIZE):
        batch = list(actions[batch_start : batch_start + _SIMULATE_BATCH_SIZE])
        response = iam.simulate_principal_policy(
            PolicySourceArn=principal_arn,
            ActionNames=batch,
            ResourceArns=list(resources),
        )
        for row in response.get("EvaluationResults", []):
            statements = tuple(
                str(s.get("SourcePolicyId", ""))
                for s in row.get("MatchedStatements") or ()
                if s.get("SourcePolicyId")
            )
            decisions.append(
                SimulationDecision(
                    principal_arn=principal_arn,
                    action=str(row["EvalActionName"]),
                    resource=str(row["EvalResourceName"]),
                    decision=str(row["EvalDecision"]),
                    matched_statement_ids=statements,
                )
            )
    return tuple(decisions)
