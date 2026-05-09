"""AWS IAM analyzer (async). Read-only checks for common identity issues."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import boto3


async def list_users_without_mfa() -> list[str]:
    """Return usernames that have a console password but no MFA device."""
    return await asyncio.to_thread(_list_users_without_mfa_sync)


def _list_users_without_mfa_sync() -> list[str]:
    iam = boto3.client("iam")
    out: list[str] = []
    for user in iam.list_users().get("Users", []):
        username = user["UserName"]
        try:
            iam.get_login_profile(UserName=username)
        except iam.exceptions.NoSuchEntityException:
            continue  # no console password — skip
        devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        if not devices:
            out.append(username)
    return out


def _statement_is_star_star(stmt: dict[str, Any]) -> bool:
    if stmt.get("Effect") != "Allow":
        return False
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    resources = stmt.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    return "*" in actions and "*" in resources


async def list_admin_policies() -> list[dict[str, Any]]:
    """Return customer-managed policies that grant Action='*' on Resource='*'."""
    return await asyncio.to_thread(_list_admin_policies_sync)


def _list_admin_policies_sync() -> list[dict[str, Any]]:
    iam = boto3.client("iam")
    out: list[dict[str, Any]] = []
    for policy in iam.list_policies(Scope="Local").get("Policies", []):
        version = iam.get_policy_version(
            PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
        )
        document = version["PolicyVersion"]["Document"]
        if isinstance(document, str):
            document = json.loads(document)
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if any(_statement_is_star_star(s) for s in statements):
            out.append(
                {
                    "policy_name": policy["PolicyName"],
                    "policy_arn": policy["Arn"],
                    "document": document,
                }
            )
    return out
