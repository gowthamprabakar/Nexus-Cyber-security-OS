"""AWS account + region discovery (async) — current-account only (F.3 v0.2 Task 3).

Discovers the **current** AWS account ID (STS `get_caller_identity`) and the
EC2 regions available to the resolved session. Both go through the Task-2
`CredentialResolver` seam, so they honor `--aws-profile` / the default chain.

Scope (Q4 lock): **current account only.** Cross-account discovery — STS
role-assumption and Organizations account enumeration — is v0.3 and
intentionally absent here. Per-region scoping through the scan tools (Prowler /
S3 / IAM) is Task 4; `discover_regions` provides the enumeration it consumes.
"""

from __future__ import annotations

import asyncio

from cloud_posture.credentials import CredentialResolver


async def discover_account_id(resolver: CredentialResolver) -> str:
    """Return the current AWS account ID via STS ``get_caller_identity``."""
    return await asyncio.to_thread(_discover_account_id_sync, resolver)


def _discover_account_id_sync(resolver: CredentialResolver) -> str:
    sts = resolver.client("sts")
    return str(sts.get_caller_identity()["Account"])


async def discover_regions(resolver: CredentialResolver) -> list[str]:
    """Return the EC2 regions available to the resolved session."""
    return await asyncio.to_thread(_discover_regions_sync, resolver)


def _discover_regions_sync(resolver: CredentialResolver) -> list[str]:
    session = resolver.resolve_session()
    return list(session.get_available_regions("ec2"))
