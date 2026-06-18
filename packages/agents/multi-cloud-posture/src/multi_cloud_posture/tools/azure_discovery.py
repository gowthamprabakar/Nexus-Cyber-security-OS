"""D.15 Azure subscription + region discovery (v0.2 Task 3).

Analog to `cloud_posture`'s account/region discovery (Q1 — Azure-native shape).
**Current-subscription only (Q6** — multi-subscription / management-group /
tenant enumeration deferred to v0.3): the subscription is `AZURE_SUBSCRIPTION_ID`
when set, else the **first** subscription visible to the resolved credential.
Locations are enumerated for that single subscription.

Per ADR-005 the SDK calls run on `asyncio.to_thread`; the wrappers are `async`.
"""

from __future__ import annotations

import asyncio
import os

from multi_cloud_posture.credentials_azure import AzureCredentialResolver


class AzureDiscoveryError(RuntimeError):
    """Azure subscription / region discovery failed."""


async def discover_subscription_id(resolver: AzureCredentialResolver) -> str:
    """The current Azure subscription id (single — Q6).

    `AZURE_SUBSCRIPTION_ID` wins; otherwise the first subscription visible to the
    resolved credential. Multiple subscriptions are **not** enumerated/scanned.
    """
    return await asyncio.to_thread(_discover_subscription_id_sync, resolver)


def _discover_subscription_id_sync(resolver: AzureCredentialResolver) -> str:
    env_sub = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if env_sub:
        return env_sub
    from azure.mgmt.subscription import SubscriptionClient

    client = resolver.client(SubscriptionClient)
    for sub in client.subscriptions.list():
        # current-subscription only (Q6): take the first; do NOT walk the rest.
        return str(sub.subscription_id)
    raise AzureDiscoveryError("no Azure subscription visible to the resolved credential")


async def discover_locations(resolver: AzureCredentialResolver, subscription_id: str) -> list[str]:
    """Enumerate Azure region/location names for the single subscription."""
    return await asyncio.to_thread(_discover_locations_sync, resolver, subscription_id)


def _discover_locations_sync(resolver: AzureCredentialResolver, subscription_id: str) -> list[str]:
    from azure.mgmt.subscription import SubscriptionClient

    client = resolver.client(SubscriptionClient)
    return sorted(
        loc.name for loc in client.subscriptions.list_locations(subscription_id) if loc.name
    )
