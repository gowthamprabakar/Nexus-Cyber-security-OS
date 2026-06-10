"""Cloud-agnostic credential-resolution contract — Pattern A (hoisted, D.2 v0.2 Task 4).

Hoisted from F.3 cloud-posture (`CredentialResolver`, boto3) and D.5
multi-cloud-posture (`AzureCredentialResolver` / `GcpCredentialResolver`) into the
charter for cross-agent reuse — D.2 Identity is the canonical 3rd consumer (it
resolves both AWS IAM and Azure AD credentials, Tasks 5 + 9), so the ADR-007 hoist
fires here. The contract lives in one place; agents subclass it instead of
re-deriving the shape.

The contract (cloud-agnostic): a resolver stores ONLY an optional *source
identifier* (a profile / credential-source name) — never secret material, which is
resolved inside the cloud SDK and never passes through (or is logged by) the
resolver. ``None`` selects the SDK's default chain (the boto3 default chain /
``DefaultAzureCredential`` / GCP ADC).

What STAYS per-cloud (WI-I2 — not hoisted): the boto3 / azure-identity / google-auth
session/credential construction, the identifier naming (``profile`` vs ``source``),
per-cloud source validation, the SDK ``client`` signature, and per-cloud exception
handling. Only the interface + the secret-safety + default-chain + region/subscription
scoping *semantics* are hoisted — hence a deliberately thin, stateless base.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class CredentialResolver(ABC):
    """Cloud-agnostic credential-resolution contract.

    A concrete resolver:

    - stores only an optional source identifier — **no secret material**;
    - treats ``None`` as "use the cloud SDK's default credential chain";
    - exposes :meth:`client` to build a ready-to-use SDK client from the resolved
      credential/session, threading per-cloud region / subscription scoping.

    This base is **stateless** (``__slots__ = ()``) so each subclass owns its own
    identifier slot (``_profile`` for boto3 F.3, ``_source`` for the azure-identity
    / google-auth D.5 resolvers) and its own ``__init__`` + source validation. The
    per-cloud session/credential construction is the subclass's responsibility.
    """

    __slots__ = ()

    @abstractmethod
    def client(self, *args: Any, **kwargs: Any) -> Any:
        """Build a cloud SDK client from the resolved credential/session.

        The signature is per-cloud (F.3: ``client(service, *, region=None)``; D.5
        Azure: ``client(client_cls, *, subscription_id=None)``). The contract is
        that a resolver yields ready-to-use SDK clients without ever exposing
        secret material.
        """
        ...
