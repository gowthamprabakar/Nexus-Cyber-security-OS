"""SaaS credential resolution (D.10 SSPM, operator Q3 — agent-local for now).

The charter ``CredentialResolver`` is cloud-only (boto3 / azure-identity / google-auth
SDK clients). SaaS posture uses OAuth2 client-credentials / API-token / PAT auth over
HTTP, so SSPM needs a SaaS-shaped resolver. It is **agent-local** until a 2nd SaaS
consumer exists, at which point it hoists to the charter (Path-B operating rule).

**Secret-safety contract** (mirrors ``charter.CredentialResolver`` semantics for SaaS):
the resolver stores ONLY *source identifiers* — the **names** of the environment
variables that hold the secrets — never the secret material itself. Tokens are read
from ``os.environ`` on each :meth:`resolve` and handed to the caller; nothing is cached
on the instance, so a resolver is safe to ``repr``/log (it carries no secrets). This is
the swiss-bar "no token persistence" guarantee, enforced by construction.

OAuth2 client-credentials exchange (M365) builds on :meth:`resolve` for the
``client_id`` / ``client_secret`` / ``tenant_id`` and is performed by the connector with
an injected HTTP transport — deliberately NOT here, so this contract stays HTTP-free and
trivially testable.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


class SaaSCredentialError(RuntimeError):
    """A required SaaS credential is not configured or its env var is unset/empty."""


@dataclass(frozen=True)
class SaaSCredentialResolver:
    """Resolve SaaS API credentials from the environment per call; never persist them.

    Args:
        provider: The SaaS provider id (e.g. ``"github"`` | ``"m365"`` | ``"slack"``) —
            for error messages only.
        env: Mapping of logical credential key → the **environment variable name** that
            holds it (a source identifier, never the secret). E.g.
            ``{"token": "NEXUS_SSPM_GITHUB_TOKEN"}`` for a PAT provider, or
            ``{"client_id": "...", "client_secret": "...", "tenant_id": "..."}`` for M365.
    """

    provider: str
    env: Mapping[str, str]

    def resolve(self, key: str) -> str:
        """Read one configured secret from the environment. Never cached on the instance.

        Raises:
            SaaSCredentialError: ``key`` is not configured, or its env var is unset/empty.
        """
        env_var = self.env.get(key)
        if not env_var:
            raise SaaSCredentialError(f"{self.provider}: credential key {key!r} is not configured")
        value = os.environ.get(env_var)
        if not value:
            raise SaaSCredentialError(
                f"{self.provider}: environment variable {env_var!r} is unset or empty"
            )
        return value

    def bearer_token(self) -> str:
        """Convenience for token/PAT providers (GitHub, Slack): resolve the ``"token"`` key."""
        return self.resolve("token")


__all__ = ["SaaSCredentialError", "SaaSCredentialResolver"]
