"""Identity Azure AD / Entra credential-resolution seam (D.2 v0.2 Task 9).

Net-new Azure AD support. Adopts the hoisted `charter.credentials.CredentialResolver`
contract (Pattern A) — the same `DefaultAzureCredential` shape D.5 multi-cloud-posture
uses, reinforcing the canonical 3rd-consumer hoist. Resolves an `azure-identity`
credential for Microsoft Graph; Task 10 wires the Graph client through `client(...)`.

It only ever handles a credential-source **name**; the secret material is resolved
inside `azure-identity` and never passes through — or is logged by — this class.
"""

from __future__ import annotations

from typing import Any

from charter.credentials import CredentialResolver

# Accepted `--azure-credential-source` values; `None`/"chain" = DefaultAzureCredential.
AZURE_CREDENTIAL_SOURCES = ("chain", "environment", "managed-identity", "cli")


class AzureCredentialResolver(CredentialResolver):
    """Resolves an azure-identity credential for an Identity (Azure AD) run.

    No source → `DefaultAzureCredential` (the chain: env Service Principal →
    Managed Identity → Azure CLI), the recommended default. The resolver's only
    state is the source name; no secret material is stored or logged.
    """

    __slots__ = ("_source",)

    def __init__(self, *, source: str | None = None) -> None:
        if source is not None and source not in AZURE_CREDENTIAL_SOURCES:
            raise ValueError(
                f"unknown azure credential source: {source!r}; "
                f"expected one of {AZURE_CREDENTIAL_SOURCES}"
            )
        self._source = source

    @property
    def source(self) -> str | None:
        """The explicit source, or `None` for the `DefaultAzureCredential` chain."""
        return self._source

    def resolve_credential(self) -> Any:
        """Build an azure-identity credential per the configured source.

        `None`/"chain" → `DefaultAzureCredential` · "environment" →
        `EnvironmentCredential` · "managed-identity" → `ManagedIdentityCredential`
        · "cli" → `AzureCliCredential`.
        """
        from azure.identity import (
            AzureCliCredential,
            DefaultAzureCredential,
            EnvironmentCredential,
            ManagedIdentityCredential,
        )

        if self._source is None or self._source == "chain":
            return DefaultAzureCredential()
        if self._source == "environment":
            return EnvironmentCredential()
        if self._source == "managed-identity":
            return ManagedIdentityCredential()
        return AzureCliCredential()  # "cli"

    def client(self, client_cls: Any, *args: Any, **kwargs: Any) -> Any:
        """Build a client from the resolved credential.

        Generic over the client class so Task 10 can construct a Microsoft Graph
        client, e.g. ``resolver.client(GraphServiceClient, scopes=[...])`` →
        ``GraphServiceClient(credential, scopes=[...])``.
        """
        return client_cls(self.resolve_credential(), *args, **kwargs)
