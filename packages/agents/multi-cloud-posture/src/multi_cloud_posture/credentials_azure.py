"""D.5 Azure credential-resolution seam (v0.2 Task 2).

Mirrors the **contract** of `cloud_posture.CredentialResolver` (Q1 — same shape,
Azure-native). F.3's resolver is boto3-specific, so there is no literal
cloud-agnostic seam to import yet; D.5 replicates the shape and the
literal hoist-to-`charter` is deferred to **D.2** (the 3rd consumer) per ADR-007.
The substrate seal stays empty either way.

Resolves an `azure-identity` credential for a run: the `DefaultAzureCredential`
chain (env Service Principal → Managed Identity → Azure CLI) or an explicitly
selected source. Only the source **name** is stored; the secret material is
resolved inside `azure-identity` and never passes through — or is logged by —
this class.
"""

from __future__ import annotations

from typing import Any

# Accepted `--azure-credential-source` values; `None`/"chain" = DefaultAzureCredential.
AZURE_CREDENTIAL_SOURCES = ("chain", "environment", "managed-identity", "cli")


class AzureCredentialResolver:
    """Resolves an azure-identity credential for a Multi-Cloud Posture run.

    No source → `DefaultAzureCredential` (the chain), which is the recommended
    default (covers dev via Azure CLI / Service Principal and prod via Managed
    Identity). The resolver's only state is the source name; no secret material
    is stored or logged.
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

    def client(self, client_cls: Any, *, subscription_id: str | None = None, **kwargs: Any) -> Any:
        """An Azure SDK management client from the resolved credential.

        Azure management clients take `(credential, subscription_id)`;
        `subscription_id` is optional here — Task 3 threads discovery.
        """
        credential = self.resolve_credential()
        if subscription_id is not None:
            return client_cls(credential, subscription_id, **kwargs)
        return client_cls(credential, **kwargs)
