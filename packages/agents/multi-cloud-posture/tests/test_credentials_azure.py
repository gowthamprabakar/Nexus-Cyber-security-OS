"""D.5 v0.2 Task 2 — Azure CredentialResolver tests (no live Azure)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from multi_cloud_posture.credentials_azure import (
    AZURE_CREDENTIAL_SOURCES,
    AzureCredentialResolver,
)


def test_default_source_is_chain() -> None:
    assert AzureCredentialResolver().source is None


def test_explicit_source_stored() -> None:
    assert AzureCredentialResolver(source="cli").source == "cli"


def test_invalid_source_raises() -> None:
    with pytest.raises(ValueError, match="unknown azure credential source"):
        AzureCredentialResolver(source="not-a-source")


def _patched_identity() -> dict[str, MagicMock]:
    return {name: MagicMock(name=name) for name in ("default", "env", "mi", "cli")}


def test_chain_resolves_default_azure_credential() -> None:
    m = _patched_identity()
    with patch.multiple(
        "azure.identity",
        DefaultAzureCredential=m["default"],
        EnvironmentCredential=m["env"],
        ManagedIdentityCredential=m["mi"],
        AzureCliCredential=m["cli"],
    ):
        AzureCredentialResolver().resolve_credential()
        AzureCredentialResolver(source="chain").resolve_credential()
    assert m["default"].call_count == 2
    assert m["env"].call_count == m["mi"].call_count == m["cli"].call_count == 0


def test_environment_source_resolves_environment_credential() -> None:
    m = _patched_identity()
    with patch.multiple(
        "azure.identity",
        DefaultAzureCredential=m["default"],
        EnvironmentCredential=m["env"],
        ManagedIdentityCredential=m["mi"],
        AzureCliCredential=m["cli"],
    ):
        AzureCredentialResolver(source="environment").resolve_credential()
    assert m["env"].call_count == 1
    assert m["default"].call_count == 0


def test_managed_identity_source_resolves_mi_credential() -> None:
    m = _patched_identity()
    with patch.multiple(
        "azure.identity",
        DefaultAzureCredential=m["default"],
        EnvironmentCredential=m["env"],
        ManagedIdentityCredential=m["mi"],
        AzureCliCredential=m["cli"],
    ):
        AzureCredentialResolver(source="managed-identity").resolve_credential()
    assert m["mi"].call_count == 1


def test_cli_source_resolves_cli_credential() -> None:
    m = _patched_identity()
    with patch.multiple(
        "azure.identity",
        DefaultAzureCredential=m["default"],
        EnvironmentCredential=m["env"],
        ManagedIdentityCredential=m["mi"],
        AzureCliCredential=m["cli"],
    ):
        AzureCredentialResolver(source="cli").resolve_credential()
    assert m["cli"].call_count == 1


def test_client_builds_with_credential_and_subscription() -> None:
    cred = MagicMock(name="credential")
    client_cls = MagicMock(name="ResourceClient")
    with patch.object(AzureCredentialResolver, "resolve_credential", return_value=cred):
        AzureCredentialResolver().client(client_cls, subscription_id="sub-123")
    client_cls.assert_called_once_with(cred, "sub-123")


def test_client_builds_without_subscription() -> None:
    cred = MagicMock(name="credential")
    client_cls = MagicMock(name="SubscriptionClient")
    with patch.object(AzureCredentialResolver, "resolve_credential", return_value=cred):
        AzureCredentialResolver().client(client_cls)
    client_cls.assert_called_once_with(cred)


def test_no_secret_material_in_state() -> None:
    # only the source name is stored — never a credential/secret.
    r = AzureCredentialResolver(source="environment")
    assert set(AzureCredentialResolver.__slots__) == {"_source"}
    assert r.source == "environment"


def test_contract_shape_mirrors_cloud_posture_resolver() -> None:
    # same seam shape as cloud_posture.CredentialResolver (Q1): a source +
    # a credential resolver + a client factory.
    r = AzureCredentialResolver()
    assert hasattr(r, "source")
    assert callable(r.resolve_credential)
    assert callable(r.client)
    assert set(AZURE_CREDENTIAL_SOURCES) == {"chain", "environment", "managed-identity", "cli"}
