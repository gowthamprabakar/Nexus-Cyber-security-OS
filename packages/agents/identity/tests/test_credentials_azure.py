"""D.2 v0.2 Task 9 — Identity Azure AD CredentialResolver tests (no live Azure)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from charter.credentials import CredentialResolver
from identity.credentials_azure import AZURE_CREDENTIAL_SOURCES, AzureCredentialResolver


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


def test_client_builds_graph_client_with_credential() -> None:
    cred = MagicMock(name="credential")
    client_cls = MagicMock(name="GraphServiceClient")
    with patch.object(AzureCredentialResolver, "resolve_credential", return_value=cred):
        AzureCredentialResolver().client(
            client_cls, scopes=["https://graph.microsoft.com/.default"]
        )
    client_cls.assert_called_once_with(cred, scopes=["https://graph.microsoft.com/.default"])


def test_conforms_to_charter_contract() -> None:
    r = AzureCredentialResolver()
    assert isinstance(r, CredentialResolver)
    assert callable(r.resolve_credential)
    assert callable(r.client)


def test_no_secret_material_in_state() -> None:
    r = AzureCredentialResolver(source="environment")
    assert set(AzureCredentialResolver.__slots__) == {"_source"}
    assert r.source == "environment"


def test_sources_tuple() -> None:
    assert set(AZURE_CREDENTIAL_SOURCES) == {"chain", "environment", "managed-identity", "cli"}
