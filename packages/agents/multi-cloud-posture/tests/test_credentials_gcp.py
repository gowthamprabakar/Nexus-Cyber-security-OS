"""D.5 v0.2 Task 6 — GCP CredentialResolver (ADC) tests (no live GCP)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from multi_cloud_posture.credentials_gcp import GCP_CREDENTIAL_SOURCES, GcpCredentialResolver


def test_default_source_is_adc() -> None:
    assert GcpCredentialResolver().source is None


def test_explicit_source_stored() -> None:
    assert GcpCredentialResolver(source="service-account").source == "service-account"


def test_invalid_source_raises() -> None:
    with pytest.raises(ValueError, match="unknown gcp credential source"):
        GcpCredentialResolver(source="nope")


def test_adc_resolves_via_google_auth_default() -> None:
    creds = MagicMock(name="creds")
    with patch("google.auth.default", return_value=(creds, "proj-123")) as default:
        out_creds, project = GcpCredentialResolver().resolve_credential()
    assert (out_creds, project) == (creds, "proj-123")
    default.assert_called_once()


def test_workload_identity_also_uses_adc() -> None:
    creds = MagicMock(name="creds")
    with patch("google.auth.default", return_value=(creds, "proj-wif")) as default:
        _, project = GcpCredentialResolver(source="workload-identity").resolve_credential()
    assert project == "proj-wif"
    default.assert_called_once()


def test_service_account_loads_key_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "sa-key.json")
    creds = MagicMock(name="sa_creds")
    creds.project_id = "sa-proj"
    with patch(
        "google.oauth2.service_account.Credentials.from_service_account_file",
        return_value=creds,
    ) as loader:
        out_creds, project = GcpCredentialResolver(source="service-account").resolve_credential()
    loader.assert_called_once_with("sa-key.json")
    assert (out_creds, project) == (creds, "sa-proj")


def test_service_account_without_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    with pytest.raises(ValueError, match="GOOGLE_APPLICATION_CREDENTIALS"):
        GcpCredentialResolver(source="service-account").resolve_credential()


def test_client_builds_with_credentials() -> None:
    creds = MagicMock(name="creds")
    client_cls = MagicMock(name="SccClient")
    with patch.object(GcpCredentialResolver, "resolve_credential", return_value=(creds, "p")):
        GcpCredentialResolver().client(client_cls)
    client_cls.assert_called_once_with(credentials=creds)


def test_no_secret_material_in_state() -> None:
    r = GcpCredentialResolver(source="adc")
    assert set(GcpCredentialResolver.__slots__) == {"_source"}
    assert r.source == "adc"


def test_contract_shape_mirrors_cloud_posture_resolver() -> None:
    r = GcpCredentialResolver()
    assert hasattr(r, "source")
    assert callable(r.resolve_credential)
    assert callable(r.client)
    assert set(GCP_CREDENTIAL_SOURCES) == {"adc", "service-account", "workload-identity"}
