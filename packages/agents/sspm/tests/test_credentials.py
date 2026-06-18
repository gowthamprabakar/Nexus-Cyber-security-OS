"""Tests for the SSPM SaaS credential resolver (D.10 PR1).

The swiss-bar guarantee: tokens are resolved from the environment per call and **never
persisted** on the resolver instance. The resolver carries only env-var *names*.
"""

from __future__ import annotations

import pytest
from sspm.credentials import SaaSCredentialError, SaaSCredentialResolver


def test_resolve_reads_env_per_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_SSPM_GITHUB_TOKEN", "ghp_secret_value")
    r = SaaSCredentialResolver(provider="github", env={"token": "NEXUS_SSPM_GITHUB_TOKEN"})
    assert r.resolve("token") == "ghp_secret_value"
    assert r.bearer_token() == "ghp_secret_value"


def test_multi_key_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CID", "client-id-val")
    monkeypatch.setenv("SEC", "client-secret-val")
    r = SaaSCredentialResolver(provider="m365", env={"client_id": "CID", "client_secret": "SEC"})
    assert r.resolve("client_id") == "client-id-val"
    assert r.resolve("client_secret") == "client-secret-val"


def test_unconfigured_key_raises() -> None:
    r = SaaSCredentialResolver(provider="github", env={})
    with pytest.raises(SaaSCredentialError, match="not configured"):
        r.resolve("token")


def test_unset_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXUS_SSPM_SLACK_TOKEN", raising=False)
    r = SaaSCredentialResolver(provider="slack", env={"token": "NEXUS_SSPM_SLACK_TOKEN"})
    with pytest.raises(SaaSCredentialError, match="unset or empty"):
        r.resolve("token")


def test_secret_is_never_persisted_on_the_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_SSPM_GITHUB_TOKEN", "ghp_secret_value")
    r = SaaSCredentialResolver(provider="github", env={"token": "NEXUS_SSPM_GITHUB_TOKEN"})
    r.resolve("token")  # resolve it — must still not be cached anywhere on the instance.

    # The instance + its repr carry only the env-var NAME, never the secret value.
    assert "ghp_secret_value" not in repr(r)
    assert "ghp_secret_value" not in str(r.__dict__)
    assert r.env == {"token": "NEXUS_SSPM_GITHUB_TOKEN"}
