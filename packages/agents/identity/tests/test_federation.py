"""D.2 v0.2 Task 13 — SAML federation trust detection (AWS + Azure, basic per Q5).

AWS SAML providers are exercised against moto; Azure federated domains use the
injected `GraphReader` fake (no live tenant).
"""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from identity.tools.federation import (
    AzureFederatedDomain,
    FederationError,
    detect_aws_saml_providers,
    detect_azure_federated_domains,
)
from moto import mock_aws

# moto requires the SAML metadata document to be >= 1000 chars.
_METADATA = "<EntityDescriptor>" + ("x" * 1100) + "</EntityDescriptor>"


# ---------------------------- AWS SAML providers --------------------------


@pytest.mark.asyncio
async def test_detects_aws_saml_providers() -> None:
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_saml_provider(Name="Okta", SAMLMetadataDocument=_METADATA)
        iam.create_saml_provider(Name="ADFS", SAMLMetadataDocument=_METADATA)
        providers = await detect_aws_saml_providers()

    assert {p.name for p in providers} == {"Okta", "ADFS"}
    assert all(p.arn.startswith("arn:aws:iam::") for p in providers)
    assert all(":saml-provider/" in p.arn for p in providers)


@pytest.mark.asyncio
async def test_no_aws_saml_providers() -> None:
    with mock_aws():
        providers = await detect_aws_saml_providers()
    assert providers == ()


@pytest.mark.asyncio
async def test_aws_saml_error_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    from identity.tools import federation as federation_mod

    class _Boom:
        def client(self, *_a: Any, **_k: Any) -> Any:
            raise RuntimeError("IAM unreachable arn:aws:iam::secret")

    # patch federation's own bound reference so the failure is deterministic
    monkeypatch.setattr(federation_mod, "CredentialResolver", lambda **_: _Boom())
    with pytest.raises(FederationError):
        await detect_aws_saml_providers()


# -------------------------- Azure federated domains -----------------------


class _FakeGraphReader:
    def __init__(self, domains: list[dict[str, Any]]) -> None:
        self._domains = domains

    async def get_all(self, resource: str, *, select: str | None = None) -> list[dict[str, Any]]:
        assert resource == "domains"
        return self._domains


@pytest.mark.asyncio
async def test_detects_only_federated_domains() -> None:
    reader = _FakeGraphReader(
        [
            {"id": "contoso.com", "authenticationType": "Managed", "isVerified": True},
            {"id": "fed.contoso.com", "authenticationType": "Federated", "isVerified": True},
            {"id": "okta.contoso.com", "authenticationType": "Federated", "isVerified": False},
        ]
    )
    domains = await detect_azure_federated_domains(graph=reader)

    assert {d.domain for d in domains} == {"fed.contoso.com", "okta.contoso.com"}
    # the managed (non-federated) domain is excluded
    assert all(d.authentication_type == "Federated" for d in domains)
    okta = next(d for d in domains if d.domain == "okta.contoso.com")
    assert okta == AzureFederatedDomain(
        domain="okta.contoso.com", authentication_type="Federated", is_verified=False
    )


@pytest.mark.asyncio
async def test_no_federated_domains() -> None:
    reader = _FakeGraphReader(
        [{"id": "contoso.com", "authenticationType": "Managed", "isVerified": True}]
    )
    assert await detect_azure_federated_domains(graph=reader) == ()


@pytest.mark.asyncio
async def test_azure_federation_error_is_wrapped() -> None:
    class _Boom:
        async def get_all(
            self, resource: str, *, select: str | None = None
        ) -> list[dict[str, Any]]:
            raise RuntimeError("Graph 403 tenant=secret")

    with pytest.raises(FederationError):
        await detect_azure_federated_domains(graph=_Boom())
