"""Federation trust detection (D.2 v0.2 Tasks 13-14) — basic, Q5 (B).

Detects WHICH external-IdP trust relationships exist per cloud — the L2 federation
surface — **not** deep cross-cloud chain traversal (Okta→AWS→assume-role paths),
which is the Q5 v0.3 residual (WI-I6: surface vs deep stated plainly).

Task 13 covers **SAML** trusts:
  - AWS  — IAM SAML 2.0 identity providers (`list_saml_providers`).
  - Azure — federated domains (`authenticationType == 'Federated'`, i.e. SAML/WS-Fed).

Per WI-I1 the two clouds are **separate** seams with their own shapes — never
aggregated into one federation count.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime

from identity.credentials import CredentialResolver
from identity.tools.azure_ad import GraphReader, build_graph_reader

AZURE_FEDERATED_AUTH_TYPE = "Federated"


class FederationError(RuntimeError):
    """A cloud federation query failed (transport / credential / API error)."""


@dataclass(frozen=True, slots=True)
class AwsSamlProvider:
    """An IAM SAML 2.0 identity provider — a trust allowing an external IdP to
    federate principals into the account."""

    arn: str
    name: str  # the friendly name (last ARN segment)
    valid_until: datetime | None


@dataclass(frozen=True, slots=True)
class AzureFederatedDomain:
    """An Azure AD domain whose authentication is federated to an external IdP
    (SAML / WS-Fed)."""

    domain: str
    authentication_type: str
    is_verified: bool


async def detect_aws_saml_providers(
    *,
    profile: str | None = None,
    region: str = "us-east-1",
    timeout_sec: float = 60.0,
) -> tuple[AwsSamlProvider, ...]:
    """Enumerate the account's IAM SAML identity providers (the SAML IdPs it trusts)."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_aws_saml_sync, profile, region), timeout=timeout_sec
        )
    except TimeoutError as exc:
        raise FederationError(f"detect_aws_saml_providers timed out after {timeout_sec}s") from exc
    except Exception as exc:  # boto3 / botocore
        raise FederationError(f"detect_aws_saml_providers failed: {exc}") from exc


def _aws_saml_sync(profile: str | None, region: str) -> tuple[AwsSamlProvider, ...]:
    iam = CredentialResolver(profile=profile, region=region).client("iam")
    providers: list[AwsSamlProvider] = []
    for p in iam.list_saml_providers().get("SAMLProviderList", []):
        arn = str(p["Arn"])
        valid_until = p.get("ValidUntil")
        providers.append(
            AwsSamlProvider(
                arn=arn,
                name=arn.rsplit("/", 1)[-1],
                valid_until=valid_until if isinstance(valid_until, datetime) else None,
            )
        )
    return tuple(providers)


async def detect_azure_federated_domains(
    *,
    graph: GraphReader | None = None,
    credential_source: str | None = None,
    timeout_sec: float = 60.0,
) -> tuple[AzureFederatedDomain, ...]:
    """Enumerate Azure AD domains whose authentication is federated (SAML/WS-Fed).

    `graph` is injectable for testing; in production it defaults to the
    httpx-backed Graph reader authenticated via the `AzureCredentialResolver`.
    """
    reader = graph or build_graph_reader(
        credential_source=credential_source, timeout_sec=timeout_sec
    )
    try:
        domains = await reader.get_all("domains", select="id,authenticationType,isVerified")
    except Exception as exc:
        raise FederationError(f"detect_azure_federated_domains failed: {exc}") from exc

    return tuple(
        AzureFederatedDomain(
            domain=str(d.get("id", "")),
            authentication_type=str(d.get("authenticationType", "")),
            is_verified=bool(d.get("isVerified", False)),
        )
        for d in domains
        if str(d.get("authenticationType", "")).lower() == AZURE_FEDERATED_AUTH_TYPE.lower()
    )
