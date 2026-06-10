"""D.2 v0.2 Task 15 — federation trust OCSF 2004 emission.

`build_finding`/`IdentityFinding` raise unless the payload is OCSF `class_uid 2004`
with a `FINDING_ID_RE`-valid id, so a successfully-constructed finding *is* the
OCSF-shape assertion.
"""

from __future__ import annotations

from datetime import UTC, datetime

from identity.normalizer import federation_to_findings
from identity.schemas import FindingType, Severity
from identity.tools.federation import (
    AwsOidcProvider,
    AwsSamlProvider,
    AzureFederatedDomain,
    AzureOidcProvider,
)
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 6, 10, tzinfo=UTC)

_SAML = AwsSamlProvider(
    arn="arn:aws:iam::111122223333:saml-provider/Okta", name="Okta", valid_until=None
)
_OIDC = AwsOidcProvider(
    arn="arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
    url="token.actions.githubusercontent.com",
    client_ids=("sts.amazonaws.com",),
)
_DOMAIN = AzureFederatedDomain(
    domain="fed.contoso.com", authentication_type="Federated", is_verified=True
)
_AZ_OIDC = AzureOidcProvider(
    id="Okta-OIDC", display_name="Okta", odata_type="#microsoft.graph.openIdConnectIdentityProvider"
)


def _env() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="identity@0.2.0",
        nlah_version="0.2.0",
        model_pin="deterministic-v0.2",
        charter_invocation_id="invocation_001",
    )


def test_emits_one_low_finding_per_trust() -> None:
    findings = federation_to_findings(
        envelope=_env(),
        aws_saml=[_SAML],
        aws_oidc=[_OIDC],
        azure_federated_domains=[_DOMAIN],
        azure_oidc=[_AZ_OIDC],
        detected_at=NOW,
    )
    assert len(findings) == 4
    assert all(f.finding_type == FindingType.FEDERATION for f in findings)
    assert all(f.severity == Severity.LOW for f in findings)


def test_aws_saml_finding_id_and_shape() -> None:
    findings = federation_to_findings(envelope=_env(), aws_saml=[_SAML], detected_at=NOW)
    assert findings[0].finding_id == "IDENT-FED-OKTA-001-saml_aws"


def test_aws_oidc_evidence() -> None:
    findings = federation_to_findings(envelope=_env(), aws_oidc=[_OIDC], detected_at=NOW)
    ev = findings[0].evidence
    assert ev["protocol"] == "oidc"
    assert ev["cloud"] == "aws"
    assert ev["url"] == "token.actions.githubusercontent.com"
    assert ev["client_ids"] == ["sts.amazonaws.com"]


def test_azure_findings_are_cloud_scoped() -> None:
    findings = federation_to_findings(
        envelope=_env(),
        azure_federated_domains=[_DOMAIN],
        azure_oidc=[_AZ_OIDC],
        detected_at=NOW,
    )
    assert all(f.evidence["cloud"] == "azure" for f in findings)
    # WI-I1: Azure findings carry no AWS account id — the principal is azuread-scoped.
    assert all("azuread" in f.principal_arns[0] for f in findings)


def test_no_trusts_emits_nothing() -> None:
    assert federation_to_findings(envelope=_env()) == []
