"""v0.5 Item 3 — gated live-reader e2e. Skips in CI; operator runs with NEXUS_LIVE_* set.

Each test is intentionally unrunnable in CI: the `_build_live_*_client()` helpers are
operator-provided at run time (not imported here). Only the NEXUS_LIVE_* env gates control
whether the test body executes. Collection never fails because all SDK imports are inside
the test bodies.
"""

from __future__ import annotations

import os

import pytest


@pytest.mark.skipif(
    not os.getenv("NEXUS_LIVE_AZURE"),
    reason="operator-gated: set NEXUS_LIVE_AZURE to run",
)
def test_azure_nsg_reader_live() -> None:
    from network_threat.tools.azure_nsg_reader import AzureNsgReader
    from network_threat.tools.reachability import reach_grants

    # Operator wires the real azure-mgmt-network client here; the reader + reach_grants are the SUT.
    client = _build_live_azure_nsg_client()  # noqa: F821 — operator provides at run time
    insts, sgs = AzureNsgReader(client).read()
    assert isinstance(reach_grants(insts, sgs), list)


@pytest.mark.skipif(
    not os.getenv("NEXUS_LIVE_GCP"),
    reason="operator-gated: set NEXUS_LIVE_GCP to run",
)
def test_gcp_firewall_reader_live() -> None:
    from network_threat.tools.gcp_firewall_reader import GcpFirewallReader
    from network_threat.tools.reachability import reach_grants

    # Operator wires the real google-cloud-compute client here; reader + reach_grants are the SUT.
    client = _build_live_gcp_firewall_client()  # noqa: F821 — operator provides at run time
    insts, sgs = GcpFirewallReader(client).read()
    assert isinstance(reach_grants(insts, sgs), list)


@pytest.mark.skipif(
    not os.getenv("NEXUS_LIVE_GCP"),
    reason="operator-gated: set NEXUS_LIVE_GCP to run",
)
def test_gcp_sa_key_reader_live() -> None:
    from identity.tools.gcp_iam import sa_key_ownership
    from identity.tools.gcp_sa_key_reader import GcpSaKeyReader

    # Operator wires the real google-auth / IAM admin client here; reader + ownership are the SUT.
    client = _build_live_gcp_sa_key_client()  # noqa: F821 — operator provides at run time
    keys = GcpSaKeyReader(client).read()
    ownership = sa_key_ownership(keys)
    assert isinstance(ownership, list)
    if ownership:
        # Each entry is (service_account, secret_fingerprint); fingerprint starts with "secretfp:"
        assert ownership[0][1].startswith("secretfp:")


@pytest.mark.skipif(
    not os.getenv("NEXUS_LIVE_AZURE"),
    reason="operator-gated: set NEXUS_LIVE_AZURE to run",
)
def test_azure_sp_secret_reader_live() -> None:
    from identity.tools.azure_ad import sp_credential_ownership
    from identity.tools.azure_sp_secret_reader import AzureSpSecretReader

    # Operator wires the real azure-identity / MS Graph client here; reader + ownership are the SUT.
    client = _build_live_azure_sp_secret_client()  # noqa: F821 — operator provides at run time
    sps = AzureSpSecretReader(client).read()
    ownership = sp_credential_ownership(sps)
    assert isinstance(ownership, list)
    if ownership:
        # Each entry is (sp_identity_key, secret_fingerprint); fingerprint starts with "secretfp:"
        assert ownership[0][1].startswith("secretfp:")
