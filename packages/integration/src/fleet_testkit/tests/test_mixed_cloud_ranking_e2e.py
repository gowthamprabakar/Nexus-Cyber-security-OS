"""Track A — mixed AWS + Azure + GCP ranking coherence.

Plants THREE public-data attack paths in one tenant (one per cloud) and verifies that
``build_report_card`` produces a coherent expected-loss ranking across all three:

- AWS  : public S3 bucket reached by a role that also reaches two MORE buckets (blast radius 3)
- Azure: public Azure Blob container reached by a managed identity (blast radius 1)
- GCP  : public GCS bucket reached by a service account (blast radius 1)

Ranking assertions:
  1. cards is non-empty
  2. chains span at least 2 clouds (arn: AND at least one of blob.core.windows.net / gs://)
  3. expected_loss list is sorted non-increasing (the ranking invariant)
  4. the AWS card (blast_radius=3) has a higher expected_loss than the single-store cloud cards
  5. render_tenant_report_card succeeds and contains the standard card markers
"""

from __future__ import annotations

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.report_card import build_report_card, render_tenant_report_card

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.azure_blob import AzureContainer, drive_azure_data_security
from fleet_testkit.gcs_blob import PUBLIC_MEMBER, GcsBucketSeed, drive_gcs_data_security
from fleet_testkit.identity_access import (
    AzureGrant,
    GcpBinding,
    drive_azure_identity_access,
    drive_gcp_identity_access,
)

_TENANT = "tenant-mixed-cloud-ranking"

# AWS identifiers
_AWS_ROLE = "arn:aws:iam::111122223333:role/mixed-cloud-role"
_AWS_BUCKET_A = "mixed-cloud-bucket-a"
_AWS_BUCKET_B = "mixed-cloud-bucket-b"
_AWS_BUCKET_C = "mixed-cloud-bucket-c"

# Azure identifiers
_AZURE_PRINCIPAL = "mi-mixed-cloud-1"
_AZURE_ACCOUNT = "mixedcloudstorage"
_AZURE_CONTAINER = "sensitive-data"


def _azure_scope(container: str) -> str:
    return (
        f"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage"
        f"/storageAccounts/{_AZURE_ACCOUNT}/blobServices/default/containers/{container}"
    )


# GCP identifiers
_GCP_SA_MEMBER = "serviceAccount:mixed-cloud-sa@acme-prod.iam.gserviceaccount.com"
_GCP_BUCKET = "mixed-cloud-gcs-bucket"
_GCP_PROJECT = "acme-prod"

# Sensitive SSN sample — passes classify_bytes
_SSN_SAMPLE = b"ssn: 123-45-6789 on file\n"


async def _plant_aws_path(store) -> None:
    """AWS: role reaches 3 public S3 buckets → blast radius 3."""
    ident = IdentityKgWriter(store, _TENANT)
    for bucket_name in (_AWS_BUCKET_A, _AWS_BUCKET_B, _AWS_BUCKET_C):
        resource_arn = f"arn:aws:s3:::{bucket_name}"
        # public resource + sensitive data (the same shape test_probabilistic_ranking.py uses)
        b = await store.upsert_entity(
            tenant_id=_TENANT,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=resource_arn,
            properties={"is_public": True},
        )
        d = await store.upsert_entity(
            tenant_id=_TENANT,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{resource_arn}/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_TENANT,
            src_entity_id=b,
            dst_entity_id=d,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )
        await ident.record_access([(_AWS_ROLE, resource_arn)])


async def _plant_azure_path(store) -> None:
    """Azure: public container with sensitive data, managed identity has access → blast radius 1."""
    containers = (
        AzureContainer(
            _AZURE_CONTAINER,
            public_access="container",
            blobs={"e.csv": _SSN_SAMPLE},
        ),
    )
    await drive_azure_data_security(
        store,
        tenant_id=_TENANT,
        containers=containers,
        storage_account=_AZURE_ACCOUNT,
    )
    await drive_azure_identity_access(
        store,
        tenant_id=_TENANT,
        grants=(
            AzureGrant(
                _AZURE_PRINCIPAL, "Storage Blob Data Reader", _azure_scope(_AZURE_CONTAINER)
            ),
        ),
    )


async def _plant_gcp_path(store) -> None:
    """GCP: public GCS bucket with sensitive data, service account has access → blast radius 1."""
    buckets = (
        GcsBucketSeed(
            _GCP_BUCKET,
            iam_members=(PUBLIC_MEMBER, _GCP_SA_MEMBER),
            blobs={"e.csv": _SSN_SAMPLE},
        ),
    )
    await drive_gcs_data_security(
        store,
        tenant_id=_TENANT,
        buckets=buckets,
        project=_GCP_PROJECT,
    )
    await drive_gcp_identity_access(
        store,
        tenant_id=_TENANT,
        bindings=(GcpBinding(_GCP_BUCKET, "roles/storage.objectViewer", (_GCP_SA_MEMBER,)),),
    )


@pytest.mark.asyncio
async def test_mixed_cloud_ranking_coherence() -> None:
    """Expected-loss ranking is coherent on a graph spanning AWS + Azure + GCP."""
    async with in_memory_semantic_store() as store:
        await _plant_aws_path(store)
        await _plant_azure_path(store)
        await _plant_gcp_path(store)

        cards = await build_report_card(store, _TENANT)

        # (a) at least one card
        assert cards, "expected at least one attack-path card from a mixed-cloud graph"

        # (b) chains span at least 2 clouds
        all_chain_ids: list[str] = [node for c in cards for node in c.chain]
        combined = " ".join(all_chain_ids)
        has_aws = "arn:" in combined
        has_azure = "blob.core.windows.net" in combined
        has_gcp = "gs://" in combined
        cloud_count = sum([has_aws, has_azure, has_gcp])
        assert cloud_count >= 2, (
            f"expected chains from at least 2 clouds; found aws={has_aws} "
            f"azure={has_azure} gcp={has_gcp} — chains: {combined!r}"
        )

        # (c) ranking invariant: expected_loss is non-increasing
        losses = [c.expected_loss for c in cards]
        assert losses == sorted(losses, reverse=True), (
            f"expected_loss must be non-increasing (ranking invariant); got {losses}"
        )

        # (d) AWS card (blast_radius=3) outranks the single-store cloud cards.
        # UNCONDITIONAL: a silently-empty aws_cards (e.g. the entity_type=.value regression) MUST fail here,
        # not skip. Both the AWS path and a single-store cloud path must actually be present.
        aws_cards = [c for c in cards if any("arn:aws:s3:::" in n for n in c.chain)]
        assert aws_cards, "AWS path must produce a card (guards the NodeCategory.value regression)"
        aws_loss = max(c.expected_loss for c in aws_cards)
        single_store_cards = [c for c in cards if c.blast_radius == 1 and c not in aws_cards]
        assert single_store_cards, (
            "expected at least one single-store (Azure/GCP) card to compare against"
        )
        for sc in single_store_cards:
            assert aws_loss >= sc.expected_loss, (
                f"AWS card (blast_radius=3, loss={aws_loss:.4f}) should rank >= "
                f"single-store card (loss={sc.expected_loss:.4f}, type={sc.path_type!r})"
            )

        # (e) render end-to-end
        rendered = await render_tenant_report_card(store, _TENANT)
        assert "[P " in rendered, "rendered card must contain probability marker '[P '"
        assert "data store" in rendered, (
            "rendered card must contain 'data store' (blast radius text)"
        )
