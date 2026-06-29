"""Multi-cloud (gap #13, GCS parity) — GCS public + sensitive data, REAL e2e.

Mirror of the Azure e2e: proves paths 3 (public secret) and 7 (public + unencrypted + sensitive)
work on GCS through the agents' own code — a public GCS bucket (``allUsers`` IAM member) + sensitive
blobs read by data-security's real GCS reader, classified by the real classifier, written to the
graph as the SAME ``CLOUD_RESOURCE{is_public}`` + ``EXPOSES_DATA`` vocabulary (keyed by the ``gs://``
URI). The cloud-agnostic ``KgQuery`` detectors then fire with NO detector change.
"""

import pytest
from charter.canonical import gcs_uri
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.gcs_blob import PUBLIC_MEMBER, GcsBucketSeed, drive_gcs_data_security

_TENANT = "tenant-gcs"
_AWS_KEY = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
_SSN = b"patient ssn 123-45-6789 on file\n"


@pytest.mark.asyncio
async def test_public_gcs_bucket_with_secret_lights_up_path3() -> None:
    buckets = (GcsBucketSeed("creds", iam_members=(PUBLIC_MEMBER,), blobs={"key.txt": _AWS_KEY}),)
    async with in_memory_semantic_store() as store:
        keys = await drive_gcs_data_security(store, tenant_id=_TENANT, buckets=buckets)
        assert keys["creds"] == gcs_uri("creds")
        hits = await KgQuery(store, _TENANT).find_public_secret_exposure()
        assert len(hits) == 1
        assert hits[0].data_type == "aws_access_key"


@pytest.mark.asyncio
async def test_public_unencrypted_gcs_bucket_with_pii_lights_up_path7() -> None:
    buckets = (
        GcsBucketSeed("hr", iam_members=(PUBLIC_MEMBER,), encrypted=False, blobs={"e.csv": _SSN}),
    )
    async with in_memory_semantic_store() as store:
        await drive_gcs_data_security(store, tenant_id=_TENANT, buckets=buckets)
        hits = await KgQuery(store, _TENANT).find_public_unencrypted_exposure()
        assert len(hits) == 1
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_private_gcs_bucket_is_dark() -> None:
    # No public IAM member → private → no EXPOSES_DATA → no hit.
    buckets = (GcsBucketSeed("priv", blobs={"key.txt": _AWS_KEY}),)
    async with in_memory_semantic_store() as store:
        await drive_gcs_data_security(store, tenant_id=_TENANT, buckets=buckets)
        assert await KgQuery(store, _TENANT).find_public_secret_exposure() == []
