"""Path 3 (public-secret-exposure) committed moto e2e.

Proves the moat's path-3 attack chain REAL through the agents' own code: a real
boto3 S3 client (under moto) is read by data-security's *live* inventory reader +
object sampler, the *real* classifier runs on the actual object bytes, the *real*
``kg_writer.record`` persists the storage + DATA_CLASSIFICATION + EXPOSES_DATA edge,
and ``KgQuery.find_public_secret_exposure`` lights up. No fixtures, no fake S3, no
hand-supplied classifier hits — the AKIA secret is detected from real bytes.

moto is in-process, so this runs unskipped in normal CI.
"""

import pytest
from meta_harness.kg_query import KgQuery

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.moto_aws import moto_s3

_TENANT = "tenant-path3"
_AWS_ACCESS_KEY = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
_SSN = b"patient ssn 123-45-6789 on file\n"


async def _run(buckets: tuple[MotoBucket, ...]) -> list:
    async with in_memory_semantic_store() as store:
        with moto_s3(buckets) as s3:
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
        return await KgQuery(store, _TENANT).find_public_secret_exposure()


@pytest.mark.asyncio
async def test_public_bucket_with_aws_key_lights_up_one_exposure() -> None:
    buckets = (MotoBucket("acme-secrets", public=True, objects={"creds.txt": _AWS_ACCESS_KEY}),)
    hits = await _run(buckets)
    assert len(hits) == 1
    assert hits[0].data_type == "aws_access_key"


@pytest.mark.asyncio
async def test_private_bucket_with_aws_key_is_dark() -> None:
    # Same secret body, but a private bucket → no EXPOSES_DATA edge → no path-3 hit.
    buckets = (MotoBucket("acme-secrets", public=False, objects={"creds.txt": _AWS_ACCESS_KEY}),)
    assert await _run(buckets) == []


@pytest.mark.asyncio
async def test_public_bucket_with_only_ssn_is_dark_for_path3() -> None:
    # PII (SSN) is not a secret-type classification → path 3 stays dark (that is path 1).
    buckets = (MotoBucket("acme-pii", public=True, objects={"records.txt": _SSN}),)
    assert await _run(buckets) == []
