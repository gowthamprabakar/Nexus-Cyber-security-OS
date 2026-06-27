"""Path 7 (public + unencrypted + sensitive) committed moto e2e.

Proves the path-7 chain REAL through the agents' own code: a real boto3 S3 client
(under moto) is read by data-security's *live* inventory reader (a default moto bucket
is unencrypted → ``is_encrypted=False``), the *real* classifier detects PII in the real
object bytes, the *real* ``kg_writer.record`` persists the storage node + EXPOSES_DATA
edge, and ``KgQuery.find_public_unencrypted_exposure`` lights up. No fixtures, no fake S3,
no hand-supplied hits. moto is in-process → runs unskipped in normal CI.
"""

import pytest
from meta_harness.kg_query import KgQuery

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.moto_aws import moto_s3

_TENANT = "tenant-path7"
_SSN = b"patient ssn 123-45-6789 on file\n"


async def _run(buckets: tuple[MotoBucket, ...]) -> list:
    async with in_memory_semantic_store() as store:
        with moto_s3(buckets) as s3:
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
        return await KgQuery(store, _TENANT).find_public_unencrypted_exposure()


@pytest.mark.asyncio
async def test_public_unencrypted_bucket_with_pii_lights_up_one_exposure() -> None:
    # Default moto bucket has no SSE → data-security reads is_encrypted=False.
    buckets = (MotoBucket("acme-clear-pii", public=True, objects={"hr.txt": _SSN}),)
    hits = await _run(buckets)
    assert len(hits) == 1
    assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_private_unencrypted_bucket_is_dark() -> None:
    # Same unencrypted PII, but a private bucket → no EXPOSES_DATA edge → no path-7 hit.
    buckets = (MotoBucket("acme-clear-pii", public=False, objects={"hr.txt": _SSN}),)
    assert await _run(buckets) == []
