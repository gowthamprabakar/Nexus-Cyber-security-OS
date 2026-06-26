"""Path 10 (exposed AI service + sensitive training data) committed moto e2e — REAL.

Proves the chain through the agents' own code:

- a moto SageMaker endpoint is NOT network-isolated (exposed) and its model reads from the
  ``acme-pii`` S3 bucket. data-security's real S3 path makes ``acme-pii`` a public-PII bucket
  (EXPOSES_DATA).
- aispm's real reader extracts the endpoint's exposure + model-data bucket; the real
  ``record_aws`` writes AI_SERVICE + EXPOSES_MODEL → internet + HAS_ACCESS_TO → the bucket.
- ``KgQuery.find_exposed_ai_with_sensitive_data`` lights up the exposed-model→sensitive-data path.

Honest constraint: data-security only writes EXPOSES_DATA for PUBLIC buckets, so the REAL
join is "exposed model + public sensitive training bucket" — a genuine double exposure. moto
is in-process → unskipped CI.
"""

import pytest
from charter.canonical import s3_bucket_arn
from charter.memory.graph_types import NodeCategory
from meta_harness.kg_query import KgQuery

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.moto_aws import drive_aispm, moto_ai_clients, setup_sagemaker_endpoint

_TENANT = "tenant-path10"
_SSN = b"patient ssn 123-45-6789 on file\n"
_BUCKET = "acme-pii"


@pytest.mark.asyncio
async def test_exposed_endpoint_with_public_pii_training_bucket_lights_up() -> None:
    buckets = (MotoBucket(_BUCKET, public=True, objects={"train.txt": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_ai_clients(buckets) as (s3, sm):
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            setup_sagemaker_endpoint(
                sm, name="infer", model_data_bucket=_BUCKET, network_isolated=False
            )
            await drive_aispm(store, tenant_id=_TENANT, sm_client=sm)

        hits = await KgQuery(store, _TENANT).find_exposed_ai_with_sensitive_data()
        assert len(hits) == 1
        assert hits[0].resource_id is not None
        assert hits[0].data_type == "ssn"
        # The bucket leg resolved to the canonical spine ARN data-security wrote.
        rows = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        assert any(r.external_id == s3_bucket_arn(_BUCKET) for r in rows)


@pytest.mark.asyncio
async def test_private_training_bucket_is_dark() -> None:
    # Exposed endpoint, but a PRIVATE training bucket → no EXPOSES_DATA → not sensitive → dark.
    # (The network-isolated negative lives in aispm's own unit tests; moto can't represent
    #  EnableNetworkIsolation=True — it always reports False.)
    buckets = (MotoBucket(_BUCKET, public=False, objects={"train.txt": _SSN}),)
    async with in_memory_semantic_store() as store:
        with moto_ai_clients(buckets) as (s3, sm):
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            setup_sagemaker_endpoint(
                sm, name="infer", model_data_bucket=_BUCKET, network_isolated=False
            )
            await drive_aispm(store, tenant_id=_TENANT, sm_client=sm)

        assert await KgQuery(store, _TENANT).find_exposed_ai_with_sensitive_data() == []
