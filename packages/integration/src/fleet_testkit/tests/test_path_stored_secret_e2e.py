"""W6 e2e — a public workload's embedded credential's blast radius emerges.

A public ECS service embeds a long-lived AWS key belonging to an over-permissioned user. Drives the
REAL cloud-posture detector + writer (STORES_SECRET) and identity (OWNED_BY owner + access), proving:
``public workload --STORES_SECRET--> secret --OWNED_BY--> identity --HAS_ACCESS_TO--> data``.

GCP extension: the same path shape fires when the workload embeds a GCP SA key blob. The fingerprint
``secret_fingerprint(private_key_id)`` is the convergence key — cloud-posture STORES_SECRET and
identity OWNED_BY both hash the same ``private_key_id``, collapsing onto one SECRET node.
"""

import json

import pytest
from charter.canonical import gcs_uri, secret_fingerprint
from charter.memory.graph_types import EdgeType, NodeCategory
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CloudKgWriter
from cloud_posture.tools.stored_secrets import gcp_stored_secret_grants, stored_secret_grants
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from identity.tools.gcp_iam import GcpServiceAccountKey, sa_key_ownership
from meta_harness.kg_query import KgQuery, StoredSecretToData

from fleet_testkit import in_memory_semantic_store

_T = "tenant-stored"
_SVC = "arn:aws:ecs:us-east-1:111:service/web"
_KEY = "AKIA" + "EXAMPLE0STORED99"
_USER = "arn:aws:iam::111:user/ci"
_BUCKET = "arn:aws:s3:::crown"

# GCP e2e fixtures
_T_GCP = "tenant-stored-gcp"
_GCP_SVC = "arn:aws:ecs:us-east-1:111:service/gcp-workload"
_GCP_SA = "ci-sa@my-project.iam.gserviceaccount.com"
_GCP_KEY_ID = "deadbeef1234567890deadbeef12345678901234"
_GCP_BUCKET = gcs_uri("gcp-crown")
_GCP_SA_KEY_JSON = json.dumps(
    {
        "type": "service_account",
        "project_id": "my-project",
        "private_key_id": _GCP_KEY_ID,
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIFAKE\n-----END RSA PRIVATE KEY-----\n",
        "client_email": _GCP_SA,
        "client_id": "987654321",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
)


@pytest.mark.asyncio
async def test_stored_credential_blast_radius_emerges() -> None:
    grants = stored_secret_grants([(_SVC, [f"AWS_ACCESS_KEY_ID={_KEY}"])])
    async with in_memory_semantic_store() as store:
        cloud = CloudKgWriter(store, _T)
        # the public workload + the STORES_SECRET edge
        await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_SVC,
            properties={"is_public": True},
        )
        await cloud.record_stored_secrets(grants)
        # identity: that key is owned by ci, who can read the crown bucket
        ident = IdentityKgWriter(store, _T)
        await ident.record_credential_ownership([(_USER, _KEY)])  # writes OWNS + OWNED_BY
        await ident.record_access([(_USER, _BUCKET)])
        bucket = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_BUCKET,
            properties={},
        )
        data = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{_BUCKET}/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=bucket,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        kq = KgQuery(store, _T)
        hits = await kq.find_stored_secret_to_data()
        assert hits, "a public workload's embedded credential reaching data must surface"
        assert isinstance(hits[0], StoredSecretToData)
        assert hits[0].workload_id is not None
        assert hits[0].secret_id is not None
        assert hits[0].principal_id is not None
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_gcp_stored_sa_key_blast_radius_emerges() -> None:
    """GCP SA key in workload env → find_stored_secret_to_data fires (convergence e2e).

    cloud-posture: ``gcp_stored_secret_grants`` detects the SA key JSON blob and emits
    ``(workload_arn, secret_fingerprint(private_key_id))``.  cloud-posture kg_writer writes
    ``CLOUD_RESOURCE --STORES_SECRET--> SECRET(fp)``.

    identity: ``record_sa_credential_ownership`` writes ``SA --OWNS--> SECRET(fp)`` and
    ``SECRET(fp) --OWNED_BY--> SA``.  Both sides hash the SAME ``private_key_id`` so they
    converge on ONE SECRET node — nothing readable stored.

    The walk ``workload --STORES_SECRET--> SECRET(fp) --OWNED_BY--> SA --HAS_ACCESS_TO-->
    bucket --EXPOSES_DATA--> data`` then fires ``find_stored_secret_to_data``.
    """
    gcp_grants = gcp_stored_secret_grants([(_GCP_SVC, [_GCP_SA_KEY_JSON])])
    assert gcp_grants, "gcp_stored_secret_grants must detect the SA key"
    expected_fp = secret_fingerprint(_GCP_KEY_ID)
    assert gcp_grants[0] == (_GCP_SVC, expected_fp)

    sa_grants = sa_key_ownership((GcpServiceAccountKey(_GCP_SA, _GCP_KEY_ID),))

    async with in_memory_semantic_store() as store:
        cloud = CloudKgWriter(store, _T_GCP)
        # workload node + STORES_SECRET edge (the new GCP producer)
        await store.upsert_entity(
            tenant_id=_T_GCP,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_GCP_SVC,
            properties={"is_public": True},
        )
        await cloud.record_gcp_stored_secrets(gcp_grants)

        # identity: SA owns the same fingerprint + has access to the GCP bucket
        ident = IdentityKgWriter(store, _T_GCP)
        await ident.record_sa_credential_ownership(sa_grants)
        await ident.record_access([(_GCP_SA, _GCP_BUCKET)])

        # data: bucket exposes PII
        bucket = await store.upsert_entity(
            tenant_id=_T_GCP,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_GCP_BUCKET,
            properties={},
        )
        data = await store.upsert_entity(
            tenant_id=_T_GCP,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{_GCP_BUCKET}/pii",
            properties={"data_type": "pii"},
        )
        await store.add_relationship(
            tenant_id=_T_GCP,
            src_entity_id=bucket,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        kq = KgQuery(store, _T_GCP)
        hits = await kq.find_stored_secret_to_data()
        assert hits, (
            "find_stored_secret_to_data must fire for a GCP SA key stored in a workload env "
            "when that SA owns the fingerprint and has access to PII data"
        )
        hit = hits[0]
        assert isinstance(hit, StoredSecretToData)
        assert hit.data_type == "pii"
        # All path legs must be resolved (internal entity IDs are ULIDs, not external ids).
        assert hit.workload_id is not None
        assert hit.secret_id is not None
        assert hit.principal_id is not None
        assert hit.resource_id is not None


@pytest.mark.asyncio
async def test_gcp_stored_sa_key_non_owned_fingerprint_no_hit() -> None:
    """Negative: a workload storing a GCP SA key with a fingerprint NOT owned by any SA → no hit.

    Proves convergence (not coincidence): the STORES_SECRET leg alone does not fire; the
    OWNED_BY leg from identity is required to complete the path.
    """
    gcp_grants = gcp_stored_secret_grants([(_GCP_SVC, [_GCP_SA_KEY_JSON])])
    # Deliberately do NOT write any sa_key_ownership — no OWNED_BY edge.

    async with in_memory_semantic_store() as store:
        cloud = CloudKgWriter(store, _T_GCP)
        await store.upsert_entity(
            tenant_id=_T_GCP,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_GCP_SVC,
            properties={"is_public": True},
        )
        await cloud.record_gcp_stored_secrets(gcp_grants)

        # SA has access to data — but the SA's key is NOT recorded as owning the stored fingerprint.
        ident = IdentityKgWriter(store, _T_GCP)
        await ident.record_access([(_GCP_SA, _GCP_BUCKET)])
        bucket = await store.upsert_entity(
            tenant_id=_T_GCP,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_GCP_BUCKET,
            properties={},
        )
        data = await store.upsert_entity(
            tenant_id=_T_GCP,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id=f"{_GCP_BUCKET}/pii",
            properties={"data_type": "pii"},
        )
        await store.add_relationship(
            tenant_id=_T_GCP,
            src_entity_id=bucket,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )

        kq = KgQuery(store, _T_GCP)
        hits = await kq.find_stored_secret_to_data()
        assert not hits, (
            "find_stored_secret_to_data must NOT fire when there is no OWNED_BY edge "
            "connecting the stored fingerprint to the SA (convergence, not coincidence)"
        )
