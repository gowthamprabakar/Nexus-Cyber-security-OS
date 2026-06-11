"""data-security v0.2 Task 7 — unified multi-cloud data-source view tests."""

from __future__ import annotations

from data_security.tools.azure_blob_inventory import AzureBlobContainer
from data_security.tools.data_source import (
    DataCloud,
    cross_cloud_replicas,
    from_azure,
    from_gcs,
    from_s3,
    unify,
)
from data_security.tools.gcs_inventory import GcsBucket
from data_security.tools.s3_inventory import BucketAcl, BucketEncryption, BucketInventory


def _s3(name: str, *, public: bool = False, enc: str = "AES256") -> BucketInventory:
    acl = BucketAcl(grants_all_users=["READ"]) if public else BucketAcl()
    return BucketInventory(
        name=name,
        region="eu-west-1",
        account_id="111122223333",
        acl=acl,
        encryption=BucketEncryption(algorithm=enc),
    )


def _azure(account: str, container: str, *, public: bool = False) -> AzureBlobContainer:
    return AzureBlobContainer(
        storage_account=account,
        container=container,
        region="westeurope",
        public_access="container" if public else "none",
    )


def _gcs(name: str, *, public: bool = False) -> GcsBucket:
    return GcsBucket(
        project="p",
        name=name,
        location="EU",
        iam_members=("allUsers",) if public else (),
    )


def test_from_s3() -> None:
    ds = from_s3(_s3("data", public=True, enc="NONE"))
    assert ds.cloud == DataCloud.AWS and ds.identifier == "data"
    assert ds.is_public is True and ds.is_encrypted is False


def test_from_azure() -> None:
    ds = from_azure(_azure("acct", "logs", public=True))
    assert ds.cloud == DataCloud.AZURE and ds.identifier == "acct/logs"
    assert ds.logical_name == "logs" and ds.is_public is True


def test_from_gcs() -> None:
    ds = from_gcs(_gcs("backups"))
    assert ds.cloud == DataCloud.GCP and ds.is_encrypted is True and ds.is_public is False


def test_unify_all_three() -> None:
    sources = unify(s3=[_s3("a")], azure=[_azure("acct", "b")], gcs=[_gcs("c")])
    assert len(sources) == 3
    assert {s.cloud for s in sources} == {DataCloud.AWS, DataCloud.AZURE, DataCloud.GCP}


def test_cross_cloud_replica_detected() -> None:
    # Same logical name "backups" across AWS + GCP -> a replica group.
    sources = unify(s3=[_s3("backups")], gcs=[_gcs("backups")], azure=[_azure("acct", "other")])
    replicas = cross_cloud_replicas(sources)
    assert len(replicas) == 1
    name, group = replicas[0]
    assert name == "backups" and {s.cloud for s in group} == {DataCloud.AWS, DataCloud.GCP}


def test_no_replica_when_single_cloud() -> None:
    sources = unify(s3=[_s3("a"), _s3("a-2")], gcs=[_gcs("b")])
    assert cross_cloud_replicas(sources) == []


def test_logical_name_from_azure_path() -> None:
    assert from_azure(_azure("acct", "Backups")).logical_name == "backups"


def test_empty_unify() -> None:
    assert unify() == () and cross_cloud_replicas([]) == []
