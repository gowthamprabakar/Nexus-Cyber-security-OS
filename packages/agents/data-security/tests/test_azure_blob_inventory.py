"""data-security v0.2 Task 5 — live Azure Blob Storage inventory + sampling tests."""

from __future__ import annotations

from typing import Any

from data_security.tools.azure_blob_inventory import (
    AzureBlobContainer,
    AzureBlobLiveReader,
)
from data_security.tools.s3_objects_live import SampleBasis

_ACCT = "mystorageacct"


class _FakeAzure:
    def __init__(self, containers: list[dict[str, Any]], *, blobs: list[str] | None = None) -> None:
        self._containers = containers
        self._blobs = blobs or []

    def list_containers(self) -> list[dict[str, Any]]:
        return self._containers

    def list_blobs(self, *, container: str) -> list[dict[str, Any]]:
        return [{"name": b} for b in self._blobs]

    def download_blob(self, *, container: str, blob: str) -> bytes:
        return b"content"


def test_reads_containers() -> None:
    reader = AzureBlobLiveReader(
        _FakeAzure(
            [{"name": "c1"}, {"name": "c2", "public_access": "container", "encrypted": False}]
        ),
        storage_account=_ACCT,
        region="westeurope",
    )
    out = reader.read()
    assert len(out) == 2 and all(isinstance(c, AzureBlobContainer) for c in out)
    assert {c.container for c in out} == {"c1", "c2"}


def test_container_posture() -> None:
    reader = AzureBlobLiveReader(
        _FakeAzure([{"name": "c2", "public_access": "container", "encrypted": False}]),
        storage_account=_ACCT,
        region="westeurope",
    )
    [c] = reader.read()
    assert c.storage_account == _ACCT and c.region == "westeurope"
    assert c.is_public is True and c.encrypted is False


def test_private_container_not_public() -> None:
    [c] = AzureBlobLiveReader(_FakeAzure([{"name": "c"}]), storage_account=_ACCT, region="x").read()
    assert c.is_public is False and c.encrypted is True  # defaults


def test_blob_public_access_level() -> None:
    [c] = AzureBlobLiveReader(
        _FakeAzure([{"name": "c", "public_access": "blob"}]), storage_account=_ACCT, region="x"
    ).read()
    assert c.is_public is True


def test_no_name_container_skipped() -> None:
    out = AzureBlobLiveReader(
        _FakeAzure([{"noname": "x"}, {"name": "good"}]), storage_account=_ACCT, region="x"
    ).read()
    assert [c.container for c in out] == ["good"]


def test_sampling() -> None:
    reader = AzureBlobLiveReader(
        _FakeAzure([{"name": "c"}], blobs=[f"b{i}" for i in range(100)]),
        storage_account=_ACCT,
        region="x",
    )
    samples, basis = reader.sample("c")
    assert len(samples) == 1  # 1% of 100
    assert isinstance(basis, SampleBasis) and basis.objects_total_estimate == 100
    assert samples[0].bucket == "c" and samples[0].content_sample == b"content"


def test_sample_full_rate() -> None:
    reader = AzureBlobLiveReader(
        _FakeAzure([{"name": "c"}], blobs=["a", "b"]),
        storage_account=_ACCT,
        region="x",
        sample_rate=1.0,
    )
    samples, basis = reader.sample("c")
    assert len(samples) == 2 and basis.objects_scanned == 2


def test_sample_basis_shape() -> None:
    reader = AzureBlobLiveReader(
        _FakeAzure([{"name": "c"}], blobs=["a"]), storage_account=_ACCT, region="x"
    )
    _, basis = reader.sample("c")
    assert set(basis.to_dict()) == {"objects_scanned", "objects_total_estimate", "sample_rate"}


def test_empty_account() -> None:
    assert AzureBlobLiveReader(_FakeAzure([]), storage_account=_ACCT, region="x").read() == ()
