"""data-security v0.2 Task 6 — live GCS bucket inventory + sampling tests."""

from __future__ import annotations

from typing import Any

from data_security.tools.gcs_inventory import GcsBucket, GcsLiveReader
from data_security.tools.s3_objects_live import SampleBasis

_PROJ = "my-project"


class _FakeGcs:
    def __init__(self, buckets: list[dict[str, Any]], *, blobs: list[str] | None = None) -> None:
        self._buckets = buckets
        self._blobs = blobs or []

    def list_buckets(self) -> list[dict[str, Any]]:
        return self._buckets

    def list_blobs(self, *, bucket: str) -> list[dict[str, Any]]:
        return [{"name": b} for b in self._blobs]

    def download_blob(self, *, bucket: str, blob: str) -> bytes:
        return b"data"


def test_reads_buckets() -> None:
    out = GcsLiveReader(_FakeGcs([{"name": "b1"}, {"name": "b2"}]), project=_PROJ).read()
    assert len(out) == 2 and all(isinstance(b, GcsBucket) for b in out)
    assert {b.name for b in out} == {"b1", "b2"}


def test_public_via_all_users() -> None:
    [b] = GcsLiveReader(
        _FakeGcs([{"name": "b", "iam_members": ["allUsers"]}]), project=_PROJ
    ).read()
    assert b.is_public is True


def test_public_via_all_authenticated() -> None:
    [b] = GcsLiveReader(
        _FakeGcs([{"name": "b", "iam_members": ["allAuthenticatedUsers"]}]), project=_PROJ
    ).read()
    assert b.is_public is True


def test_private_bucket() -> None:
    [b] = GcsLiveReader(
        _FakeGcs([{"name": "b", "iam_members": ["user:alice@example.com"]}]), project=_PROJ
    ).read()
    assert b.is_public is False


def test_location_and_project() -> None:
    [b] = GcsLiveReader(_FakeGcs([{"name": "b", "location": "EU"}]), project=_PROJ).read()
    assert b.location == "EU" and b.project == _PROJ


def test_encryption_default_true() -> None:
    [b] = GcsLiveReader(_FakeGcs([{"name": "b"}]), project=_PROJ).read()
    assert b.encrypted is True


def test_no_name_skipped() -> None:
    out = GcsLiveReader(_FakeGcs([{"x": 1}, {"name": "good"}]), project=_PROJ).read()
    assert [b.name for b in out] == ["good"]


def test_sampling() -> None:
    reader = GcsLiveReader(
        _FakeGcs([{"name": "b"}], blobs=[f"o{i}" for i in range(100)]), project=_PROJ
    )
    samples, basis = reader.sample("b")
    assert len(samples) == 1 and basis.objects_total_estimate == 100
    assert samples[0].content_sample == b"data"


def test_sample_basis_shape() -> None:
    reader = GcsLiveReader(_FakeGcs([{"name": "b"}], blobs=["a"]), project=_PROJ)
    _, basis = reader.sample("b")
    assert isinstance(basis, SampleBasis)
    assert set(basis.to_dict()) == {"objects_scanned", "objects_total_estimate", "sample_rate"}


def test_empty_project() -> None:
    assert GcsLiveReader(_FakeGcs([]), project=_PROJ).read() == ()
