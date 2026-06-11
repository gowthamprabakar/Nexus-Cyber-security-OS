"""data-security v0.2 Task 3 — live S3 sampling + privacy contract tests (WI-S8/S9/S12)."""

from __future__ import annotations

import io
from typing import Any

import pytest
from data_security.privacy import (
    PrivacyContractError,
    assert_privacy_contract,
    privacy_hash,
)
from data_security.tools.s3_objects_live import (
    DEFAULT_SAMPLE_RATE,
    S3LiveObjectSampler,
    SampleBasis,
)


class _FakeObjClient:
    def __init__(self, keys: list[str], *, content: bytes = b"hello") -> None:
        self._keys = keys
        self._content = content
        self.fetched: list[str] = []

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
        return {"Contents": [{"Key": k} for k in self._keys], "IsTruncated": False}

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        self.fetched.append(Key)
        return {"Body": io.BytesIO(self._content)}


# ---------------------------- sampling -----------------------------------


def test_default_sample_rate() -> None:
    assert DEFAULT_SAMPLE_RATE == 0.01


def test_samples_at_one_percent() -> None:
    # 100 keys at 1% (stride 100) -> 1 sampled.
    sampler = S3LiveObjectSampler(_FakeObjClient([f"k{i}" for i in range(100)]))
    samples, basis = sampler.sample("b")
    assert len(samples) == 1 and basis.objects_total_estimate == 100


def test_sample_basis_mandatory_shape() -> None:
    sampler = S3LiveObjectSampler(_FakeObjClient([f"k{i}" for i in range(10)]), sample_rate=0.5)
    _, basis = sampler.sample("b")
    assert isinstance(basis, SampleBasis)
    d = basis.to_dict()
    assert set(d) == {"objects_scanned", "objects_total_estimate", "sample_rate"}
    assert d["objects_total_estimate"] == 10 and d["sample_rate"] == 0.5


def test_sampling_is_deterministic() -> None:
    client = _FakeObjClient(
        [f"k{i}" for i in range(20)],
    )
    s1, _ = S3LiveObjectSampler(client, sample_rate=0.25).sample("b")
    s2, _ = S3LiveObjectSampler(
        _FakeObjClient([f"k{i}" for i in range(20)]), sample_rate=0.25
    ).sample("b")
    assert [o.key for o in s1] == [o.key for o in s2]  # stride-based, stable


def test_full_rate_samples_all() -> None:
    samples, basis = S3LiveObjectSampler(_FakeObjClient(["a", "b", "c"]), sample_rate=1.0).sample(
        "x"
    )
    assert len(samples) == 3 and basis.objects_scanned == 3


def test_content_capped_16kib() -> None:
    big = b"x" * (32 * 1024)
    samples, _ = S3LiveObjectSampler(_FakeObjClient(["k"], content=big), sample_rate=1.0).sample(
        "b"
    )
    assert len(samples[0].content_sample) == 16 * 1024


def test_empty_bucket() -> None:
    samples, basis = S3LiveObjectSampler(_FakeObjClient([])).sample("b")
    assert samples == () and basis.objects_scanned == 0


def test_invalid_rate_raises() -> None:
    with pytest.raises(ValueError, match="sample_rate"):
        S3LiveObjectSampler(_FakeObjClient(["a"]), sample_rate=0.0).sample("b")


# ---------------------- privacy contract (WI-S8/S9) -----------------------


def test_privacy_hash_deterministic() -> None:
    assert privacy_hash("secret") == privacy_hash(b"secret")
    assert len(privacy_hash("x")) == 64


def test_assert_privacy_contract_allows_labels() -> None:
    # Labels + hashes are fine.
    assert_privacy_contract(
        {"label": "ssn", "privacy_hash": privacy_hash("123-45-6789"), "count": 3}
    )


def test_assert_privacy_contract_rejects_plaintext_ssn() -> None:
    with pytest.raises(PrivacyContractError, match="plaintext sensitive content"):
        assert_privacy_contract({"sample": "patient SSN is 123-45-6789"})


def test_assert_privacy_contract_rejects_plaintext_in_list() -> None:
    with pytest.raises(PrivacyContractError):
        assert_privacy_contract({"samples": ["clean", "card 4111 1111 1111 1111"]})
