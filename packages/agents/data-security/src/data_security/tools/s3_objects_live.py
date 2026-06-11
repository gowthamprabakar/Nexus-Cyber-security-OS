"""Live AWS S3 object sampling (data-security v0.2 Task 3).

The v0.2 live counterpart to the offline ``read_s3_objects``. Lists a bucket's objects and
samples a configurable fraction (**Q4** — default 1%, contract-overridable), reading up to
16 KiB per sampled object into the same ``ObjectSample`` shape the classifier consumes.

Sampling is **deterministic** (stride-based — every Nth key), so a re-scan of an unchanged
bucket samples the same objects. Per **WI-S12** every sample run emits a mandatory
``SampleBasis`` (objects_scanned / objects_total_estimate / sample_rate) so the operator
knows exactly what was scanned vs estimated. The S3 client is injectable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from data_security.tools.s3_objects import MAX_SAMPLE_BYTES, ObjectSample

DEFAULT_SAMPLE_RATE = 0.01


class S3ObjectClient(Protocol):
    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]: ...
    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class SampleBasis:
    objects_scanned: int
    objects_total_estimate: int
    sample_rate: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "objects_scanned": self.objects_scanned,
            "objects_total_estimate": self.objects_total_estimate,
            "sample_rate": self.sample_rate,
        }


def _stride(sample_rate: float) -> int:
    if sample_rate >= 1.0:
        return 1
    if sample_rate <= 0.0:
        raise ValueError("sample_rate must be > 0")
    return max(1, round(1.0 / sample_rate))


def _list_keys(client: S3ObjectClient, bucket: str) -> list[str]:
    keys: list[str] = []
    token: str | None = None
    while True:
        kwargs: dict[str, Any] = {"Bucket": bucket}
        if token:
            kwargs["ContinuationToken"] = token
        resp = client.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []) if isinstance(resp.get("Contents"), list) else []:
            if isinstance(obj, dict) and isinstance(obj.get("Key"), str):
                keys.append(obj["Key"])
        token = resp.get("NextContinuationToken") if resp.get("IsTruncated") else None
        if not token:
            break
    return keys


class S3LiveObjectSampler:
    """Samples a fraction of a bucket's objects into `ObjectSample`s (+ a `SampleBasis`)."""

    __slots__ = ("_client", "_sample_rate")

    def __init__(self, client: S3ObjectClient, *, sample_rate: float = DEFAULT_SAMPLE_RATE) -> None:
        self._client = client
        self._sample_rate = sample_rate

    def sample(self, bucket: str) -> tuple[tuple[ObjectSample, ...], SampleBasis]:
        """List ``bucket``, select every Nth key (N from the rate), read ≤16 KiB each."""
        keys = _list_keys(self._client, bucket)
        selected = keys[:: _stride(self._sample_rate)]
        samples: list[ObjectSample] = []
        for key in selected:
            body: Any = self._client.get_object(Bucket=bucket, Key=key).get("Body")
            raw = body.read() if hasattr(body, "read") else body
            content = raw if isinstance(raw, bytes) else (bytes(raw) if raw else b"")
            samples.append(
                ObjectSample(bucket=bucket, key=key, content_sample=content[:MAX_SAMPLE_BYTES])
            )
        basis = SampleBasis(
            objects_scanned=len(samples),
            objects_total_estimate=len(keys),
            sample_rate=self._sample_rate,
        )
        return tuple(samples), basis
