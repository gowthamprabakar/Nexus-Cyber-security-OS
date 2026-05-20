"""``read_s3_objects`` — filesystem ingest for S3 object-content samples.

Reads an operator-staged JSON dump of S3 object samples (bucket + key +
base64-encoded content prefix) and yields ``ObjectSample`` records. Per
ADR-005 the filesystem read happens on ``asyncio.to_thread``; the
wrapper is ``async`` for TaskGroup fan-out from the agent driver.

**Operator workflow.** Per the D.5 v0.1 runbook, operators stage a JSON
file with the shape::

    {"objects": [
        {"bucket": "<name>", "key": "<key>", "content_sample_b64": "..."}
    ]}

where ``content_sample_b64`` is base64-encoded bytes capped at ~16 KiB.
The operator decides which keys to sample (typically a random K from
each bucket, or all keys above a size threshold).

**Q6 privacy contract** (load-bearing). The sample bytes are the input
to the classifier (Task 3). The classifier returns a label only — the
sample bytes are discarded immediately after classification in the
agent driver (Task 12). This reader does NOT persist the sample bytes
anywhere outside the returned ``ObjectSample`` tuple, and downstream
code MUST NOT log or persist them.

D.5 v0.2 replaces this with live boto3 ``get_object`` (range-limited to
16 KiB) behind the same async wrapper signature.

**Forgiving** on malformed entries — a single bad sample is dropped,
not the whole file.
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator


class S3ObjectsReaderError(RuntimeError):
    """The S3 object-sample JSON feed could not be read."""


# v0.1 cap matches PRD §7.1.4 sample-based scanning posture (~16 KiB per
# object). Larger samples increase classifier false-positive surface
# without proportional recall.
MAX_SAMPLE_BYTES = 16 * 1024


class ObjectSample(BaseModel):
    """One S3 object's sampled content + the bucket / key it came from.

    The ``content_sample`` field carries raw bytes for the classifier to
    consume. **Per Q6 the consumer MUST discard these bytes after
    classification.** The reader does not persist them; only the agent
    driver (Task 12) is permitted to hand them to the classifier and
    must then drop the reference.
    """

    bucket: str = Field(min_length=1, max_length=63)
    key: str = Field(min_length=1)
    content_sample: bytes = Field(max_length=MAX_SAMPLE_BYTES)

    @field_validator("content_sample", mode="before")
    @classmethod
    def _decode_b64(cls, value: Any) -> bytes:
        """Accept the wire-format ``content_sample_b64`` string and decode.

        Strict base64 — ``validate=True`` rejects non-base64 input. The
        decoded length is then bounded by the field's ``max_length``.
        """
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            try:
                return base64.b64decode(value, validate=True)
            except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
                raise ValueError(f"content_sample_b64 is not valid base64: {exc}") from exc
        raise ValueError(f"content_sample must be base64 string or bytes; got {type(value)}")

    def decoded_text(self) -> str:
        """Return the sample as decoded UTF-8 text, with replacement on errors.

        The classifier operates on text. Non-text samples (compressed,
        binary, encoded media) lose most signal in this conversion, but
        the classifier handles them safely (UTF-8 replacement chars don't
        match any regex pattern). Returns the empty string for empty
        samples.
        """
        if not self.content_sample:
            return ""
        return self.content_sample.decode("utf-8", errors="replace")


async def read_s3_objects(*, path: Path) -> tuple[ObjectSample, ...]:
    """Read an S3 object-sample JSON dump and return the parsed samples.

    Raises ``S3ObjectsReaderError`` if the file is missing, not a file,
    or malformed JSON. Individual samples that fail validation (bad
    base64, exceed the 16 KiB cap, missing bucket/key) are dropped
    silently.

    The reader is pure I/O: no classifier calls, no detector logic, no
    side effects beyond the filesystem read.
    """
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[ObjectSample, ...]:
    if not path.exists():
        raise S3ObjectsReaderError(f"s3 objects json not found: {path}")
    if not path.is_file():
        raise S3ObjectsReaderError(f"s3 objects json is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except json.JSONDecodeError as exc:
        raise S3ObjectsReaderError(f"s3 objects json is malformed: {exc}") from exc

    raw_records = _extract_records(blob)
    out: list[ObjectSample] = []
    for raw in raw_records:
        rec = _try_parse(raw)
        if rec is not None:
            out.append(rec)
    return tuple(out)


def _extract_records(blob: Any) -> list[dict[str, Any]]:
    """Pull the list of object dicts out of the top-level JSON.

    Supports ``{"objects": [...]}`` (canonical) or a bare list.
    """
    if isinstance(blob, dict):
        if "objects" in blob:
            objects = blob["objects"]
            if isinstance(objects, list):
                return [o for o in objects if isinstance(o, dict)]
        return []
    if isinstance(blob, list):
        return [o for o in blob if isinstance(o, dict)]
    return []


def _try_parse(raw: dict[str, Any]) -> ObjectSample | None:
    """Parse one raw object dict; return None if validation fails.

    The wire field is ``content_sample_b64`` but the model field is
    ``content_sample`` (decoded). Rewrite the key before validation
    so pydantic's field-aliasing isn't needed.
    """
    raw = dict(raw)
    if "content_sample_b64" in raw and "content_sample" not in raw:
        raw["content_sample"] = raw.pop("content_sample_b64")
    try:
        return ObjectSample.model_validate(raw)
    except ValidationError:
        return None
