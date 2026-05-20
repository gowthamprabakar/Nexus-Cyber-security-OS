"""Tests — ``data_security.tools.s3_objects``.

Task 4. Verifies the S3 object-sample reader:

- Happy-path parse (canonical ``{"objects": [...]}`` shape, bare list).
- Base64 decode round-trips correctly.
- Wire field ``content_sample_b64`` decodes into model field
  ``content_sample`` (bytes).
- 16 KiB sample cap enforced.
- Bad base64 → entry dropped (forgiving).
- Missing file / not-a-file / malformed JSON → raises.
- ``decoded_text`` handles non-UTF-8 with replacement (no crash).
- Q6 reminder: the reader does not log / persist sample bytes
  anywhere outside the returned tuple.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from data_security.tools.s3_objects import (
    MAX_SAMPLE_BYTES,
    ObjectSample,
    S3ObjectsReaderError,
    read_s3_objects,
)


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _write_json(tmp_path: Path, content: object) -> Path:
    path = tmp_path / "objects.json"
    path.write_text(json.dumps(content), encoding="utf-8")
    return path


def _well_formed_object(
    bucket: str = "alpha", key: str = "data/file.txt", payload: bytes = b"hello"
) -> dict[str, object]:
    return {"bucket": bucket, "key": key, "content_sample_b64": _b64(payload)}


# ---------------------------------------------------------------------------
# Happy-path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reads_canonical_objects_shape(tmp_path: Path) -> None:
    payload_1 = b"first sample"
    payload_2 = b"second sample"
    path = _write_json(
        tmp_path,
        {
            "objects": [
                _well_formed_object("alpha", "k1", payload_1),
                _well_formed_object("alpha", "k2", payload_2),
            ]
        },
    )
    result = await read_s3_objects(path=path)
    assert len(result) == 2
    assert result[0].content_sample == payload_1
    assert result[1].content_sample == payload_2


@pytest.mark.asyncio
async def test_reads_bare_list_shape(tmp_path: Path) -> None:
    path = _write_json(tmp_path, [_well_formed_object(payload=b"solo")])
    result = await read_s3_objects(path=path)
    assert len(result) == 1
    assert result[0].content_sample == b"solo"


@pytest.mark.asyncio
async def test_empty_objects_returns_empty_tuple(tmp_path: Path) -> None:
    path = _write_json(tmp_path, {"objects": []})
    result = await read_s3_objects(path=path)
    assert result == ()


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(S3ObjectsReaderError, match="not found"):
        await read_s3_objects(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_directory_path_raises(tmp_path: Path) -> None:
    with pytest.raises(S3ObjectsReaderError, match="not a file"):
        await read_s3_objects(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not valid", encoding="utf-8")
    with pytest.raises(S3ObjectsReaderError, match="malformed"):
        await read_s3_objects(path=path)


# ---------------------------------------------------------------------------
# Forgiving parse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drops_bad_base64_keeps_good_ones(tmp_path: Path) -> None:
    """An entry with invalid base64 is dropped silently."""
    path = _write_json(
        tmp_path,
        {
            "objects": [
                _well_formed_object("good", "k1", b"valid"),
                {"bucket": "bad", "key": "k", "content_sample_b64": "@@@not-base64@@@"},
                _well_formed_object("good", "k2", b"also valid"),
            ]
        },
    )
    result = await read_s3_objects(path=path)
    assert len(result) == 2
    assert all(s.bucket == "good" for s in result)


@pytest.mark.asyncio
async def test_drops_missing_required_fields(tmp_path: Path) -> None:
    """Entries missing ``bucket`` / ``key`` / ``content_sample_b64`` are dropped."""
    path = _write_json(
        tmp_path,
        {
            "objects": [
                _well_formed_object("good"),
                {"bucket": "no-key", "content_sample_b64": _b64(b"x")},
                {"key": "no-bucket", "content_sample_b64": _b64(b"x")},
                {"bucket": "no-content", "key": "k"},
            ]
        },
    )
    result = await read_s3_objects(path=path)
    assert len(result) == 1
    assert result[0].bucket == "good"


@pytest.mark.asyncio
async def test_drops_oversized_sample(tmp_path: Path) -> None:
    """Samples over 16 KiB are dropped (per the documented MAX_SAMPLE_BYTES)."""
    oversized = b"x" * (MAX_SAMPLE_BYTES + 1)
    path = _write_json(
        tmp_path,
        {
            "objects": [
                _well_formed_object("good", "small", b"ok"),
                {"bucket": "too-big", "key": "k", "content_sample_b64": _b64(oversized)},
            ]
        },
    )
    result = await read_s3_objects(path=path)
    assert len(result) == 1
    assert result[0].bucket == "good"


# ---------------------------------------------------------------------------
# Cap is exactly 16 KiB
# ---------------------------------------------------------------------------


def test_max_sample_bytes_is_16_kib() -> None:
    """Documented cap per PRD §7.1.4 sample-based scanning."""
    assert MAX_SAMPLE_BYTES == 16 * 1024


@pytest.mark.asyncio
async def test_exactly_16_kib_sample_accepted(tmp_path: Path) -> None:
    """Boundary: exactly 16 KiB must be accepted."""
    payload = b"x" * MAX_SAMPLE_BYTES
    path = _write_json(
        tmp_path,
        {"objects": [{"bucket": "edge", "key": "k", "content_sample_b64": _b64(payload)}]},
    )
    result = await read_s3_objects(path=path)
    assert len(result) == 1
    assert len(result[0].content_sample) == MAX_SAMPLE_BYTES


# ---------------------------------------------------------------------------
# decoded_text behaviour
# ---------------------------------------------------------------------------


def test_decoded_text_empty_sample_returns_empty_string() -> None:
    sample = ObjectSample(bucket="b", key="k", content_sample=b"")
    assert sample.decoded_text() == ""


def test_decoded_text_utf8_round_trips() -> None:
    sample = ObjectSample(bucket="b", key="k", content_sample=b"hello")
    assert sample.decoded_text() == "hello"


def test_decoded_text_non_utf8_uses_replacement() -> None:
    """Non-UTF-8 bytes get replaced rather than raising — classifier reads
    text only, so binary samples produce mostly-replacement output that
    the regex patterns won't match.
    """
    sample = ObjectSample(bucket="b", key="k", content_sample=b"\xff\xfe valid")
    text = sample.decoded_text()
    assert "valid" in text  # the valid suffix survives
    assert "�" in text  # UTF-8 replacement char inserted


@pytest.mark.asyncio
async def test_decoded_text_classifier_smoke(tmp_path: Path) -> None:
    """Smoke test: the reader → ``decoded_text`` → classifier composition works.

    Q6 reminder: in production, after this call the agent driver MUST
    discard the sample bytes. Test scope: just confirms the pipeline
    types compose correctly.
    """
    from data_security.classifiers import classify
    from data_security.schemas import ClassifierLabel

    path = _write_json(
        tmp_path,
        {
            "objects": [
                {
                    "bucket": "test",
                    "key": "data.csv",
                    "content_sample_b64": _b64(
                        b"name,email,ssn\nalice,alice@example.com,123-45-6789"
                    ),
                }
            ]
        },
    )
    result = await read_s3_objects(path=path)
    assert len(result) == 1
    # Classifier on the decoded sample returns SSN (highest precedence
    # match in this payload).
    label = classify(result[0].decoded_text())
    assert label == ClassifierLabel.SSN
