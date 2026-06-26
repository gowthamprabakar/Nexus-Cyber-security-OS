"""Known detection gaps — characterization tests that document where the detectors MISS.

The capability banks measure precision/recall on cases the detectors handle. This file does the
opposite: it pins the *boundaries* — realistic inputs we currently miss — so a gap is visible and
tracked, not hidden behind a green bank. Each assertion documents a real limitation; if a gap is
ever closed (a detector starts catching the input), the matching assertion fails on purpose,
prompting an update to docs/strategy/detection-gaps.md.

These are honest counter-evidence to the banks' 1.000 scores: the scores are 1.000 *on the bank*,
with the documented out-of-bank gaps below.
"""

import base64
import gzip

import pytest
from meta_harness.kg_query import KgQuery

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.moto_aws import moto_s3

_KEY = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
_SSN = b"patient ssn 123-45-6789\n"
_TENANT = "limits"


async def _secret_hits(body: bytes) -> int:
    async with in_memory_semantic_store() as store:
        buckets = (MotoBucket("acme-blob", public=True, objects={"o": body}),)
        with moto_s3(buckets) as s3:
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
        return len(await KgQuery(store, _TENANT).find_public_secret_exposure())


async def _unencrypted_hits(body: bytes) -> int:
    async with in_memory_semantic_store() as store:
        buckets = (MotoBucket("acme-blob", public=True, objects={"o": body}),)
        with moto_s3(buckets) as s3:
            await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
        return len(await KgQuery(store, _TENANT).find_public_unencrypted_exposure())


@pytest.mark.asyncio
async def test_boundary_decoded_text_is_detected() -> None:
    # The classifier matches patterns in decoded UTF-8 text — including inside structured text.
    assert await _secret_hits(_KEY) == 1
    assert await _secret_hits(b'{"aws_key": "AKIAIOSFODNN7EXAMPLE"}') == 1


@pytest.mark.asyncio
async def test_gap_gzipped_secret_is_missed() -> None:
    # GAP: archives are not decompressed before classification. Wiz/Macie scan inside .gz/.zip.
    assert await _secret_hits(gzip.compress(_KEY)) == 0, (
        "gzipped-secret gap closed — update docs/strategy/detection-gaps.md"
    )


@pytest.mark.asyncio
async def test_gap_base64_secret_is_missed() -> None:
    # GAP: encoded blobs are not decoded before classification.
    assert await _secret_hits(base64.b64encode(_KEY)) == 0, (
        "base64-secret gap closed — update docs/strategy/detection-gaps.md"
    )


@pytest.mark.asyncio
async def test_gap_gzipped_pii_is_missed() -> None:
    # GAP: same archive blind spot applies to PII (path 7 and every EXPOSES_DATA consumer).
    assert await _unencrypted_hits(gzip.compress(_SSN)) == 0, (
        "gzipped-PII gap closed — update docs/strategy/detection-gaps.md"
    )
