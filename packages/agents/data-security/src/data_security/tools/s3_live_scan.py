"""S3 live-scan wrapper for the Phase C SS4 guarded live route.

The v0.2 live readers (``S3LiveInventoryReader`` / ``S3LiveObjectSampler``) take an
*injected* boto3 client, which makes them awkward to dispatch as a single governed tool.
This wrapper mirrors k8s-posture's ``read_cluster_workloads`` pattern: it builds the boto3
S3 client **internally** from simple kwargs (profile / region) and returns the combined
``(buckets, samples)`` the agent's ``run()`` INGEST stage needs — one charter-dispatched
tool call instead of injecting a live client through ``ctx.call_tool``.

Only AWS S3 has a guarded live route at v0.2 (boto3 is the sole cloud SDK dependency). The
Azure Blob + GCS live readers remain client-injected and ungoverned-by-run() until their
SDKs land as dependencies — a v0.3 deliverable.
"""

from __future__ import annotations

import asyncio

from data_security.tools.s3_inventory import BucketInventory
from data_security.tools.s3_inventory_live import S3LiveInventoryReader
from data_security.tools.s3_objects import ObjectSample
from data_security.tools.s3_objects_live import DEFAULT_SAMPLE_RATE, S3LiveObjectSampler


async def scan_s3_live(
    *,
    account_id: str,
    profile: str | None = None,
    region: str | None = None,
    sample_rate: float = DEFAULT_SAMPLE_RATE,
) -> tuple[tuple[BucketInventory, ...], tuple[ObjectSample, ...]]:
    """Enumerate live S3 buckets + sample their objects via boto3, off the event loop.

    Returns ``(buckets, samples)`` in the same shapes the offline feed readers produce, so
    the INGEST stage is source-agnostic. The boto3 client is built here (never injected),
    keeping the tool stateless + dispatchable through the charter.
    """

    def _scan() -> tuple[tuple[BucketInventory, ...], tuple[ObjectSample, ...]]:
        import boto3

        client = boto3.Session(profile_name=profile, region_name=region).client("s3")
        buckets = S3LiveInventoryReader(client, account_id=account_id).read()
        sampler = S3LiveObjectSampler(client, sample_rate=sample_rate)
        samples: list[ObjectSample] = []
        for bucket in buckets:
            bucket_samples, _basis = sampler.sample(bucket.name)
            samples.extend(bucket_samples)
        return buckets, tuple(samples)

    return await asyncio.to_thread(_scan)
