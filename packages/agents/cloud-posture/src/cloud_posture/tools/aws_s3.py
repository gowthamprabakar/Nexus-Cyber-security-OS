"""AWS S3 describe tools (async). Read-only inspection of buckets."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import boto3
from botocore.exceptions import ClientError


async def list_buckets(region: str = "us-east-1") -> list[str]:
    return await asyncio.to_thread(_list_buckets_sync, region)


def _list_buckets_sync(region: str) -> list[str]:
    client = boto3.client("s3", region_name=region)
    resp = client.list_buckets()
    return [b["Name"] for b in resp.get("Buckets", [])]


def _get_or_none(fn: Callable[..., Any], **kwargs: Any) -> Any:
    try:
        return fn(**kwargs)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {
            "NoSuchBucketPolicy",
            "ServerSideEncryptionConfigurationNotFoundError",
            "NoSuchPublicAccessBlockConfiguration",
        }:
            return None
        raise


async def describe_bucket(bucket: str, region: str = "us-east-1") -> dict[str, Any]:
    return await asyncio.to_thread(_describe_bucket_sync, bucket, region)


def _describe_bucket_sync(bucket: str, region: str) -> dict[str, Any]:
    client = boto3.client("s3", region_name=region)
    client.head_bucket(Bucket=bucket)
    return {
        "bucket": bucket,
        "region": region,
        "acl": client.get_bucket_acl(Bucket=bucket).get("Grants", []),
        "policy": _get_or_none(client.get_bucket_policy, Bucket=bucket),
        "encryption": _get_or_none(client.get_bucket_encryption, Bucket=bucket),
        "versioning": client.get_bucket_versioning(Bucket=bucket).get("Status"),
        "public_access_block": _get_or_none(client.get_public_access_block, Bucket=bucket),
        "logging": client.get_bucket_logging(Bucket=bucket).get("LoggingEnabled"),
    }
