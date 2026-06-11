"""Live AWS S3 bucket inventory (data-security v0.2 Task 2).

The v0.2 live counterpart to the offline ``read_s3_inventory`` (which stays for the
deterministic eval). Stitches the per-bucket S3 API responses (location / ACL / public-
access-block / encryption / policy / tags) into the same ``BucketInventory`` dict shape the
offline reader parses, so buckets are **byte-identical** via the shared ``_try_parse``. The
S3 client is **injectable** so this is unit-testable without live AWS.
"""

from __future__ import annotations

from typing import Any, Protocol

from data_security.tools.s3_inventory import BucketInventory, _try_parse

_PUBLIC_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
_PUBLIC_AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


class S3Client(Protocol):
    """The subset of the boto3 S3 client surface the live reader uses."""

    def list_buckets(self) -> dict[str, Any]: ...
    def get_bucket_location(self, *, Bucket: str) -> dict[str, Any]: ...
    def get_bucket_acl(self, *, Bucket: str) -> dict[str, Any]: ...
    def get_public_access_block(self, *, Bucket: str) -> dict[str, Any]: ...
    def get_bucket_encryption(self, *, Bucket: str) -> dict[str, Any]: ...
    def get_bucket_policy(self, *, Bucket: str) -> dict[str, Any]: ...
    def get_bucket_tagging(self, *, Bucket: str) -> dict[str, Any]: ...


def _safe(call: Any, **kwargs: Any) -> dict[str, Any]:
    """Run an S3 call, treating any client error (NoSuchBucketPolicy, NoSuchTagSet,
    ServerSideEncryptionConfigurationNotFoundError, AccessDenied, …) as 'absent'."""
    try:
        result = call(**kwargs)
    except Exception:
        return {}
    return result if isinstance(result, dict) else {}


def _acl_grants(acl: dict[str, Any]) -> dict[str, list[str]]:
    all_users: list[str] = []
    auth_users: list[str] = []
    for grant in acl.get("Grants", []) if isinstance(acl.get("Grants"), list) else []:
        if not isinstance(grant, dict):
            continue
        grantee_raw = grant.get("Grantee")
        grantee = grantee_raw if isinstance(grantee_raw, dict) else {}
        uri = grantee.get("URI")
        perm = grant.get("Permission")
        if not isinstance(perm, str):
            continue
        if uri == _PUBLIC_ALL_USERS:
            all_users.append(perm)
        elif uri == _PUBLIC_AUTH_USERS:
            auth_users.append(perm)
    return {"grants_all_users": all_users, "grants_authenticated_users": auth_users}


def _encryption_algorithm(enc: dict[str, Any]) -> dict[str, Any]:
    config = enc.get("ServerSideEncryptionConfiguration")
    rules = config.get("Rules") if isinstance(config, dict) else None
    if isinstance(rules, list) and rules and isinstance(rules[0], dict):
        default = rules[0].get("ApplyServerSideEncryptionByDefault")
        if isinstance(default, dict):
            algo = str(default.get("SSEAlgorithm", "NONE"))
            return {"algorithm": algo, "kms_master_key_id": default.get("KMSMasterKeyID")}
    return {"algorithm": "NONE", "kms_master_key_id": None}


def _bucket_record(client: S3Client, name: str, *, account_id: str) -> dict[str, Any]:
    location = _safe(client.get_bucket_location, Bucket=name).get("LocationConstraint")
    region = str(location) if location else "us-east-1"
    pab = _safe(client.get_public_access_block, Bucket=name).get(
        "PublicAccessBlockConfiguration", {}
    )
    policy = _safe(client.get_bucket_policy, Bucket=name).get("Policy")
    tag_set = _safe(client.get_bucket_tagging, Bucket=name).get("TagSet", [])
    tags = {
        t["Key"]: t["Value"] for t in tag_set if isinstance(t, dict) and "Key" in t and "Value" in t
    }
    return {
        "name": name,
        "region": region,
        "account_id": account_id,
        "acl": _acl_grants(_safe(client.get_bucket_acl, Bucket=name)),
        "public_access_block": {
            "block_public_acls": bool(pab.get("BlockPublicAcls", False)),
            "ignore_public_acls": bool(pab.get("IgnorePublicAcls", False)),
            "block_public_policy": bool(pab.get("BlockPublicPolicy", False)),
            "restrict_public_buckets": bool(pab.get("RestrictPublicBuckets", False)),
        },
        "encryption": _encryption_algorithm(_safe(client.get_bucket_encryption, Bucket=name)),
        "policy_json": str(policy) if isinstance(policy, str) else None,
        "tags": tags,
    }


class S3LiveInventoryReader:
    """Reads live S3 bucket posture into byte-identical `BucketInventory` records."""

    __slots__ = ("_account_id", "_client")

    def __init__(self, client: S3Client, *, account_id: str) -> None:
        self._client = client
        self._account_id = account_id

    def read(self) -> tuple[BucketInventory, ...]:
        resp = self._client.list_buckets()
        buckets = resp.get("Buckets", []) if isinstance(resp, dict) else []
        out: list[BucketInventory] = []
        for b in buckets:
            if not isinstance(b, dict) or "Name" not in b:
                continue
            raw = _bucket_record(self._client, str(b["Name"]), account_id=self._account_id)
            rec = _try_parse(raw)
            if rec is not None:
                out.append(rec)
        return tuple(out)
