"""One-click cloud remediation, REAL against moto — watch the fix actually apply + verify.

Drives the remediation agent's cloud actions against in-process moto: S3 Block Public Access
(closes public_secret / public_unencrypted) and RDS make-private (closes exposed_database). Proves
the safety properties: preview mutates nothing, execute flips + verifies, idempotent re-run is a
no-op, tighten-only, and the captured before-state rolls back. Real-account execution stays
operator-gated; this proves the logic.
"""

import boto3
import pytest
from moto import mock_aws
from remediation.tools.cloud_remediation import (
    block_public_access,
    disable_public_access,
    restore_public_access,
)

_REGION = "us-east-1"


def test_report_auto_via_matches_real_action_ids() -> None:
    # The attack-path report names these actions as `auto_via`; they must equal the real action
    # ids the executor exposes, or "one-click" would point at nothing.
    from meta_harness.attack_path_remediation import REMEDIATION
    from remediation.tools.cloud_remediation import (
        ACTION_RDS_DISABLE_PUBLIC_ACCESS,
        ACTION_S3_BLOCK_PUBLIC_ACCESS,
    )

    real = {ACTION_S3_BLOCK_PUBLIC_ACCESS, ACTION_RDS_DISABLE_PUBLIC_ACCESS}
    cloud = ("remediation_s3", "remediation_rds")
    wired = {
        a.auto_via for a in REMEDIATION.values() if a.auto_via and a.auto_via.startswith(cloud)
    }
    assert wired == real, f"report auto_via {wired} must match real action ids {real}"
    # The three top exposure paths are now auto-fixable.
    for pt in ("public_secret", "public_unencrypted", "exposed_database"):
        assert REMEDIATION[pt].auto_fixable and REMEDIATION[pt].auto_via


def _is_blocked(s3, bucket: str) -> bool:
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except Exception:
        return False
    return all(cfg[k] for k in cfg)


@pytest.mark.asyncio
async def test_s3_block_public_access_preview_then_execute() -> None:
    with mock_aws():
        s3 = boto3.client("s3", region_name=_REGION)
        s3.create_bucket(Bucket="acme-creds")

        # Preview: reports the change, mutates NOTHING.
        preview = block_public_access(s3, "acme-creds", execute=False)
        assert preview.outcome == "would_change" and preview.mode == "preview"
        with pytest.raises(
            Exception
        ):  # no BPA config exists yet — preview didn't create one  # noqa: B017
            s3.get_public_access_block(Bucket="acme-creds")

        # Execute: flips all four flags and verifies.
        done = block_public_access(s3, "acme-creds", execute=True)
        assert done.outcome == "executed_verified" and done.changed
        assert _is_blocked(s3, "acme-creds")

        # Idempotent: a second execute on a compliant bucket is a no-op.
        again = block_public_access(s3, "acme-creds", execute=True)
        assert again.outcome == "already_compliant"

        # Rollback: restore the captured prior (open) state.
        restore_public_access(s3, "acme-creds", done.before)
        assert not _is_blocked(s3, "acme-creds")


@pytest.mark.asyncio
async def test_rds_disable_public_access_preview_then_execute() -> None:
    with mock_aws():
        rds = boto3.client("rds", region_name=_REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="acme-prod-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="pw-not-a-secret-1234",
            AllocatedStorage=20,
            PubliclyAccessible=True,
        )

        preview = disable_public_access(rds, "acme-prod-db", execute=False)
        assert preview.outcome == "would_change"
        # Preview didn't change anything.
        inst = rds.describe_db_instances(DBInstanceIdentifier="acme-prod-db")["DBInstances"][0]
        assert inst["PubliclyAccessible"] is True

        done = disable_public_access(rds, "acme-prod-db", execute=True)
        assert done.outcome == "executed_verified" and done.changed
        inst2 = rds.describe_db_instances(DBInstanceIdentifier="acme-prod-db")["DBInstances"][0]
        assert inst2["PubliclyAccessible"] is False

        again = disable_public_access(rds, "acme-prod-db", execute=True)
        assert again.outcome == "already_compliant"


@pytest.mark.asyncio
async def test_tighten_only_already_private_db_is_noop() -> None:
    with mock_aws():
        rds = boto3.client("rds", region_name=_REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="private-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="pw-not-a-secret-1234",
            AllocatedStorage=20,
            PubliclyAccessible=False,
        )
        # An already-private instance: both preview and execute are no-ops (never re-opens).
        assert (
            disable_public_access(rds, "private-db", execute=False).outcome == "already_compliant"
        )
        assert disable_public_access(rds, "private-db", execute=True).outcome == "already_compliant"
