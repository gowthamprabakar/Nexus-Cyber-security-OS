"""``scan_rds_posture`` — live RDS posture classification (v0.4 Stage 1.2).

Posture-only (metadata, not row content): encryption-at-rest, public accessibility,
and deletion-protection across RDS DB instances + clusters. Row-content data
classification is deferred to v0.5 (it needs a live SQL driver / testcontainers —
CI infra not justified for v0.4's marginal coverage).

Charter-registered tool (ADR-016): the boto3 ``describe_*`` calls are the cloud
calls; ``rds_to_findings`` (pure) turns the posture records into OCSF 2003 findings.
"""

from __future__ import annotations

from typing import Any

import boto3


def _violations(*, encrypted: bool, public: bool, deletion_protection: bool) -> list[str]:
    out: list[str] = []
    if not encrypted:
        out.append("storage_not_encrypted")
    if public:
        out.append("publicly_accessible")
    if not deletion_protection:
        out.append("deletion_protection_disabled")
    return out


async def scan_rds_posture(
    *,
    account_id: str,
    profile: str | None = None,
    region: str | None = None,
) -> list[dict[str, Any]]:
    """Return one posture record per RDS instance/cluster that has ≥1 violation.

    Record: ``{identifier, kind, region, violations: [...]}``. Clean (no violations)
    resources are omitted. ``account_id`` is part of the live-route contract.
    """
    del account_id  # resolved via the credential chain; part of the live contract
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    client = session.client("rds", region_name=region)
    records: list[dict[str, Any]] = []

    for db in client.describe_db_instances().get("DBInstances", []):
        violations = _violations(
            encrypted=bool(db.get("StorageEncrypted", False)),
            public=bool(db.get("PubliclyAccessible", False)),
            deletion_protection=bool(db.get("DeletionProtection", False)),
        )
        if violations:
            records.append(
                {
                    "identifier": str(db.get("DBInstanceIdentifier", "")),
                    "kind": "instance",
                    "region": region or "",
                    "violations": violations,
                }
            )

    for cluster in client.describe_db_clusters().get("DBClusters", []):
        violations = _violations(
            encrypted=bool(cluster.get("StorageEncrypted", False)),
            public=bool(cluster.get("PubliclyAccessible", False)),
            deletion_protection=bool(cluster.get("DeletionProtection", False)),
        )
        if violations:
            records.append(
                {
                    "identifier": str(cluster.get("DBClusterIdentifier", "")),
                    "kind": "cluster",
                    "region": region or "",
                    "violations": violations,
                }
            )

    return records


__all__ = ["scan_rds_posture"]
