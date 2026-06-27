"""RDS instance + internet-exposure reader (path #19 — exposed managed database).

A publicly-accessible managed database is a first-class attack surface: it holds the application's
data and is reachable from the internet. This reads RDS instances and flags ``PubliclyAccessible``
— the canonical CSPM signal (CIS flags it). A managed DB is sensitive-by-assumption; classifying
its contents is a separate DSPM-over-databases slice.

Plain boto3 reader (same shape as ``aws_ec2``): inject the ``rds`` client, so it runs against real
AWS or in-process moto identically.

ponytail: ``PubliclyAccessible`` is the headline; a public DB behind a restrictive security group
isn't actually reachable. Add SG-reachability refinement if the false-positive rate warrants it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RdsInstance:
    """An RDS instance resolved to its ARN, internet-exposure, and engine."""

    instance_arn: str
    is_public: bool
    engine: str = ""


def read_rds_instances(rds: object) -> list[RdsInstance]:
    """Enumerate RDS instances as ``RdsInstance`` rows (exposure = ``PubliclyAccessible``)."""
    out: list[RdsInstance] = []
    for db in rds.describe_db_instances().get("DBInstances", []):  # type: ignore[attr-defined]
        arn = str(db.get("DBInstanceArn", ""))
        if not arn:
            continue
        out.append(
            RdsInstance(
                instance_arn=arn,
                is_public=bool(db.get("PubliclyAccessible")),
                engine=str(db.get("Engine", "")),
            )
        )
    return out


__all__ = ["RdsInstance", "read_rds_instances"]
