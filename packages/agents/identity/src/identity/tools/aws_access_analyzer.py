"""AWS IAM Access Analyzer async wrapper.

Surfaces *external* access — cross-account principals and public exposure —
that AWS Access Analyzer detects on resources within an account/org.

Per ADR-005 (boto3 → asyncio.to_thread). The analyzer ARN is required
because Access Analyzer is per-region and per-organization-or-account;
callers thread the right one in. moto does not currently implement
Access Analyzer, so tests stub `boto3.Session` directly.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import boto3


class AccessAnalyzerError(RuntimeError):
    """Access Analyzer call raised, or the caller's session is invalid."""


@dataclass(frozen=True, slots=True)
class AccessAnalyzerFinding:
    """One Access Analyzer finding flattened into our wire-friendly shape.

    `external_principals` lists every principal value Access Analyzer
    surfaced in the `principal` map (AWS account IDs, role ARNs,
    federated principals, or the literal ``"*"`` for public access).
    `is_public` is True when the analyzer flagged the resource as
    publicly reachable.
    """

    id: str
    resource_arn: str
    resource_type: str
    external_principals: tuple[str, ...]
    actions: tuple[str, ...]
    is_public: bool
    status: str
    finding_type: str
    created_at: datetime
    updated_at: datetime
    matched_condition_keys: tuple[str, ...] = field(default_factory=tuple)


async def aws_access_analyzer_findings(
    *,
    analyzer_arn: str,
    profile: str | None = None,
    region: str = "us-east-1",
    statuses: Sequence[str] = ("ACTIVE",),
    timeout_sec: float = 60.0,
) -> tuple[AccessAnalyzerFinding, ...]:
    """Return all findings for an Access Analyzer.

    Args:
        analyzer_arn: ARN of the analyzer to query.
        profile: AWS named profile (defaults to environment auth).
        region: For client construction.
        statuses: Finding statuses to include; defaults to active only.
            Pass ``("ACTIVE", "ARCHIVED", "RESOLVED")`` to include all.
        timeout_sec: Wall-clock timeout — raises if pagination runs long.

    Raises:
        AccessAnalyzerError: on any underlying boto3 / botocore error or timeout.
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                _list_findings_sync,
                analyzer_arn,
                profile,
                region,
                tuple(statuses),
            ),
            timeout=timeout_sec,
        )
    except TimeoutError as exc:
        raise AccessAnalyzerError(
            f"aws_access_analyzer_findings timed out after {timeout_sec}s"
        ) from exc
    except AccessAnalyzerError:
        raise
    except Exception as exc:
        raise AccessAnalyzerError(f"aws_access_analyzer_findings failed: {exc}") from exc


def _list_findings_sync(
    analyzer_arn: str,
    profile: str | None,
    region: str,
    statuses: tuple[str, ...],
) -> tuple[AccessAnalyzerFinding, ...]:
    session = (
        boto3.Session(profile_name=profile, region_name=region)
        if profile
        else boto3.Session(region_name=region)
    )
    client = session.client("accessanalyzer")

    findings: list[AccessAnalyzerFinding] = []
    next_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {
            "analyzerArn": analyzer_arn,
            "filter": {"status": {"eq": list(statuses)}} if statuses else {},
        }
        if next_token:
            kwargs["nextToken"] = next_token

        response = client.list_findings_v2(**kwargs)
        for raw in response.get("findings", []):
            findings.append(_parse_finding(raw))

        next_token = response.get("nextToken")
        if not next_token:
            break

    return tuple(findings)


def _parse_finding(raw: dict[str, Any]) -> AccessAnalyzerFinding:
    principals = raw.get("principal") or {}
    if isinstance(principals, dict):
        external_principals = tuple(str(v) for v in principals.values() if v)
    else:
        external_principals = ()

    actions_raw = raw.get("action") or []
    actions = tuple(str(a) for a in actions_raw) if isinstance(actions_raw, list) else ()

    cond_raw = raw.get("condition") or {}
    matched_conditions = tuple(str(k) for k in cond_raw) if isinstance(cond_raw, dict) else ()

    return AccessAnalyzerFinding(
        id=str(raw["id"]),
        resource_arn=str(raw.get("resource") or raw.get("resourceArn") or ""),
        resource_type=str(raw.get("resourceType", "")),
        external_principals=external_principals,
        actions=actions,
        is_public=bool(raw.get("isPublic", False)),
        status=str(raw.get("status", "")),
        finding_type=str(raw.get("findingType", "")),
        created_at=_to_dt(raw.get("createdAt")),
        updated_at=_to_dt(raw.get("updatedAt")),
        matched_condition_keys=matched_conditions,
    )


def _to_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    raise AccessAnalyzerError(f"finding timestamp missing or wrong type: {value!r}")


__all__ = [
    "AccessAnalyzerError",
    "AccessAnalyzerFinding",
    "aws_access_analyzer_findings",
]
