"""Capability-bank runner — measures a path detector's precision / recall / FP on a bank.

Loads a §3.2 YAML case (validated by :func:`fleet_testkit.capability.load_test_case`), builds
the moto buckets from its inline ``environment.buckets``, drives data-security's REAL detection
path, and scores the emitted ``PublicSecretExposure`` hits against the case's ground truth via
the shared evaluator. The output is a real ``CapabilityResult`` (precision/recall/FP/time) — the
measured number, not a felt one.

Path-3 (public-secret-exposure) is the first vertical. A second path generalizes the
``run_*_case`` shape; until then it stays concrete (YAGNI).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from meta_harness.kg_query import KgQuery

from fleet_testkit.capability import (
    CapabilityResult,
    GroundTruth,
    TestCase,
    detection_timer,
    load_test_case,
    score,
)
from fleet_testkit.moto_aws import MotoBucket, drive_data_security, moto_s3
from fleet_testkit.store import in_memory_semantic_store

_TENANT = "bank-tenant"


@dataclass(frozen=True, slots=True)
class _SecretHit:
    """A detector hit resolved to its stable identity for scoring (entity_id → bucket ARN)."""

    bucket_arn: str
    data_type: str


def load_bank_case(path: Path | str) -> tuple[TestCase, tuple[MotoBucket, ...]]:
    """Parse + validate a §3.2 case AND build its moto buckets from ``environment.buckets``."""
    case = load_test_case(path)
    raw = yaml.safe_load(Path(path).read_text())
    specs = (raw.get("environment") or {}).get("buckets") or []
    buckets = tuple(
        MotoBucket(
            name=str(b["name"]),
            public=bool(b["public"]),
            objects={k: str(v).encode() for k, v in (b.get("objects") or {}).items()},
        )
        for b in specs
    )
    return case, buckets


def _match(hit: _SecretHit, gt: GroundTruth) -> bool:
    """A hit matches a ground-truth violation iff same bucket ARN and same secret data type."""
    return hit.bucket_arn == gt.resource and hit.data_type == str(gt.extra.get("data_type", ""))


async def run_public_secret_case(path: Path | str) -> CapabilityResult:
    """Drive the REAL path-3 detection for a case and score it against ground truth."""
    case, buckets = load_bank_case(path)
    async with in_memory_semantic_store() as store:
        with detection_timer() as timer:
            with moto_s3(buckets) as s3:
                await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            raw_hits = await KgQuery(store, _TENANT).find_public_secret_exposure()
            hits: list[_SecretHit] = []
            for h in raw_hits:
                entity = await store.get_entity(tenant_id=_TENANT, entity_id=h.resource_id)
                hits.append(
                    _SecretHit(
                        bucket_arn=entity.external_id if entity else "",
                        data_type=h.data_type,
                    )
                )
        return score(
            hits,
            case.ground_truth_violations,
            case.expected_non_detections,
            match=_match,
            label=lambda h: f"{h.bucket_arn}:{h.data_type}",
            detection_time_seconds=timer.seconds,
            test_case_id=case.test_case_id,
        )


__all__ = ["load_bank_case", "run_public_secret_case"]
