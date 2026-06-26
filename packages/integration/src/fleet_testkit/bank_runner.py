"""Capability-bank runner — measures a data-security path detector's precision / recall / FP.

Loads a §3.2 YAML case (validated by :func:`fleet_testkit.capability.load_test_case`), builds
the moto buckets from its inline ``environment.buckets``, drives data-security's REAL detection
path, and scores the emitted hits against the case's ground truth via the shared evaluator. The
output is a real ``CapabilityResult`` (precision/recall/FP/time) — the measured number.

The data-security paths (3 public-secret, 7 public-unencrypted, …) differ only in *which*
``KgQuery`` detector runs; every hit carries ``resource_id`` + ``data_type``, so one runner +
one ``match`` covers them. ``detect`` selects the path.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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

#: A detector selector: given a tenant-scoped KgQuery, return the path's hits (each with
#: ``resource_id`` + ``data_type``).
Detect = Callable[[KgQuery], Awaitable[Sequence[Any]]]


@dataclass(frozen=True, slots=True)
class _Hit:
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
            encrypted=bool(b.get("encrypted", False)),
            objects={k: str(v).encode() for k, v in (b.get("objects") or {}).items()},
        )
        for b in specs
    )
    return case, buckets


def _match(hit: _Hit, gt: GroundTruth) -> bool:
    """A hit matches a ground-truth violation iff same bucket ARN and same data type."""
    return hit.bucket_arn == gt.resource and hit.data_type == str(gt.extra.get("data_type", ""))


async def run_data_security_case(path: Path | str, *, detect: Detect) -> CapabilityResult:
    """Drive a REAL data-security path detection for a case and score it against ground truth."""
    case, buckets = load_bank_case(path)
    async with in_memory_semantic_store() as store:
        with detection_timer() as timer:
            with moto_s3(buckets) as s3:
                await drive_data_security(store, tenant_id=_TENANT, buckets=buckets, s3_client=s3)
            raw_hits = await detect(KgQuery(store, _TENANT))
            hits: list[_Hit] = []
            for h in raw_hits:
                entity = await store.get_entity(tenant_id=_TENANT, entity_id=h.resource_id)
                hits.append(
                    _Hit(bucket_arn=entity.external_id if entity else "", data_type=h.data_type)
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


async def run_public_secret_case(path: Path | str) -> CapabilityResult:
    """Path 3 — public-secret exposure."""
    return await run_data_security_case(path, detect=lambda kg: kg.find_public_secret_exposure())


async def run_public_unencrypted_case(path: Path | str) -> CapabilityResult:
    """Path 7 — public + unencrypted + sensitive."""
    return await run_data_security_case(
        path, detect=lambda kg: kg.find_public_unencrypted_exposure()
    )


__all__ = [
    "load_bank_case",
    "run_data_security_case",
    "run_public_secret_case",
    "run_public_unencrypted_case",
]
