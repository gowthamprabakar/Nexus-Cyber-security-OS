"""DEEP capability bank — public data exposure (the L2 reference, 'deep as hell').

Each case plants a realistic environment in the fake cloud (moto), runs the REAL data-security
readers + the public-exposure detectors, and scores TP/FN/FP through the REAL capability evaluator.
No cloud account. Heavy weighting on FALSE-POSITIVE TRAPS + EDGE CASES — the categories that prove a
detector is trustworthy, not just loud. This sets the depth bar for the per-agent bank cascade.

Covered §3.3 categories: clean_baseline, standard_violations, edge_cases, false_positive_traps,
enrichment_context, negative_space, cross_domain_inputs.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest
from charter.memory.graph_types import NodeCategory
from meta_harness.kg_query import KgQuery

from fleet_testkit import MotoBucket, drive_data_security, in_memory_semantic_store
from fleet_testkit.capability import (
    GroundTruth,
    NonDetection,
    PassCriteria,
    evaluate,
    score,
)
from fleet_testkit.moto_aws import moto_s3

_AWS_KEY = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
_SSN = b"patient ssn 123-45-6789 on file\n"
_HTML = b"<html>public marketing page</html>\n"
_NOISE = b"loremipsumdolorsitametconsecteturadipi\n"  # 40-ish chars, NOT an AKIA key
_OTHER_ACCT = "arn:aws:iam::999999999999:role/partner"


def _policy(bucket: str, principal: Any) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": principal,
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }
            ],
        }
    )


def _block_public_access(*buckets: str) -> Callable[[Any], None]:
    def setup(s3: Any) -> None:
        for b in buckets:
            s3.put_public_access_block(
                Bucket=b,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )

    return setup


@dataclass(frozen=True, slots=True)
class _Case:
    id: str
    category: str
    description: str
    buckets: tuple[MotoBucket, ...]
    ground_truth: tuple[tuple[str, str, str], ...]  # (gt_id, type, bucket_name)
    non_detections: tuple[tuple[str, str], ...]  # (bucket_name, reason)
    criteria: PassCriteria
    setup_fn: Callable[[Any], None] | None = None  # advanced moto setup (BPA, object ACLs)
    setup_tenant: str = "demo"  # negative_space writes under a DIFFERENT tenant than we query


_PERFECT = PassCriteria(precision=1.0, recall=1.0, false_positives_max=0)

_BANK: tuple[_Case, ...] = (
    # ---------------- 1. CLEAN BASELINE — must stay silent ----------------
    _Case(
        "clean-1",
        "clean_baseline",
        "Only benign buckets: private-with-data + public-but-harmless.",
        buckets=(
            MotoBucket("acme-archive", public=False, encrypted=True, objects={"o": _SSN}),
            MotoBucket("acme-web", public=True, encrypted=True, objects={"o": _HTML}),
        ),
        ground_truth=(),
        non_detections=(
            ("acme-archive", "private bucket — not exposed"),
            ("acme-web", "public but no sensitive data"),
        ),
        criteria=_PERFECT,
    ),
    # ---------------- 2. STANDARD VIOLATIONS ----------------
    _Case(
        "std-1",
        "standard_violations",
        "Public bucket leaks an AWS key (ACL-public) + public SSN.",
        buckets=(
            MotoBucket("acme-creds", public=True, encrypted=True, objects={"k": _AWS_KEY}),
            MotoBucket("acme-logs", public=True, encrypted=False, objects={"l": _SSN}),
        ),
        ground_truth=(
            ("g1", "public_secret", "acme-creds"),
            ("g2", "public_unencrypted", "acme-logs"),
        ),
        non_detections=(),
        criteria=_PERFECT,
    ),
    _Case(
        "std-2",
        "standard_violations",
        "Public via BUCKET POLICY (not ACL) still leaks a secret.",
        buckets=(
            MotoBucket(
                "acme-policy-pub",
                public=False,
                encrypted=True,
                objects={"k": _AWS_KEY},
                policy=_policy("acme-policy-pub", "*"),
            ),
        ),
        ground_truth=(("g1", "public_secret", "acme-policy-pub"),),
        non_detections=(),
        criteria=_PERFECT,
    ),
    # ---------------- 3. EDGE CASES ----------------
    _Case(
        "edge-1",
        "edge_cases",
        "Encryption does NOT save a PUBLIC secret — still a leak.",
        buckets=(MotoBucket("acme-enc-pub", public=True, encrypted=True, objects={"k": _AWS_KEY}),),
        ground_truth=(("g1", "public_secret", "acme-enc-pub"),),
        non_detections=(),
        criteria=_PERFECT,
    ),
    _Case(
        "edge-2",
        "edge_cases",
        "One bucket public + holds BOTH a secret AND unencrypted SSN.",
        buckets=(
            MotoBucket(
                "acme-both", public=True, encrypted=False, objects={"k": _AWS_KEY, "s": _SSN}
            ),
        ),
        ground_truth=(
            ("g1", "public_secret", "acme-both"),
            ("g2", "public_unencrypted", "acme-both"),
        ),
        non_detections=(),
        criteria=_PERFECT,
    ),
    # ---------------- 4. FALSE-POSITIVE TRAPS (the deep part) ----------------
    _Case(
        "trap-1",
        "false_positive_traps",
        "Private bucket WITH a secret — must NOT fire (not exposed).",
        buckets=(
            MotoBucket("acme-priv-secret", public=False, encrypted=True, objects={"k": _AWS_KEY}),
        ),
        ground_truth=(),
        non_detections=(("acme-priv-secret", "has a secret but the bucket is private"),),
        criteria=_PERFECT,
    ),
    _Case(
        "trap-2",
        "false_positive_traps",
        "Wildcard bucket-policy but BLOCK PUBLIC ACCESS is on — BPA neutralizes it, must NOT fire.",
        buckets=(
            MotoBucket(
                "acme-bpa",
                public=False,
                encrypted=True,
                objects={"k": _AWS_KEY},
                policy=_policy("acme-bpa", "*"),
            ),
        ),
        ground_truth=(),
        non_detections=(("acme-bpa", "wildcard policy is neutralized by Block-Public-Access"),),
        criteria=_PERFECT,
        setup_fn=_block_public_access("acme-bpa"),
    ),
    _Case(
        "trap-3",
        "false_positive_traps",
        "Bucket-policy grants a SPECIFIC account (not '*') — a named grant, not public exposure.",
        buckets=(
            MotoBucket(
                "acme-named-grant",
                public=False,
                encrypted=True,
                objects={"k": _AWS_KEY},
                policy=_policy("acme-named-grant", {"AWS": _OTHER_ACCT}),
            ),
        ),
        ground_truth=(),
        non_detections=(("acme-named-grant", "specific-principal grant is not a PUBLIC exposure"),),
        criteria=_PERFECT,
    ),
    # ---------------- 5. ENRICHMENT / CONTEXT ----------------
    _Case(
        "enrich-1",
        "enrichment_context",
        "Public bucket with a 40-char string that is NOT an AKIA key — classifier must not cry wolf.",
        buckets=(MotoBucket("acme-noise", public=True, encrypted=True, objects={"n": _NOISE}),),
        ground_truth=(),
        non_detections=(("acme-noise", "looks key-shaped but is not a real AWS credential"),),
        criteria=_PERFECT,
    ),
    # ---------------- 6. NEGATIVE SPACE ----------------
    _Case(
        "neg-1",
        "negative_space",
        "A public+secret bucket belongs to ANOTHER tenant — must not appear in our results.",
        buckets=(MotoBucket("other-creds", public=True, encrypted=True, objects={"k": _AWS_KEY}),),
        ground_truth=(),
        non_detections=(("other-creds", "off-tenant data must never cross"),),
        criteria=_PERFECT,
        setup_tenant="other-tenant",
    ),
    # ---------------- 7. CROSS-DOMAIN INPUTS ----------------
    _Case(
        "xdom-1",
        "cross_domain_inputs",
        "Mixed env: a real public leak alongside a private-with-secret trap and benign public.",
        buckets=(
            MotoBucket("acme-leak", public=True, encrypted=True, objects={"k": _AWS_KEY}),
            MotoBucket("acme-safe", public=False, encrypted=True, objects={"k": _AWS_KEY}),
            MotoBucket("acme-pub-html", public=True, encrypted=True, objects={"o": _HTML}),
        ),
        ground_truth=(("g1", "public_secret", "acme-leak"),),
        non_detections=(
            ("acme-safe", "private — must not fire"),
            ("acme-pub-html", "public but benign"),
        ),
        criteria=_PERFECT,
    ),
)


def _match(finding: dict[str, str], gt: GroundTruth) -> bool:
    return finding["type"] == gt.type and finding["resource"] == gt.resource


async def _run(case: _Case):
    async with in_memory_semantic_store() as store:
        with moto_s3(case.buckets) as s3:
            if case.setup_fn:
                case.setup_fn(s3)
            arns = await drive_data_security(
                store, tenant_id=case.setup_tenant, buckets=case.buckets, s3_client=s3
            )
        name_by_id: dict[str, str] = {}
        for r in await store.list_entities_by_type(
            tenant_id="demo", entity_type=NodeCategory.CLOUD_RESOURCE.value
        ):
            for nm, arn in arns.items():
                if r.external_id == arn:
                    name_by_id[r.entity_id] = nm
        kg = KgQuery(store, "demo")
        findings: list[dict[str, str]] = []
        for h in await kg.find_public_secret_exposure():
            findings.append(
                {"type": "public_secret", "resource": name_by_id.get(h.resource_id, h.resource_id)}
            )
        for h in await kg.find_public_unencrypted_exposure():
            findings.append(
                {
                    "type": "public_unencrypted",
                    "resource": name_by_id.get(h.resource_id, h.resource_id),
                }
            )

    gts = tuple(GroundTruth(id=g[0], type=g[1], resource=g[2]) for g in case.ground_truth)
    nds = tuple(
        NonDetection(id=f"nd-{i}", resource=r, reason=why)
        for i, (r, why) in enumerate(case.non_detections)
    )
    return score(
        findings,
        gts,
        nds,
        match=_match,
        label=lambda f: f"{f['type']}:{f['resource']}",
        test_case_id=case.id,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _BANK, ids=[c.id for c in _BANK])
async def test_case_meets_criteria(case: _Case) -> None:
    evaluate(await _run(case), case.criteria)


def test_bank_covers_all_seven_categories() -> None:
    covered = {c.category for c in _BANK}
    required = {
        "clean_baseline",
        "standard_violations",
        "edge_cases",
        "false_positive_traps",
        "cross_domain_inputs",
        "enrichment_context",
        "negative_space",
    }
    assert covered == required, f"bank must cover all 7 categories; missing {required - covered}"
    # Deep bar: traps + edges are the heaviest-weighted categories.
    traps_and_edges = sum(1 for c in _BANK if c.category in {"false_positive_traps", "edge_cases"})
    assert traps_and_edges >= 4, "a 'deep' bank leans on traps + edges, not just happy-path hits"


@pytest.mark.asyncio
async def test_deep_bank_scorecard() -> None:
    tp = fn = fp = 0
    print("\n=== PUBLIC-EXPOSURE DEEP CAPABILITY BANK (no cloud account; real readers on moto) ===")
    print(f"  {'case':12s} {'category':22s} {'TP':>3} {'FN':>3} {'FP':>3}")
    for case in _BANK:
        r = await _run(case)
        tp += r.true_positives
        fn += r.false_negatives
        fp += r.false_positives
        print(
            f"  {case.id:12s} {case.category:22s} {r.true_positives:>3} "
            f"{r.false_negatives:>3} {r.false_positives:>3}"
        )
    precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
    print(
        f"  {'TOTAL':12s} {'':22s} {tp:>3} {fn:>3} {fp:>3}  "
        f"precision={precision:.3f} recall={recall:.3f}  ({len(_BANK)} cases)"
    )
    assert fp == 0 and fn == 0
