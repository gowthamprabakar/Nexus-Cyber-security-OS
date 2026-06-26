"""Data Security Agent driver — wires the 7-stage pipeline under Charter.

Mirrors multi-cloud-posture's [`agent.py`](../../../multi-cloud-posture/
src/multi_cloud_posture/agent.py) shape (filesystem-mode TaskGroup fan-out
under the runtime charter) with the D.5-specific 7-stage pipeline. ADR-007
pattern check (D.5): the ``agent.run`` signature converges across agents —
``(contract, *, llm_provider, ...)``. Confirmed for the eleventh time.

Seven-stage pipeline:

1. **INGEST**    — two feeds concurrent via ``asyncio.TaskGroup``:
   S3 bucket inventory + S3 object samples.
2. **CLASSIFY**  — Task-3 classifier over object-sample text. Label
   hits aggregated per bucket. **Q6 invariant** — only labels are kept;
   sample bytes are released after classification.
3. **DETECT**    — 4 pure-function detectors per bucket:
   ``public_bucket`` / ``unencrypted`` / ``sensitive_location`` /
   ``oversharing_iam``.
4. **CORRELATE** — optional F.3 sibling-workspace read; matches D.5
   findings against F.3 findings by bucket ARN.
5. **SCORE**     — apply correlation uplift (HIGH→CRITICAL etc.).
6. **SUMMARIZE** — deterministic markdown render with Q6 render-layer
   assert.
7. **HANDOFF**   — write ``findings.json`` + ``report.md`` to the
   charter workspace; charter's implicit audit chain records tool
   calls + writes.

Differences from multi-cloud-posture:

- **Two** ingest feeds instead of four.
- **Classifier pass** (Stage 2) — new substrate; classifier returns
  ``ClassifierLabel`` enum only, never the matched substring.
- **Detector loop** (Stage 3) — 4 deterministic detectors per bucket
  vs multi-cloud-posture's per-source normalizers.
- **F.3 cross-correlation** (Stage 4) — optional ``--cloud-posture-
  workspace`` flag; mirrors D.7's sibling-workspace read pattern.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from charter.memory.semantic import SemanticStore
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from data_security import __version__ as agent_version
from data_security.classifiers import classify_bytes
from data_security.correlate import (
    CorrelationResult,
    correlate_with_f3,
    read_f3_findings,
)
from data_security.db_classify import dynamodb_to_findings, rds_to_findings
from data_security.detectors import (
    detect_oversharing_iam,
    detect_public_bucket,
    detect_sensitive_location,
    detect_unencrypted,
)
from data_security.kg_writer import KnowledgeGraphWriter
from data_security.schemas import (
    ClassifierLabel,
    CloudPostureFinding,
    FindingsReport,
)
from data_security.scorer import apply_correlation_uplift
from data_security.secrets_ingest import (
    ingest_code_secret_findings,
    ingest_runtime_secret_findings,
)
from data_security.summarizer import render_summary
from data_security.tools import (
    BucketInventory,
    ObjectSample,
    read_s3_inventory,
    read_s3_objects,
)
from data_security.tools.dynamodb_scan import scan_dynamodb
from data_security.tools.rds_scan import scan_rds_posture
from data_security.tools.s3_live_scan import scan_s3_live

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent.

    Phase C SS4: ``scan_s3_live`` is registered so the v0.2 live S3 readers dispatch through
    the charter proxy (ADR-016) — budget/audit/permission bound — and ``run()`` can route to a
    live AWS account behind a guarded flag. cloud_calls=1 (boto3 list/get calls). The Azure
    Blob + GCS live readers stay client-injected + ungoverned until their SDKs land (v0.3).
    """
    reg = ToolRegistry()
    reg.register("read_s3_inventory", read_s3_inventory, version="0.1.0", cloud_calls=0)
    reg.register("read_s3_objects", read_s3_objects, version="0.1.0", cloud_calls=0)
    reg.register("read_f3_findings", read_f3_findings, version="0.1.0", cloud_calls=0)
    reg.register("scan_s3_live", scan_s3_live, version="0.2.0", cloud_calls=1)
    # v0.4 Stage 1.2: live DynamoDB content classification + RDS posture (boto3).
    reg.register("scan_dynamodb", scan_dynamodb, version="0.4.0", cloud_calls=1)
    reg.register("scan_rds_posture", scan_rds_posture, version="0.4.0", cloud_calls=1)
    return reg


def _envelope(
    contract: ExecutionContract,
    *,
    correlation_id: str,
    model_pin: str,
) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id=contract.customer_id,
        agent_id="data_security",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,  # plumbed; not called in v0.1
    s3_inventory_feed: Path | str | None = None,
    s3_objects_feed: Path | str | None = None,
    live_s3_account_id: str | None = None,
    live_dynamodb_account_id: str | None = None,
    live_rds_account_id: str | None = None,
    aws_profile: str | None = None,
    aws_region: str | None = None,
    cloud_posture_workspace: Path | str | None = None,
    vulnerability_workspace: Path | str | None = None,
    appsec_workspace: Path | str | None = None,
    trusted_sensitivity_tag: str = "Restricted",
    semantic_store: SemanticStore | None = None,
) -> FindingsReport:
    """Run the Data Security Agent end-to-end under the runtime charter.

    Args:
        contract: The signed ``ExecutionContract``.
        llm_provider: Reserved for future LLM-driven flows; not called in v0.1.
        s3_inventory_feed: Optional S3 bucket-inventory JSON path. Skipped
            if None (returns an empty FindingsReport).
        s3_objects_feed: Optional S3 object-sample JSON path. Skipped if
            None; detectors run without classifier signal (no CRITICAL
            uplift via classifier).
        live_s3_account_id: Phase C SS4 guarded live route. When set, INGEST
            scans a live AWS account via ``scan_s3_live`` (boto3) instead of
            the JSON feeds — mutually exclusive with ``s3_inventory_feed`` /
            ``s3_objects_feed``. Azure/GCS live routing is a v0.3 deliverable
            (their SDKs are not yet dependencies).
        aws_profile: Optional boto3 profile name for the live S3 route.
        aws_region: Optional AWS region for the live S3 route.
        cloud_posture_workspace: Optional path to a sibling F.3 workspace
            directory containing ``findings.json`` (Q4). When present,
            Stage 4 CORRELATE runs and Stage 5 SCORE uplifts severity for
            matched findings.
        vulnerability_workspace: Optional path to a sibling D.1 workspace
            directory containing ``runtime_secrets.json`` (A-2.4 / ADR-015).
            When present, Stage 3b ingests D.1's redacted secret hits and
            emits OCSF 2003 ``SECRET_EXPOSED_IN_RUNTIME`` findings (D.1 scans,
            DSPM emits). Absent/empty → no secret findings (byte-identical).
        appsec_workspace: Optional path to a sibling D.14 AppSec workspace
            directory containing ``code_secrets.json`` (B-1 / ADR-015 §Rationale-3).
            When present, ingests AppSec's redacted secrets-in-code and emits OCSF
            2003 ``SECRET_EXPOSED_IN_CODE`` findings (AppSec scans, DSPM emits).
            Absent/empty → no secret findings (byte-identical).
        trusted_sensitivity_tag: Override for the trusted ``Sensitivity``
            tag value (defaults to ``"Restricted"`` — the documented
            common AWS Data Classification posture).

    Returns:
        The ``FindingsReport``. Side effects: writes ``findings.json`` and
        ``report.md`` to the charter workspace; charter emits the implicit
        per-stage audit log to ``audit.jsonl``.
    """
    del llm_provider  # reserved for future iterations

    if live_s3_account_id is not None and (s3_inventory_feed or s3_objects_feed):
        raise ValueError(
            "live_s3_account_id is mutually exclusive with s3_inventory_feed / "
            "s3_objects_feed — pick the live AWS route or the JSON feeds (Phase C SS4)"
        )

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)

        # Stage 1 — INGEST: live AWS account (SS4 guarded route) or the JSON feeds.
        buckets, samples = await _ingest(
            ctx,
            s3_inventory_feed=s3_inventory_feed,
            s3_objects_feed=s3_objects_feed,
            live_s3_account_id=live_s3_account_id,
            aws_profile=aws_profile,
            aws_region=aws_region,
        )

        # Stage 2 — CLASSIFY: per-bucket classifier-label aggregation.
        # Q6 INVARIANT: only labels are kept; sample bytes are released
        # after the classifier returns its enum value.
        classifier_hits_by_bucket = _classify(samples)

        # v0.4 Stage 1.5: write the storage + data-classification inventory to the
        # fleet graph when a SemanticStore is injected. Opt-in — default None is inert
        # (no graph writes), so findings.json + report.md stay byte-identical.
        if semantic_store is not None:
            kg = KnowledgeGraphWriter(semantic_store, contract.customer_id)
            await kg.record(buckets, classifier_hits_by_bucket)

        # Stage 3 — DETECT: 4 detectors per bucket.
        d5_findings = _detect_all(
            buckets,
            classifier_hits_by_bucket=classifier_hits_by_bucket,
            envelope=envelope,
            scan_time=scan_started,
            trusted_sensitivity_tag=trusted_sensitivity_tag,
        )

        # Stage 3b — A-2.4 (ADR-015): ingest D.1's secrets-in-runtime handoff.
        # D.1 SCANS (writes redacted runtime_secrets.json); DSPM EMITS the OCSF
        # 2003 SECRET_EXPOSED_IN_RUNTIME finding. No plaintext crosses (D.1
        # redacted at source). Additive: empty/absent artifact → zero findings,
        # so the no-secret path is byte-identical.
        d5_findings = [
            *d5_findings,
            *ingest_runtime_secret_findings(
                vulnerability_workspace,
                envelope=envelope,
                detected_at=scan_started,
            ),
            # B-1 PR4 (ADR-015 §Rationale-3): consume AppSec (D.14) secrets-in-code
            # the same way as D.1 runtime secrets → OCSF 2003 SECRET_EXPOSED_IN_CODE.
            *ingest_code_secret_findings(
                appsec_workspace,
                envelope=envelope,
                detected_at=scan_started,
            ),
        ]

        # Stage 3c — v0.4 Stage 1.2: live DynamoDB content classification + RDS
        # posture, each behind a guarded account-id flag (default None → skipped →
        # byte-identical). Tools route through the charter proxy (ADR-016).
        if live_dynamodb_account_id is not None:
            dynamo_hits = await ctx.call_tool(
                "scan_dynamodb",
                account_id=live_dynamodb_account_id,
                profile=aws_profile,
                region=aws_region,
            )
            d5_findings = [
                *d5_findings,
                *dynamodb_to_findings(dynamo_hits, envelope=envelope, detected_at=scan_started),
            ]
        if live_rds_account_id is not None:
            rds_records = await ctx.call_tool(
                "scan_rds_posture",
                account_id=live_rds_account_id,
                profile=aws_profile,
                region=aws_region,
            )
            d5_findings = [
                *d5_findings,
                *rds_to_findings(rds_records, envelope=envelope, detected_at=scan_started),
            ]

        # Stage 4 — CORRELATE: optional F.3 sibling-workspace read.
        correlation = await _correlate(
            ctx,
            d5_findings=d5_findings,
            cloud_posture_workspace=cloud_posture_workspace,
        )

        # Stage 5 — SCORE: apply correlation uplift.
        scored = apply_correlation_uplift(d5_findings, correlation)

        # Stage 6 — SUMMARIZE: deterministic markdown render. The Q6
        # render-layer assert runs inside ``render_summary`` and raises
        # ``SummarizerQ6Violation`` if any classifier-matched substring
        # leaked into a finding field.
        summary_md = render_summary(scored, run_id=contract.delegation_id)

        # Stage 7 — HANDOFF: build the FindingsReport + write artifacts.
        report = FindingsReport(
            agent="data_security",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
        )
        for f in scored:
            report.add_finding(f)

        ctx.write_output(
            "findings.json",
            report.model_dump_json(indent=2).encode("utf-8"),
        )
        ctx.write_output("report.md", summary_md.encode("utf-8"))

        ctx.assert_complete()

    return report


# ---------------------------- pipeline stages -----------------------------


async def _ingest(
    ctx: Charter,
    *,
    s3_inventory_feed: Path | str | None,
    s3_objects_feed: Path | str | None,
    live_s3_account_id: str | None = None,
    aws_profile: str | None = None,
    aws_region: str | None = None,
) -> tuple[Sequence[BucketInventory], Sequence[ObjectSample]]:
    """Stage 1 — ingest buckets + object samples.

    Phase C SS4: when ``live_s3_account_id`` is set, dispatch the single ``scan_s3_live``
    tool (boto3 inventory + per-bucket sampling) through the charter, making the live S3
    readers load-bearing. Otherwise fan out the two JSON feeds via TaskGroup (a skipped feed
    → empty tuple). The two paths return the same shapes, so downstream stages are
    source-agnostic.
    """
    if live_s3_account_id is not None:
        buckets_live, samples_live = await ctx.call_tool(
            "scan_s3_live",
            account_id=live_s3_account_id,
            profile=aws_profile,
            region=aws_region,
        )
        return buckets_live, samples_live

    async with asyncio.TaskGroup() as tg:
        inventory_task = (
            tg.create_task(ctx.call_tool("read_s3_inventory", path=Path(s3_inventory_feed)))
            if s3_inventory_feed
            else None
        )
        objects_task = (
            tg.create_task(ctx.call_tool("read_s3_objects", path=Path(s3_objects_feed)))
            if s3_objects_feed
            else None
        )

    buckets: Sequence[BucketInventory] = inventory_task.result() if inventory_task else ()
    samples: Sequence[ObjectSample] = objects_task.result() if objects_task else ()
    return buckets, samples


def _classify(samples: Sequence[ObjectSample]) -> dict[str, list[ClassifierLabel]]:
    """Stage 2 — run the Task-3 classifier over object-sample text, aggregating
    label hits per bucket.

    **Q6 INVARIANT** — only the returned label enum is retained per sample;
    the sample bytes themselves are NOT persisted in any cross-stage map.
    Each iteration's local reference to the sample bytes is dropped at the
    next iteration. The returned dict carries only label enum values.
    """
    hits_by_bucket: dict[str, list[ClassifierLabel]] = {}
    for sample in samples:
        # Q6: classify returns label only; matched substring is never returned.
        # classify_bytes transparently decodes gzip/base64 wrappers (gap #3).
        label = classify_bytes(sample.content_sample)
        if label == ClassifierLabel.NONE:
            continue
        hits_by_bucket.setdefault(sample.bucket, []).append(label)
        # The local ``sample`` reference goes out of scope at the next iter;
        # no module-level cache or aggregation includes the bytes.
    return hits_by_bucket


def _detect_all(
    buckets: Sequence[BucketInventory],
    *,
    classifier_hits_by_bucket: dict[str, list[ClassifierLabel]],
    envelope: NexusEnvelope,
    scan_time: datetime,
    trusted_sensitivity_tag: str,
) -> list[CloudPostureFinding]:
    """Stage 3 — run all 4 detectors over every bucket.

    Each detector is a pure function; sequence numbers are assigned
    monotonically across all detector outputs for finding-id uniqueness.
    """
    findings: list[CloudPostureFinding] = []
    sequence = 0
    for bucket in buckets:
        bucket_hits = classifier_hits_by_bucket.get(bucket.name, [])

        sequence += 1
        findings.extend(
            detect_public_bucket(
                bucket,
                classifier_hits=bucket_hits,
                envelope=envelope,
                detected_at=scan_time,
                sequence=sequence,
            )
        )

        sequence += 1
        findings.extend(
            detect_unencrypted(
                bucket,
                classifier_hits=bucket_hits,
                envelope=envelope,
                detected_at=scan_time,
                sequence=sequence,
            )
        )

        sequence += 1
        findings.extend(
            detect_sensitive_location(
                bucket,
                classifier_hits=bucket_hits,
                envelope=envelope,
                detected_at=scan_time,
                sequence=sequence,
                trusted_tag_value=trusted_sensitivity_tag,
            )
        )

        sequence += 1
        findings.extend(
            detect_oversharing_iam(
                bucket,
                classifier_hits=bucket_hits,
                envelope=envelope,
                detected_at=scan_time,
                sequence=sequence,
            )
        )

    return findings


async def _correlate(
    ctx: Charter,
    *,
    d5_findings: list[CloudPostureFinding],
    cloud_posture_workspace: Path | str | None,
) -> CorrelationResult:
    """Stage 4 — read the operator-pinned F.3 workspace if provided, then
    correlate by bucket ARN. Returns an empty ``CorrelationResult`` when
    no workspace is pinned or no F.3 findings load.
    """
    if not cloud_posture_workspace:
        return CorrelationResult()
    workspace_path = Path(cloud_posture_workspace)
    f3_findings = await ctx.call_tool("read_f3_findings", workspace_path=workspace_path)
    return correlate_with_f3(d5_findings, f3_findings)


__all__ = ["build_registry", "run"]
