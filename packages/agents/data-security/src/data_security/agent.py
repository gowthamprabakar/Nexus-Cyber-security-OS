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
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from data_security import __version__ as agent_version
from data_security.classifiers import classify
from data_security.correlate import (
    CorrelationResult,
    correlate_with_f3,
    read_f3_findings,
)
from data_security.detectors import (
    detect_oversharing_iam,
    detect_public_bucket,
    detect_sensitive_location,
    detect_unencrypted,
)
from data_security.schemas import (
    ClassifierLabel,
    CloudPostureFinding,
    FindingsReport,
)
from data_security.scorer import apply_correlation_uplift
from data_security.summarizer import render_summary
from data_security.tools import (
    BucketInventory,
    ObjectSample,
    read_s3_inventory,
    read_s3_objects,
)

DEFAULT_NLAH_VERSION = "0.1.0"


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent."""
    reg = ToolRegistry()
    reg.register("read_s3_inventory", read_s3_inventory, version="0.1.0", cloud_calls=0)
    reg.register("read_s3_objects", read_s3_objects, version="0.1.0", cloud_calls=0)
    reg.register("read_f3_findings", read_f3_findings, version="0.1.0", cloud_calls=0)
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
    cloud_posture_workspace: Path | str | None = None,
    trusted_sensitivity_tag: str = "Restricted",
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
        cloud_posture_workspace: Optional path to a sibling F.3 workspace
            directory containing ``findings.json`` (Q4). When present,
            Stage 4 CORRELATE runs and Stage 5 SCORE uplifts severity for
            matched findings.
        trusted_sensitivity_tag: Override for the trusted ``Sensitivity``
            tag value (defaults to ``"Restricted"`` — the documented
            common AWS Data Classification posture).

    Returns:
        The ``FindingsReport``. Side effects: writes ``findings.json`` and
        ``report.md`` to the charter workspace; charter emits the implicit
        per-stage audit log to ``audit.jsonl``.
    """
    del llm_provider  # reserved for future iterations

    registry = build_registry()
    model_pin = "deterministic"
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)

        # Stage 1 — INGEST: two feeds concurrent via TaskGroup.
        buckets, samples = await _ingest(
            ctx,
            s3_inventory_feed=s3_inventory_feed,
            s3_objects_feed=s3_objects_feed,
        )

        # Stage 2 — CLASSIFY: per-bucket classifier-label aggregation.
        # Q6 INVARIANT: only labels are kept; sample bytes are released
        # after the classifier returns its enum value.
        classifier_hits_by_bucket = _classify(samples)

        # Stage 3 — DETECT: 4 detectors per bucket.
        d5_findings = _detect_all(
            buckets,
            classifier_hits_by_bucket=classifier_hits_by_bucket,
            envelope=envelope,
            scan_time=scan_started,
            trusted_sensitivity_tag=trusted_sensitivity_tag,
        )

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
) -> tuple[Sequence[BucketInventory], Sequence[ObjectSample]]:
    """Stage 1 — fan out the two feeds via TaskGroup. Skipped feed → empty tuple."""
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
        label = classify(sample.decoded_text())
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
