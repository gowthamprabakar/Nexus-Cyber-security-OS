"""`validator` — Stage 6 (VALIDATE) + Stage 7 (ROLLBACK) of the pipeline.

**Critical safety code.** This is where A.1 decides whether an executed
patch actually fixed the problem, or whether to roll it back.

Stage 6 — `validate_outcome`:

1. Waits `rollback_window_sec` seconds (configurable via `Authorization`;
   default 300s; capped 1800s). The wait gives the K8s control plane
   time to apply the patch: a Deployment patch propagates to its Pods on
   the next reconcile, which can take 10-90s; a pod-spec patch is
   nearly instant but webhooks may add latency.
2. Re-runs the D.6 manifest analyser against **only the affected workload**.
   The detector reads the live manifest (via the kubernetes SDK if
   in-cluster mode, else kubeconfig) and checks: is the original
   `rule_id` still firing?
3. Returns a `ValidationResult` — either `validated` (rule_id gone →
   patch worked) or `requires_rollback` (rule_id still present → patch
   didn't fix the issue; roll it back).

Stage 7 — `rollback`:

1. Applies the artifact's **inverse_patch_body** via `apply_patch` (same
   kubectl path Stage 5 used, no dry-run).
2. The inverse patch removes the fields Stage 5 added — returns the
   workload to its pre-patch shape (matching what D.6 originally
   flagged as the problem; the operator knew the issue existed before).
3. Records a `RolledBack` outcome in the audit chain (Task 9 wires this).

**Why the validator re-runs D.6 instead of inspecting the patch directly:**

A K8s patch can succeed at the API layer but fail at the runtime layer
(controller webhook rejects the spec change; the Pod doesn't restart;
the patch race-conditions against another writer). Only a post-validation
detector pass tells us whether the *vulnerability* is gone, not just
whether the *patch* applied. This is the gold-standard safety contract:
re-detect, don't just re-apply.

**Why we use the same D.6 reader path A.1 originally ingested from:**

The `--findings PATH` input gave us a snapshot of D.6 findings. The
validator runs the live D.6 detector against the post-patch cluster,
not the snapshot. This requires the agent to be in `--kubeconfig` or
`--in-cluster` mode (the two modes that have a live cluster connection);
the artifact-only mode disables Stages 4-7 entirely.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from k8s_posture.tools.cluster_workloads import read_cluster_workloads
from k8s_posture.tools.manifests import ManifestFinding

from remediation.schemas import RemediationArtifact
from remediation.tools.kubectl_executor import PatchResult, apply_patch


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of Stage 6 — did the patch resolve the source finding?"""

    requires_rollback: bool
    """True iff the original rule_id is still firing on the affected workload."""

    matched_findings: tuple[ManifestFinding, ...]
    """The post-patch findings filtered to the patched workload+rule. Non-empty
    when `requires_rollback` is True (those are the findings the rollback is
    responding to)."""

    @property
    def validated(self) -> bool:
        return not self.requires_rollback


# Type alias for the detector callable. The agent driver passes a closure
# that wraps `read_cluster_workloads` with the right cluster-access config
# (kubeconfig path / in_cluster bool / cluster_namespace). Tests inject
# fakes here without monkey-patching the SDK.
DetectorCallable = Callable[[], Awaitable[tuple[ManifestFinding, ...]]]


# ---------------------------- Stage 6: validate --------------------------


async def validate_outcome(
    *,
    artifact: RemediationArtifact,
    source_rule_id: str,
    detector: DetectorCallable,
    rollback_window_sec: int,
) -> ValidationResult:
    """Wait the rollback window, re-run the detector, decide on rollback.

    Args:
        artifact: The artifact that was just executed in Stage 5. Its
            (namespace, workload_name, container_name) tuple is the scope
            the validator filters the detector output against.
        source_rule_id: The original D.6 rule_id that triggered this
            remediation (e.g. `"run-as-root"`). The validator checks for
            this exact rule_id in the post-patch detector output.
        detector: An awaitable that returns a fresh tuple of `ManifestFinding`
            records from the live cluster. The agent driver pre-binds the
            cluster-access config; the validator doesn't know whether it's
            kubeconfig or in-cluster mode.
        rollback_window_sec: How long to wait between executing the patch
            and re-running the detector. `Authorization.rollback_window_sec`
            (60-1800; default 300) sets this.

    Returns:
        `ValidationResult`. `requires_rollback=True` iff the detector still
        sees the original rule_id firing on the same workload.
    """
    await asyncio.sleep(rollback_window_sec)
    fresh_findings = await detector()

    # Filter to the affected workload + the same rule_id.
    matched = tuple(
        f
        for f in fresh_findings
        if f.rule_id == source_rule_id
        and f.namespace == artifact.namespace
        and f.workload_kind == artifact.kind
        and f.workload_name == artifact.name
        and (artifact.kind != "Pod" or f.container_name == "")  # pod-level findings
        and (f.container_name == "" or _container_matches(f, artifact))
    )
    return ValidationResult(
        requires_rollback=bool(matched),
        matched_findings=matched,
    )


def _container_matches(finding: ManifestFinding, artifact: RemediationArtifact) -> bool:
    """Container-level findings carry the patched container name in the artifact's
    patch_body — extract and compare.

    For v0.1, every container-level action class wraps its container patch via
    `wrap_container_patch`, which puts the container name at the well-known
    location in the patch body. We compare against that.
    """
    body = artifact.patch_body
    # Walk the pod-spec path. We rely on the patch body matching the artifact's
    # workload kind via the same wrapping helper the action class used.
    candidate = body
    for key in ("spec", "template", "spec", "containers"):
        if not isinstance(candidate, dict):
            return False
        # `containers` is at the end and is a list — handle separately.
        if key == "containers":
            if not isinstance(candidate.get("containers"), list):
                return False
            containers = candidate["containers"]
            if not containers or not isinstance(containers[0], dict):
                return False
            patched_name = containers[0].get("name")
            return patched_name == finding.container_name
        candidate = candidate.get(key, {})
    return False


# ---------------------------- Stage 7: rollback --------------------------


async def rollback(
    artifact: RemediationArtifact,
    *,
    kubeconfig: Path | None = None,
) -> PatchResult:
    """Apply the artifact's inverse patch (returns the resource to its pre-patch state).

    Stage 7 fires only when Stage 6 returned `requires_rollback=True`. The
    inverse patch is whatever the action class emitted as `inverse_patch_body`
    when building the original artifact (every action class is a pure-function
    pair `(build, inverse)` — this is what makes deterministic rollback work).

    Args:
        artifact: The artifact whose execution we're rolling back. We swap
            `patch_body` with `inverse_patch_body` and re-apply.
        kubeconfig: Same cluster-access discipline as Stage 4/5. Defaults to
            None (in-cluster / default discovery).

    Returns:
        `PatchResult` from the inverse kubectl-patch invocation. The agent
        driver records pre/post-patch hashes in the audit chain.
    """
    inverse_artifact = RemediationArtifact(
        action_type=artifact.action_type,
        api_version=artifact.api_version,
        kind=artifact.kind,
        namespace=artifact.namespace,
        name=artifact.name,
        patch_strategy=artifact.patch_strategy,
        patch_body=artifact.inverse_patch_body,
        inverse_patch_body=artifact.patch_body,
        source_finding_uid=artifact.source_finding_uid,
        correlation_id=f"{artifact.correlation_id}-rollback",
    )
    return await apply_patch(
        inverse_artifact,
        dry_run=False,
        kubeconfig=kubeconfig,
        fetch_state=True,
    )


# ---------------------------- detector builder ---------------------------


def build_d6_detector(
    *,
    namespace: str,
    kubeconfig: Path | None,
    in_cluster: bool,
) -> DetectorCallable:
    """Build a closure that runs the D.6 manifest analyser against the live cluster.

    The agent driver calls this once per artifact (binding the affected
    namespace so the detector scan is scoped, not cluster-wide). The
    closure is what `validate_outcome` invokes after the rollback window.

    Args:
        namespace: The namespace the patched workload lives in. The
            detector scan is scoped to this namespace.
        kubeconfig: Same as everywhere else — explicit path OR None.
        in_cluster: Mirrors D.6 v0.3's flag. Mutually exclusive with a
            kubeconfig path (3-way exclusion already enforced upstream).
    """

    async def _detect() -> tuple[ManifestFinding, ...]:
        return await read_cluster_workloads(
            kubeconfig=kubeconfig,
            in_cluster=in_cluster,
            namespace=namespace,
        )

    return _detect


__all__ = [
    "DetectorCallable",
    "ValidationResult",
    "build_d6_detector",
    "rollback",
    "validate_outcome",
]
