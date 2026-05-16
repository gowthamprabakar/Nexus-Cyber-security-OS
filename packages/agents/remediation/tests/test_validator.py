"""Tests for `remediation.validator` — Stage 6 (VALIDATE) + Stage 7 (ROLLBACK).

Critical safety code. Mocks the detector callable, the `asyncio.sleep` for
the rollback window, and the executor `_run` for the rollback's kubectl
invocation.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from k8s_posture.tools.manifests import ManifestFinding
from remediation.action_classes._common import wrap_container_patch
from remediation.schemas import RemediationActionType, RemediationArtifact
from remediation.tools import kubectl_executor as kc_mod
from remediation.validator import (
    ValidationResult,
    build_d6_detector,
    rollback,
    validate_outcome,
)

NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)


def _finding(
    *,
    rule_id: str = "run-as-root",
    workload_kind: str = "Deployment",
    workload_name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule_id,
        rule_title=rule_id.replace("-", " ").title(),
        severity="high",
        workload_kind=workload_kind,
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        manifest_path="cluster:///production/Deployment/frontend",
        detected_at=NOW,
    )


def _artifact(
    *,
    action_type: RemediationActionType = RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
    kind: str = "Deployment",
    name: str = "frontend",
    namespace: str = "production",
    container_name: str = "nginx",
) -> RemediationArtifact:
    """Build an artifact whose patch_body matches the wrap_container_patch shape
    `validate_outcome._container_matches` expects."""
    finding = _finding(
        workload_kind=kind, workload_name=name, namespace=namespace, container_name=container_name
    )
    leaf = {"securityContext": {"runAsNonRoot": True}}
    inverse_leaf = {"securityContext": {"runAsNonRoot": None}}
    return RemediationArtifact(
        action_type=action_type,
        api_version="apps/v1" if kind != "Pod" else "v1",
        kind=kind,
        namespace=namespace,
        name=name,
        patch_strategy="strategic",
        patch_body=wrap_container_patch(finding, leaf),
        inverse_patch_body=wrap_container_patch(finding, inverse_leaf),
        source_finding_uid="CSPM-KUBERNETES-MANIFEST-001-x",
        correlation_id="corr-test",
    )


def _make_detector(
    *,
    findings: tuple[ManifestFinding, ...] = (),
) -> Callable[[], Awaitable[tuple[ManifestFinding, ...]]]:
    """Build a detector closure that returns the given findings on each call."""

    async def _detect() -> tuple[ManifestFinding, ...]:
        return findings

    return _detect


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch asyncio.sleep to be instant — tests shouldn't actually wait 300s.

    Applied to all tests in this file.
    """
    import remediation.validator as validator_mod

    async def _instant(_seconds: float) -> None:
        return None

    monkeypatch.setattr(validator_mod.asyncio, "sleep", _instant)


# ---------------------------- Stage 6: validate_outcome -------------------


@pytest.mark.asyncio
async def test_validate_outcome_succeeds_when_finding_gone() -> None:
    """The happy path — D.6 no longer reports the rule_id on the patched workload."""
    artifact = _artifact()
    detector = _make_detector(findings=())  # post-patch detector returns clean
    result = await validate_outcome(
        artifact=artifact,
        source_rule_id="run-as-root",
        detector=detector,
        rollback_window_sec=300,
    )
    assert result.validated is True
    assert result.requires_rollback is False
    assert result.matched_findings == ()


@pytest.mark.asyncio
async def test_validate_outcome_requires_rollback_when_finding_persists() -> None:
    """The patch was applied but the detector still sees the rule_id on the same
    workload+container — Stage 7 must roll the patch back."""
    artifact = _artifact()
    surviving = _finding(rule_id="run-as-root", workload_name="frontend", container_name="nginx")
    detector = _make_detector(findings=(surviving,))
    result = await validate_outcome(
        artifact=artifact,
        source_rule_id="run-as-root",
        detector=detector,
        rollback_window_sec=300,
    )
    assert result.requires_rollback is True
    assert len(result.matched_findings) == 1


@pytest.mark.asyncio
async def test_validate_outcome_ignores_unrelated_workloads() -> None:
    """A surviving finding on a *different* workload doesn't trigger rollback —
    we're only validating this workload's patch."""
    artifact = _artifact(name="frontend")
    other = _finding(rule_id="run-as-root", workload_name="api")  # different workload
    detector = _make_detector(findings=(other,))
    result = await validate_outcome(
        artifact=artifact,
        source_rule_id="run-as-root",
        detector=detector,
        rollback_window_sec=300,
    )
    assert result.validated is True
    assert result.matched_findings == ()


@pytest.mark.asyncio
async def test_validate_outcome_ignores_unrelated_rule_ids() -> None:
    """A different rule firing on the same workload isn't this patch's responsibility."""
    artifact = _artifact()
    other = _finding(
        rule_id="missing-resource-limits", workload_name="frontend", container_name="nginx"
    )
    detector = _make_detector(findings=(other,))
    result = await validate_outcome(
        artifact=artifact,
        source_rule_id="run-as-root",  # we patched run-as-root, not resource-limits
        detector=detector,
        rollback_window_sec=300,
    )
    assert result.validated is True


@pytest.mark.asyncio
async def test_validate_outcome_ignores_other_containers_in_same_workload() -> None:
    """A surviving finding on `sidecar` doesn't roll back our `nginx` patch."""
    artifact = _artifact(container_name="nginx")
    sidecar_finding = _finding(
        rule_id="run-as-root", workload_name="frontend", container_name="sidecar"
    )
    detector = _make_detector(findings=(sidecar_finding,))
    result = await validate_outcome(
        artifact=artifact,
        source_rule_id="run-as-root",
        detector=detector,
        rollback_window_sec=300,
    )
    assert result.validated is True


@pytest.mark.asyncio
async def test_validate_outcome_waits_for_rollback_window() -> None:
    """The validator must `await sleep(rollback_window_sec)` before calling the detector
    — gives K8s controllers time to reconcile."""
    import remediation.validator as validator_mod

    seen_seconds: list[float] = []

    async def _spy(seconds: float) -> None:
        seen_seconds.append(seconds)

    # Override the autouse `fast_sleep` for this one test.
    original_sleep = validator_mod.asyncio.sleep
    validator_mod.asyncio.sleep = _spy  # type: ignore[assignment]
    try:
        await validate_outcome(
            artifact=_artifact(),
            source_rule_id="run-as-root",
            detector=_make_detector(),
            rollback_window_sec=600,
        )
    finally:
        validator_mod.asyncio.sleep = original_sleep  # type: ignore[assignment]
    assert seen_seconds == [600]


# ---------------------------- Stage 7: rollback ---------------------------


@pytest.mark.asyncio
async def test_rollback_swaps_patch_for_inverse(monkeypatch: pytest.MonkeyPatch) -> None:
    """`rollback` must call kubectl with the artifact's `inverse_patch_body` as the
    new patch body."""

    captured: dict[str, Any] = {}

    async def fake_run(cmd: Sequence[str]) -> tuple[int, str, str]:
        captured.setdefault("calls", []).append(list(cmd))
        return 0, "", ""

    monkeypatch.setattr(kc_mod, "_run", fake_run)
    monkeypatch.setattr(kc_mod, "_kubectl_binary", lambda: "/usr/local/bin/kubectl")

    artifact = _artifact()
    result = await rollback(artifact)

    # Three calls expected: pre-fetch, patch, post-fetch (state capture is default).
    calls = captured["calls"]
    assert len(calls) == 3
    patch_call = calls[1]
    # The patch body passed to kubectl is the artifact's inverse_patch_body.
    import json

    p_idx = patch_call.index("-p")
    payload = json.loads(patch_call[p_idx + 1])
    assert payload == artifact.inverse_patch_body
    # Rollback runs in execute mode (no --dry-run).
    assert "--dry-run=server" not in patch_call
    # PatchResult succeeded (exit 0).
    assert result.succeeded


@pytest.mark.asyncio
async def test_rollback_uses_kubeconfig_when_provided(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Same cluster-access discipline as Stage 4/5 — explicit kubeconfig is honoured."""

    captured: list[Sequence[str]] = []

    async def fake_run(cmd: Sequence[str]) -> tuple[int, str, str]:
        captured.append(list(cmd))
        return 0, "{}", ""

    monkeypatch.setattr(kc_mod, "_run", fake_run)
    monkeypatch.setattr(kc_mod, "_kubectl_binary", lambda: "/usr/local/bin/kubectl")
    kc = tmp_path / "kc.yaml"
    kc.write_text("apiVersion: v1\nkind: Config\n")

    await rollback(_artifact(), kubeconfig=kc)
    # Every kubectl invocation should carry --kubeconfig.
    for cmd in captured:
        assert "--kubeconfig" in cmd
        assert str(kc) in cmd


# ---------------------------- build_d6_detector ---------------------------


def test_build_d6_detector_returns_a_coroutine_callable() -> None:
    """The detector builder returns a callable that produces an awaitable."""
    import inspect

    det = build_d6_detector(namespace="production", kubeconfig=None, in_cluster=False)
    assert callable(det)
    assert inspect.iscoroutinefunction(det)


@pytest.mark.asyncio
async def test_build_d6_detector_forwards_args_to_read_cluster_workloads(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The closure must call read_cluster_workloads with the bound (namespace,
    kubeconfig, in_cluster) tuple."""
    captured: dict[str, Any] = {}

    async def fake_read(**kwargs: Any) -> tuple[ManifestFinding, ...]:
        captured.update(kwargs)
        return ()

    # Patch at the validator import site.
    import remediation.validator as validator_mod

    monkeypatch.setattr(validator_mod, "read_cluster_workloads", fake_read)

    kc = tmp_path / "kc.yaml"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    detector = build_d6_detector(
        namespace="production",
        kubeconfig=kc,
        in_cluster=False,
    )
    await detector()
    assert captured["namespace"] == "production"
    assert captured["kubeconfig"] == kc
    assert captured["in_cluster"] is False


# ---------------------------- ValidationResult shape ----------------------


def test_validation_result_is_frozen() -> None:
    result = ValidationResult(requires_rollback=False, matched_findings=())
    with pytest.raises((TypeError, AttributeError)):
        result.requires_rollback = True  # type: ignore[misc]


def test_validation_result_validated_is_inverse_of_rollback() -> None:
    assert ValidationResult(requires_rollback=False, matched_findings=()).validated is True
    finding = _finding()
    assert ValidationResult(requires_rollback=True, matched_findings=(finding,)).validated is False
