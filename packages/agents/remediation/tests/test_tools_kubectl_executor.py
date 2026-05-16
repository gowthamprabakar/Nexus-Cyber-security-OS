"""Tests for `remediation.tools.kubectl_executor` — Stage 4/5 of the pipeline.

Tests **never** invoke the real `kubectl` binary. We monkeypatch `_run` to
inject deterministic results (matching the pattern D.6 uses to mock the
kubernetes SDK in `test_tools_cluster_workloads`).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from remediation.schemas import RemediationActionType, RemediationArtifact
from remediation.tools import kubectl_executor as mod
from remediation.tools.kubectl_executor import (
    KubectlExecutorError,
    PatchResult,
    apply_patch,
    fetch_resource,
    hash_resource,
)


def _artifact() -> RemediationArtifact:
    return RemediationArtifact(
        action_type=RemediationActionType.K8S_PATCH_RUN_AS_NON_ROOT,
        api_version="apps/v1",
        kind="Deployment",
        namespace="production",
        name="frontend",
        patch_strategy="strategic",
        patch_body={
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx",
                                "securityContext": {"runAsNonRoot": True, "runAsUser": 65532},
                            }
                        ]
                    }
                }
            }
        },
        inverse_patch_body={
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx",
                                "securityContext": {"runAsNonRoot": None, "runAsUser": None},
                            }
                        ]
                    }
                }
            }
        },
        source_finding_uid="CSPM-KUBERNETES-MANIFEST-001-run-as-root-frontend",
        correlation_id="corr-test",
    )


# A fake _run helper that maps commands → (exit_code, stdout, stderr).
class _FakeRunner:
    """Helper that records every invocation and returns scripted responses."""

    def __init__(self) -> None:
        self.calls: list[Sequence[str]] = []
        self.responses: list[tuple[int, str, str]] = []

    def queue(self, exit_code: int, stdout: str = "", stderr: str = "") -> None:
        """Queue one response; FIFO."""
        self.responses.append((exit_code, stdout, stderr))

    async def __call__(self, cmd: Sequence[str]) -> tuple[int, str, str]:
        self.calls.append(list(cmd))
        if not self.responses:
            return 0, "", ""
        return self.responses.pop(0)


@pytest.fixture
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> _FakeRunner:
    """Replace `_run` with a scriptable fake. Also ensures `_kubectl_binary` succeeds."""
    runner = _FakeRunner()
    monkeypatch.setattr(mod, "_run", runner)
    monkeypatch.setattr(mod, "_kubectl_binary", lambda: "/usr/local/bin/kubectl")
    return runner


# ---------------------------- _kubectl_binary discovery ------------------


def test_kubectl_binary_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """When kubectl isn't on PATH, the executor raises with an actionable message."""
    monkeypatch.setattr(mod.shutil, "which", lambda _: None)
    with pytest.raises(KubectlExecutorError, match="kubectl binary not found"):
        mod._kubectl_binary()


# ---------------------------- hash_resource -------------------------------


def test_hash_resource_is_deterministic() -> None:
    """The hash must be stable across key-order permutations of the same dict."""
    a = {"a": 1, "b": {"c": 2, "d": 3}}
    b = {"b": {"d": 3, "c": 2}, "a": 1}  # same content, different insertion order
    assert hash_resource(a) == hash_resource(b)


def test_hash_resource_differs_for_different_content() -> None:
    a = {"a": 1}
    b = {"a": 2}
    assert hash_resource(a) != hash_resource(b)


def test_hash_resource_is_sha256_hex() -> None:
    """SHA-256 hex digest is 64 chars of [0-9a-f]."""
    h = hash_resource({"x": 1})
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


# ---------------------------- fetch_resource ------------------------------


@pytest.mark.asyncio
async def test_fetch_resource_happy_path(fake_runner: _FakeRunner) -> None:
    """kubectl get <kind>/<name> -o json returns parsed dict + exit 0."""
    fake_runner.queue(
        0,
        json.dumps(
            {"kind": "Deployment", "metadata": {"name": "frontend", "namespace": "production"}}
        ),
    )
    rc, resource, stderr = await fetch_resource(
        kind="Deployment", name="frontend", namespace="production"
    )
    assert rc == 0
    assert resource is not None
    assert resource["kind"] == "Deployment"
    assert stderr == ""


@pytest.mark.asyncio
async def test_fetch_resource_404_returns_none_with_stderr(fake_runner: _FakeRunner) -> None:
    """A `kubectl get` against a non-existent resource yields exit 1 + None."""
    fake_runner.queue(1, "", 'Error from server (NotFound): deployments.apps "missing" not found')
    rc, resource, stderr = await fetch_resource(
        kind="Deployment", name="missing", namespace="production"
    )
    assert rc == 1
    assert resource is None
    assert "NotFound" in stderr


@pytest.mark.asyncio
async def test_fetch_resource_non_json_stdout_returns_none(fake_runner: _FakeRunner) -> None:
    """If stdout isn't parseable JSON, the parsed-resource is None — defensive."""
    fake_runner.queue(0, "not valid json {{")
    rc, resource, stderr = await fetch_resource(
        kind="Deployment", name="frontend", namespace="production"
    )
    assert rc == 0
    assert resource is None
    assert "non-JSON" in stderr


@pytest.mark.asyncio
async def test_fetch_resource_uses_kubeconfig_flag(
    fake_runner: _FakeRunner, tmp_path: Path
) -> None:
    """When kubeconfig is provided, the executor passes --kubeconfig <path> to kubectl."""
    fake_runner.queue(0, "{}")
    kc = tmp_path / "kc.yaml"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    await fetch_resource(
        kind="Pod",
        name="x",
        namespace="default",
        kubeconfig=kc,
    )
    cmd = fake_runner.calls[0]
    assert "--kubeconfig" in cmd
    assert str(kc) in cmd


@pytest.mark.asyncio
async def test_fetch_resource_omits_kubeconfig_when_none(fake_runner: _FakeRunner) -> None:
    """In-cluster mode (kubeconfig=None): kubectl picks up the Pod's SA token via default
    discovery — the executor doesn't pass `--kubeconfig`."""
    fake_runner.queue(0, "{}")
    await fetch_resource(kind="Pod", name="x", namespace="default")
    cmd = fake_runner.calls[0]
    assert "--kubeconfig" not in cmd


# ---------------------------- apply_patch (dry-run) -----------------------


@pytest.mark.asyncio
async def test_apply_patch_dry_run_adds_server_flag(fake_runner: _FakeRunner) -> None:
    """`dry_run=True` adds `--dry-run=server` to the kubectl command."""
    fake_runner.queue(0, "deployment.apps/frontend patched (dry run)")
    result = await apply_patch(_artifact(), dry_run=True)
    cmd = fake_runner.calls[0]
    assert "--dry-run=server" in cmd
    assert result.dry_run is True
    assert result.succeeded is True


@pytest.mark.asyncio
async def test_apply_patch_dry_run_skips_state_capture(fake_runner: _FakeRunner) -> None:
    """In dry-run mode, no pre/post-fetch happens — only one kubectl call."""
    fake_runner.queue(0, "deployment.apps/frontend patched (dry run)")
    result = await apply_patch(_artifact(), dry_run=True)
    assert len(fake_runner.calls) == 1  # only the patch call, no pre/post fetch
    assert result.pre_patch_hash is None
    assert result.post_patch_hash is None


@pytest.mark.asyncio
async def test_apply_patch_dry_run_failure_returns_non_zero(fake_runner: _FakeRunner) -> None:
    fake_runner.queue(1, "", "error: validation failed")
    result = await apply_patch(_artifact(), dry_run=True)
    assert result.exit_code == 1
    assert result.succeeded is False
    assert "validation failed" in result.stderr


# ---------------------------- apply_patch (execute, with state capture) ---


@pytest.mark.asyncio
async def test_apply_patch_execute_captures_pre_and_post_state(
    fake_runner: _FakeRunner,
) -> None:
    """In execute mode with fetch_state=True, the executor:
    1. fetches pre-patch resource (call 0)
    2. applies patch (call 1)
    3. fetches post-patch resource (call 2)
    and returns hashes for both."""
    pre_resource = {"kind": "Deployment", "spec": {"replicas": 3}}
    post_resource = {
        "kind": "Deployment",
        "spec": {"replicas": 3, "template": {"spec": {"securityContext": {"runAsNonRoot": True}}}},
    }
    fake_runner.queue(0, json.dumps(pre_resource))  # pre-fetch
    fake_runner.queue(0, "deployment.apps/frontend patched")  # patch
    fake_runner.queue(0, json.dumps(post_resource))  # post-fetch

    result = await apply_patch(_artifact(), dry_run=False, fetch_state=True)

    assert len(fake_runner.calls) == 3
    assert result.exit_code == 0
    assert result.pre_patch_hash is not None
    assert result.post_patch_hash is not None
    assert result.pre_patch_hash != result.post_patch_hash
    assert result.pre_patch_resource == pre_resource
    assert result.post_patch_resource == post_resource


@pytest.mark.asyncio
async def test_apply_patch_execute_skips_post_fetch_when_patch_fails(
    fake_runner: _FakeRunner,
) -> None:
    """If the patch itself fails (e.g. RBAC denied), the executor records the pre-patch
    state but does NOT attempt a post-fetch — there's nothing new to capture."""
    fake_runner.queue(0, json.dumps({"kind": "Deployment"}))  # pre-fetch ok
    fake_runner.queue(1, "", "error: admission webhook rejected")  # patch fails
    result = await apply_patch(_artifact(), dry_run=False, fetch_state=True)
    # Pre-fetch ran (call 0), patch ran (call 1), but NO post-fetch (no call 2).
    assert len(fake_runner.calls) == 2
    assert result.exit_code == 1
    assert result.succeeded is False
    assert result.pre_patch_hash is not None
    assert result.post_patch_hash is None


@pytest.mark.asyncio
async def test_apply_patch_execute_handles_pre_fetch_failure(fake_runner: _FakeRunner) -> None:
    """If the pre-fetch fails (resource not found / RBAC), the executor still proceeds
    with the patch — pre_patch_hash stays None but the patch is attempted."""
    fake_runner.queue(1, "", "Error: NotFound")  # pre-fetch fails
    fake_runner.queue(0, "deployment.apps/frontend patched")  # patch succeeds
    fake_runner.queue(0, json.dumps({"kind": "Deployment"}))  # post-fetch ok
    result = await apply_patch(_artifact(), dry_run=False, fetch_state=True)
    assert result.pre_patch_hash is None
    assert result.post_patch_hash is not None
    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_apply_patch_execute_with_fetch_state_false_skips_both(
    fake_runner: _FakeRunner,
) -> None:
    """`fetch_state=False` skips pre + post fetch — operators can opt out for fast paths."""
    fake_runner.queue(0, "deployment.apps/frontend patched")
    result = await apply_patch(_artifact(), dry_run=False, fetch_state=False)
    assert len(fake_runner.calls) == 1  # only the patch
    assert result.pre_patch_hash is None
    assert result.post_patch_hash is None


# ---------------------------- command structure ---------------------------


@pytest.mark.asyncio
async def test_apply_patch_command_uses_strategic_merge_type(fake_runner: _FakeRunner) -> None:
    """The artifact's `patch_strategy` flows through to `--type <strategy>`."""
    fake_runner.queue(0, "")
    await apply_patch(_artifact(), dry_run=True)
    cmd = fake_runner.calls[0]
    assert "--type" in cmd
    type_idx = cmd.index("--type")
    assert cmd[type_idx + 1] == "strategic"


@pytest.mark.asyncio
async def test_apply_patch_command_includes_patch_body_as_json(
    fake_runner: _FakeRunner,
) -> None:
    """The patch body is serialised as JSON and passed via `-p`."""
    fake_runner.queue(0, "")
    artifact = _artifact()
    await apply_patch(artifact, dry_run=True)
    cmd = fake_runner.calls[0]
    p_idx = cmd.index("-p")
    payload = json.loads(cmd[p_idx + 1])
    assert payload == artifact.patch_body


@pytest.mark.asyncio
async def test_apply_patch_command_uses_lowercase_kind(fake_runner: _FakeRunner) -> None:
    """kubectl expects `deployment`, not `Deployment` — the executor lowercases the kind."""
    fake_runner.queue(0, "")
    await apply_patch(_artifact(), dry_run=True)
    cmd = fake_runner.calls[0]
    # Find the position right after "patch" in the command.
    patch_idx = cmd.index("patch")
    assert cmd[patch_idx + 1] == "deployment"  # lowercased from "Deployment"


@pytest.mark.asyncio
async def test_apply_patch_command_targets_correct_namespace(fake_runner: _FakeRunner) -> None:
    fake_runner.queue(0, "")
    await apply_patch(_artifact(), dry_run=True)
    cmd = fake_runner.calls[0]
    n_idx = cmd.index("-n")
    assert cmd[n_idx + 1] == "production"


@pytest.mark.asyncio
async def test_apply_patch_command_uses_kubeconfig_when_set(
    fake_runner: _FakeRunner, tmp_path: Path
) -> None:
    fake_runner.queue(0, "")
    kc = tmp_path / "kc.yaml"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    await apply_patch(_artifact(), dry_run=True, kubeconfig=kc)
    cmd = fake_runner.calls[0]
    assert "--kubeconfig" in cmd
    kc_idx = cmd.index("--kubeconfig")
    assert cmd[kc_idx + 1] == str(kc)


# ---------------------------- PatchResult shape ---------------------------


def test_patch_result_is_frozen() -> None:
    """PatchResult is immutable — preserves the audit trail."""
    result = PatchResult(
        exit_code=0,
        stdout="",
        stderr="",
        dry_run=False,
        pre_patch_hash="x",
        post_patch_hash="y",
        pre_patch_resource={},
        post_patch_resource={},
    )
    with pytest.raises((TypeError, AttributeError)):
        result.exit_code = 1  # type: ignore[misc]


def test_patch_result_succeeded_property() -> None:
    """`succeeded` is a convenience for exit_code == 0."""
    ok = PatchResult(
        exit_code=0,
        stdout="",
        stderr="",
        dry_run=False,
        pre_patch_hash=None,
        post_patch_hash=None,
        pre_patch_resource=None,
        post_patch_resource=None,
    )
    fail = PatchResult(
        exit_code=1,
        stdout="",
        stderr="oops",
        dry_run=False,
        pre_patch_hash=None,
        post_patch_hash=None,
        pre_patch_resource=None,
        post_patch_resource=None,
    )
    assert ok.succeeded is True
    assert fail.succeeded is False


# ---------------------------- typed payload ------------------------------


def test_apply_patch_signature_accepts_only_known_args() -> None:
    """Signature smoke: `apply_patch` accepts artifact, dry_run, kubeconfig, fetch_state."""
    import inspect

    sig = inspect.signature(apply_patch)
    expected_params: set[str] = {"artifact", "dry_run", "kubeconfig", "fetch_state"}
    assert set(sig.parameters) == expected_params


# Ensure `Any` import is used (silences unused-import lints in test).
_ = Any
