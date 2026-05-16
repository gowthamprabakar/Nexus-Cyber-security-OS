"""Async wrapper around `kubectl patch` — Stage 4 (DRY-RUN) + Stage 5 (EXECUTE).

The executor shells out to the operator-installed `kubectl` binary. We don't
use the kubernetes Python SDK for the apply path because:

1. The SDK's `patch_namespaced_*` methods require per-kind dispatch
   (CoreV1Api / AppsV1Api / BatchV1Api), which would duplicate D.6's call
   tables and rot in lockstep. `kubectl` already knows the dispatch.
2. `kubectl` understands strategic-merge-patch natively (the patch type
   our action classes emit). The SDK's strategic-merge requires more
   manual content-type juggling.
3. `kubectl --dry-run=server` is the audited path that operators trust;
   the SDK's dry-run mode is less battle-tested.

**Cluster access** mirrors D.6 v0.2/v0.3:
- `kubeconfig: Path | None = None` — passes `--kubeconfig <path>` when set.
- When `kubeconfig is None`, kubectl uses default discovery (KUBECONFIG env
  var, ~/.kube/config, or in-cluster SA mount). The agent driver passes
  None in `--in-cluster` mode.

**State capture for audit** — when `fetch_state=True` and not dry-run, the
executor:
1. Runs `kubectl get <kind>/<name> -o json` BEFORE the patch.
2. Computes SHA-256 of that JSON → `pre_patch_hash`.
3. Applies the patch.
4. Re-fetches and computes `post_patch_hash`.

Hashes go into the audit chain (Task 9). Operators can verify post-execution
state matches the recorded hash to detect tampering.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from remediation.schemas import RemediationArtifact


class KubectlExecutorError(RuntimeError):
    """Raised when the kubectl binary is missing or invocation cannot be initialised."""


@dataclass(frozen=True)
class PatchResult:
    """Structured result of a single `kubectl patch` invocation."""

    exit_code: int
    stdout: str
    stderr: str
    dry_run: bool
    pre_patch_hash: str | None
    post_patch_hash: str | None
    pre_patch_resource: dict[str, Any] | None
    post_patch_resource: dict[str, Any] | None

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0


def _hash_payload(payload: str) -> str:
    """SHA-256 hex digest of a JSON payload string. Used for audit-chain hashes."""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _kubectl_binary() -> str:
    """Locate the `kubectl` binary on the operator's PATH.

    Raises `KubectlExecutorError` when missing — caught by the agent driver
    and surfaced as a `RemediationOutcome.EXECUTE_FAILED` per-run.
    """
    path = shutil.which("kubectl")
    if path is None:
        raise KubectlExecutorError(
            "kubectl binary not found on PATH — install kubectl and re-run, or "
            "use --mode recommend (no execution required)"
        )
    return path


async def _run(cmd: Sequence[str]) -> tuple[int, str, str]:
    """Run a subprocess, return (exit_code, stdout, stderr) as text.

    All cluster-touching paths in A.1 flow through this — tests monkeypatch
    it to inject deterministic results without invoking the real binary.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, stderr_b = await proc.communicate()
    exit_code = proc.returncode if proc.returncode is not None else -1
    return (
        exit_code,
        stdout_b.decode("utf-8", errors="replace"),
        stderr_b.decode("utf-8", errors="replace"),
    )


async def fetch_resource(
    *,
    kind: str,
    name: str,
    namespace: str,
    kubeconfig: Path | None = None,
) -> tuple[int, dict[str, Any] | None, str]:
    """Fetch a K8s resource as JSON. Used for pre/post-patch state capture.

    Returns `(exit_code, parsed_resource_or_None, stderr)`. A non-zero exit
    means the resource couldn't be fetched (RBAC denied, not found, etc.);
    the caller decides whether that's fatal.
    """
    binary = _kubectl_binary()
    cmd: list[str] = [
        binary,
        "get",
        kind.lower(),
        name,
        "-n",
        namespace,
        "-o",
        "json",
    ]
    if kubeconfig is not None:
        cmd.extend(["--kubeconfig", str(kubeconfig)])

    exit_code, stdout, stderr = await _run(cmd)
    if exit_code != 0:
        return exit_code, None, stderr
    try:
        resource = json.loads(stdout)
    except json.JSONDecodeError:
        return exit_code, None, "kubectl get returned non-JSON output"
    return exit_code, resource, stderr


async def apply_patch(
    artifact: RemediationArtifact,
    *,
    dry_run: bool,
    kubeconfig: Path | None = None,
    fetch_state: bool = True,
) -> PatchResult:
    """Apply a strategic-merge-patch via `kubectl patch`.

    Args:
        artifact: The `RemediationArtifact` to apply. Its `patch_body` is
            serialised as JSON and passed via `-p`.
        dry_run: When True, adds `--dry-run=server`. The server validates the
            patch (catches admission-webhook rejections, schema violations,
            etc.) but does NOT persist the change.
        kubeconfig: Optional explicit kubeconfig path (v0.2 mode). When None,
            kubectl uses default discovery (v0.3 in-cluster mode is a special
            case of None — kubectl reads SA token from the Pod mount).
        fetch_state: When True (and not dry-run), fetch the resource before +
            after the patch and record SHA-256 hashes for the audit chain.
            Defaults to True for `execute` mode; the agent driver passes
            False when state capture isn't needed (e.g. when the operator
            opts out via the contract).

    Returns:
        `PatchResult` carrying exit code, stdout/stderr, dry-run flag, and
        — when applicable — pre/post-patch hashes + parsed resource bodies.
    """
    binary = _kubectl_binary()
    patch_json = json.dumps(artifact.patch_body)
    cmd: list[str] = [
        binary,
        "patch",
        artifact.kind.lower(),
        artifact.name,
        "-n",
        artifact.namespace,
        "--type",
        artifact.patch_strategy,
        "-p",
        patch_json,
    ]
    if dry_run:
        cmd.extend(["--dry-run=server"])
    if kubeconfig is not None:
        cmd.extend(["--kubeconfig", str(kubeconfig)])

    # Pre-patch state capture (skip in dry-run — there's nothing to compare to).
    pre_patch_resource: dict[str, Any] | None = None
    pre_patch_hash: str | None = None
    if fetch_state and not dry_run:
        rc, resource, _ = await fetch_resource(
            kind=artifact.kind,
            name=artifact.name,
            namespace=artifact.namespace,
            kubeconfig=kubeconfig,
        )
        if rc == 0 and resource is not None:
            pre_patch_resource = resource
            pre_patch_hash = _hash_payload(json.dumps(resource, sort_keys=True))

    # Apply the patch.
    exit_code, stdout, stderr = await _run(cmd)

    # Post-patch state capture (only when patch succeeded AND not dry-run).
    post_patch_resource: dict[str, Any] | None = None
    post_patch_hash: str | None = None
    if fetch_state and not dry_run and exit_code == 0:
        rc, resource, _ = await fetch_resource(
            kind=artifact.kind,
            name=artifact.name,
            namespace=artifact.namespace,
            kubeconfig=kubeconfig,
        )
        if rc == 0 and resource is not None:
            post_patch_resource = resource
            post_patch_hash = _hash_payload(json.dumps(resource, sort_keys=True))

    return PatchResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        dry_run=dry_run,
        pre_patch_hash=pre_patch_hash,
        post_patch_hash=post_patch_hash,
        pre_patch_resource=pre_patch_resource,
        post_patch_resource=post_patch_resource,
    )


def hash_resource(resource: Mapping[str, Any]) -> str:
    """Compute the SHA-256 hex digest of a resource dict, sort_keys-deterministic.

    Exposed so the agent driver + audit code can hash arbitrary resource
    snapshots (e.g., the rollback flow re-hashes after applying the inverse
    patch).
    """
    return _hash_payload(json.dumps(resource, sort_keys=True))


__all__ = [
    "KubectlExecutorError",
    "PatchResult",
    "apply_patch",
    "fetch_resource",
    "hash_resource",
]
