"""`read_manifests` — flat-directory manifest static analysis.

Reads a directory of `*.yaml` files, parses each as one-or-more
Kubernetes manifests, and runs a **bundled 10-rule analyser** over
every pod template. Per ADR-005 the filesystem read happens on
`asyncio.to_thread`; the wrapper is `async` for TaskGroup fan-out.

**The 10-rule v0.1 ruleset** (per Q4 of the plan):

| ID                          | Severity | Description                                                                |
| --------------------------- | -------- | -------------------------------------------------------------------------- |
| run-as-root                 | HIGH     | Container running as root (`runAsUser=0` or missing)                       |
| privileged-container        | HIGH     | `privileged=true` set                                                       |
| host-network                | HIGH     | `hostNetwork=true`                                                          |
| host-pid                    | HIGH     | `hostPID=true`                                                              |
| host-ipc                    | HIGH     | `hostIPC=true`                                                              |
| missing-resource-limits     | MEDIUM   | No `resources.limits.cpu` or `resources.limits.memory`                      |
| image-pull-policy-not-always| MEDIUM   | `imagePullPolicy` not explicitly `Always`                                  |
| allow-privilege-escalation  | HIGH     | `allowPrivilegeEscalation=true`                                            |
| read-only-root-fs-missing   | MEDIUM   | `readOnlyRootFilesystem` not `true`                                        |
| auto-mount-sa-token         | MEDIUM   | `automountServiceAccountToken` not explicitly `false`                       |

**Supported workload kinds** (their pod template is walked):

- `Pod` — `spec`
- `Deployment` / `StatefulSet` / `DaemonSet` / `ReplicaSet` — `spec.template.spec`
- `Job` — `spec.template.spec`
- `CronJob` — `spec.jobTemplate.spec.template.spec`

Other kinds (Service / Ingress / ConfigMap / Secret / etc.) are silently
skipped — they don't carry pod posture.

**Forgiving** on malformed entries — bad files / non-dict YAML
documents / missing fields are skipped silently. PyYAML parse errors
drop the whole file but the agent run continues.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import yaml
from pydantic import BaseModel, Field

from k8s_posture.schemas import Severity


class ManifestReaderError(RuntimeError):
    """The manifest directory could not be read."""


@dataclass(frozen=True)
class _Rule:
    """One v0.1 manifest-analysis rule."""

    rule_id: str
    title: str
    severity: Severity


_RULES: dict[str, _Rule] = {
    "run-as-root": _Rule("run-as-root", "Container running as root", Severity.HIGH),
    "privileged-container": _Rule("privileged-container", "Privileged container", Severity.HIGH),
    "host-network": _Rule("host-network", "Host network namespace shared", Severity.HIGH),
    "host-pid": _Rule("host-pid", "Host PID namespace shared", Severity.HIGH),
    "host-ipc": _Rule("host-ipc", "Host IPC namespace shared", Severity.HIGH),
    "missing-resource-limits": _Rule(
        "missing-resource-limits", "Missing resource limits", Severity.MEDIUM
    ),
    "image-pull-policy-not-always": _Rule(
        "image-pull-policy-not-always",
        "imagePullPolicy not explicitly Always",
        Severity.MEDIUM,
    ),
    "allow-privilege-escalation": _Rule(
        "allow-privilege-escalation", "Privilege escalation allowed", Severity.HIGH
    ),
    "read-only-root-fs-missing": _Rule(
        "read-only-root-fs-missing",
        "readOnlyRootFilesystem not enabled",
        Severity.MEDIUM,
    ),
    "auto-mount-sa-token": _Rule(
        "auto-mount-sa-token",
        "automountServiceAccountToken not explicitly disabled",
        Severity.MEDIUM,
    ),
}


_POD_TEMPLATE_KINDS: frozenset[str] = frozenset(
    {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
)


class ManifestFinding(BaseModel):
    """One v0.1 manifest-rule finding."""

    rule_id: str = Field(min_length=1)
    rule_title: str = Field(min_length=1)
    severity: Severity
    workload_kind: str = Field(min_length=1)
    workload_name: str = Field(min_length=1)
    namespace: str = Field(default="default")
    container_name: str = Field(default="")  # empty for pod-level rules
    manifest_path: str = Field(min_length=1)
    detected_at: datetime
    unmapped: dict[str, Any] = Field(default_factory=dict)


async def read_manifests(*, path: Path) -> tuple[ManifestFinding, ...]:
    """Read a directory of YAML manifests and emit static-analysis findings."""
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[ManifestFinding, ...]:
    if not path.exists():
        raise ManifestReaderError(f"manifest dir not found: {path}")
    if not path.is_dir():
        raise ManifestReaderError(f"manifest path is not a directory: {path}")

    detected_at = datetime.now(UTC)
    out: list[ManifestFinding] = []
    for yaml_path in sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")):
        try:
            docs = list(yaml.safe_load_all(yaml_path.read_text(encoding="utf-8")))
        except yaml.YAMLError:
            continue  # bad YAML — skip the file, keep going
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            out.extend(_analyse_manifest(doc, manifest_path=yaml_path, detected_at=detected_at))
    return tuple(out)


def _analyse_manifest(
    manifest: dict[str, Any],
    *,
    manifest_path: Path,
    detected_at: datetime,
) -> list[ManifestFinding]:
    kind = str(manifest.get("kind", ""))
    pod_spec, workload_kind = _resolve_pod_spec(manifest, kind=kind)
    if pod_spec is None:
        return []

    metadata = manifest.get("metadata") or {}
    name = str(metadata.get("name", "")) if isinstance(metadata, dict) else ""
    namespace = (
        str(metadata.get("namespace", "default")) if isinstance(metadata, dict) else "default"
    ) or "default"
    if not name:
        return []
    auto_mount = manifest.get("spec") if kind == "Pod" else None  # for SA-token rule
    # `automountServiceAccountToken` can live on the pod template OR the pod-spec itself.

    out: list[ManifestFinding] = []
    out.extend(
        _check_pod_level_rules(
            pod_spec,
            workload_kind=workload_kind,
            workload_name=name,
            namespace=namespace,
            manifest_path=manifest_path,
            detected_at=detected_at,
        )
    )

    containers = pod_spec.get("containers")
    if isinstance(containers, list):
        for container in containers:
            if not isinstance(container, dict):
                continue
            out.extend(
                _check_container_rules(
                    container,
                    workload_kind=workload_kind,
                    workload_name=name,
                    namespace=namespace,
                    manifest_path=manifest_path,
                    detected_at=detected_at,
                )
            )

    # initContainers walked too — same rules apply.
    init_containers = pod_spec.get("initContainers")
    if isinstance(init_containers, list):
        for container in init_containers:
            if not isinstance(container, dict):
                continue
            out.extend(
                _check_container_rules(
                    container,
                    workload_kind=workload_kind,
                    workload_name=name,
                    namespace=namespace,
                    manifest_path=manifest_path,
                    detected_at=detected_at,
                )
            )

    # cosmetic: silence `auto_mount` unused-variable warning when kind != Pod.
    del auto_mount
    return out


def _resolve_pod_spec(manifest: dict[str, Any], *, kind: str) -> tuple[dict[str, Any] | None, str]:
    """Return the inner pod spec dict + the user-visible workload kind."""
    if kind == "Pod":
        spec = manifest.get("spec")
        return (spec if isinstance(spec, dict) else None), "Pod"
    if kind in _POD_TEMPLATE_KINDS:
        spec = manifest.get("spec") or {}
        if not isinstance(spec, dict):
            return None, kind
        template = spec.get("template") or {}
        if not isinstance(template, dict):
            return None, kind
        pod_spec = template.get("spec")
        return (pod_spec if isinstance(pod_spec, dict) else None), kind
    if kind == "CronJob":
        spec = manifest.get("spec") or {}
        if not isinstance(spec, dict):
            return None, kind
        job_template = spec.get("jobTemplate") or {}
        if not isinstance(job_template, dict):
            return None, kind
        job_spec = job_template.get("spec") or {}
        if not isinstance(job_spec, dict):
            return None, kind
        template = job_spec.get("template") or {}
        if not isinstance(template, dict):
            return None, kind
        pod_spec = template.get("spec")
        return (pod_spec if isinstance(pod_spec, dict) else None), kind
    return None, kind


# ---------------------------- pod-level rules ----------------------------


def _check_pod_level_rules(
    pod_spec: dict[str, Any],
    *,
    workload_kind: str,
    workload_name: str,
    namespace: str,
    manifest_path: Path,
    detected_at: datetime,
) -> list[ManifestFinding]:
    out: list[ManifestFinding] = []

    if pod_spec.get("hostNetwork") is True:
        out.append(
            _build_finding(
                _RULES["host-network"],
                workload_kind=workload_kind,
                workload_name=workload_name,
                namespace=namespace,
                container_name="",
                manifest_path=manifest_path,
                detected_at=detected_at,
            )
        )
    if pod_spec.get("hostPID") is True:
        out.append(
            _build_finding(
                _RULES["host-pid"],
                workload_kind=workload_kind,
                workload_name=workload_name,
                namespace=namespace,
                container_name="",
                manifest_path=manifest_path,
                detected_at=detected_at,
            )
        )
    if pod_spec.get("hostIPC") is True:
        out.append(
            _build_finding(
                _RULES["host-ipc"],
                workload_kind=workload_kind,
                workload_name=workload_name,
                namespace=namespace,
                container_name="",
                manifest_path=manifest_path,
                detected_at=detected_at,
            )
        )
    # automountServiceAccountToken — finding iff NOT explicitly false.
    auto_mount = pod_spec.get("automountServiceAccountToken")
    if auto_mount is not False:
        out.append(
            _build_finding(
                _RULES["auto-mount-sa-token"],
                workload_kind=workload_kind,
                workload_name=workload_name,
                namespace=namespace,
                container_name="",
                manifest_path=manifest_path,
                detected_at=detected_at,
            )
        )
    return out


# ---------------------------- container-level rules ----------------------


def _check_container_rules(
    container: dict[str, Any],
    *,
    workload_kind: str,
    workload_name: str,
    namespace: str,
    manifest_path: Path,
    detected_at: datetime,
) -> list[ManifestFinding]:
    out: list[ManifestFinding] = []
    container_name = str(container.get("name", "")) or "container"
    sec_ctx = container.get("securityContext")
    sec_ctx_dict = cast("dict[str, Any]", sec_ctx) if isinstance(sec_ctx, dict) else {}

    # run-as-root: runAsUser == 0 OR missing (default upstream is root if unset).
    run_as_user = sec_ctx_dict.get("runAsUser")
    if run_as_user is None or run_as_user == 0:
        out.append(
            _build_finding(
                _RULES["run-as-root"],
                workload_kind=workload_kind,
                workload_name=workload_name,
                namespace=namespace,
                container_name=container_name,
                manifest_path=manifest_path,
                detected_at=detected_at,
            )
        )
    # privileged: securityContext.privileged is true
    if sec_ctx_dict.get("privileged") is True:
        out.append(
            _build_finding(
                _RULES["privileged-container"],
                workload_kind=workload_kind,
                workload_name=workload_name,
                namespace=namespace,
                container_name=container_name,
                manifest_path=manifest_path,
                detected_at=detected_at,
            )
        )
    # allowPrivilegeEscalation: true → finding
    if sec_ctx_dict.get("allowPrivilegeEscalation") is True:
        out.append(
            _build_finding(
                _RULES["allow-privilege-escalation"],
                workload_kind=workload_kind,
                workload_name=workload_name,
                namespace=namespace,
                container_name=container_name,
                manifest_path=manifest_path,
                detected_at=detected_at,
            )
        )
    # readOnlyRootFilesystem: NOT true → finding
    if sec_ctx_dict.get("readOnlyRootFilesystem") is not True:
        out.append(
            _build_finding(
                _RULES["read-only-root-fs-missing"],
                workload_kind=workload_kind,
                workload_name=workload_name,
                namespace=namespace,
                container_name=container_name,
                manifest_path=manifest_path,
                detected_at=detected_at,
            )
        )

    # imagePullPolicy: not explicitly "Always"
    pull_policy = container.get("imagePullPolicy")
    if pull_policy != "Always":
        out.append(
            _build_finding(
                _RULES["image-pull-policy-not-always"],
                workload_kind=workload_kind,
                workload_name=workload_name,
                namespace=namespace,
                container_name=container_name,
                manifest_path=manifest_path,
                detected_at=detected_at,
            )
        )

    # missing-resource-limits: resources.limits.cpu OR memory missing
    resources = container.get("resources")
    limits = resources.get("limits") if isinstance(resources, dict) else None
    has_cpu_limit = isinstance(limits, dict) and limits.get("cpu") is not None
    has_mem_limit = isinstance(limits, dict) and limits.get("memory") is not None
    if not (has_cpu_limit and has_mem_limit):
        out.append(
            _build_finding(
                _RULES["missing-resource-limits"],
                workload_kind=workload_kind,
                workload_name=workload_name,
                namespace=namespace,
                container_name=container_name,
                manifest_path=manifest_path,
                detected_at=detected_at,
            )
        )

    return out


def _build_finding(
    rule: _Rule,
    *,
    workload_kind: str,
    workload_name: str,
    namespace: str,
    container_name: str,
    manifest_path: Path,
    detected_at: datetime,
) -> ManifestFinding:
    return ManifestFinding(
        rule_id=rule.rule_id,
        rule_title=rule.title,
        severity=rule.severity,
        workload_kind=workload_kind,
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        manifest_path=str(manifest_path),
        detected_at=detected_at,
    )


__all__ = [
    "ManifestFinding",
    "ManifestReaderError",
    "read_manifests",
]
