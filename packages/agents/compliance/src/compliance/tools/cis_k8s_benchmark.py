"""CIS Kubernetes Benchmark v1.8 reader (compliance v0.2 Task 5).

The v0.2 fourth framework in the CIS family — completes CIS-AWS/Azure/GCP/K8s. Reuses the
framework-generic parse from :mod:`compliance.tools.cis_aws_benchmark` over the bundled
``compliance.control_libraries.cis_k8s_v18.yaml`` — controls wire to k8s-posture's real
emitted rule ids (kube-bench rule_id == control id, plus the fixed runtime / RBAC rule ids).
"""

from __future__ import annotations

import asyncio
from importlib import resources
from pathlib import Path

from compliance.tools.cis_aws_benchmark import CisControl, _read_sync


def default_cis_k8s_v18_path() -> Path:
    """Return the path to the bundled CIS K8s v1.8 YAML."""
    pkg = resources.files("compliance.control_libraries")
    return Path(str(pkg / "cis_k8s_v18.yaml"))


async def read_cis_k8s_benchmark(*, path: Path | None = None) -> tuple[CisControl, ...]:
    """Read the CIS K8s Benchmark v1.8 YAML and return the parsed controls. Uses the
    bundled library when ``path`` is ``None``. Pure I/O; malformed entries dropped."""
    target = path if path is not None else default_cis_k8s_v18_path()
    return await asyncio.to_thread(_read_sync, target)


__all__ = ["default_cis_k8s_v18_path", "read_cis_k8s_benchmark"]
