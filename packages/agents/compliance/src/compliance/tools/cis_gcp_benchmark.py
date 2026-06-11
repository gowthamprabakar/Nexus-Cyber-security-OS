"""CIS Google Cloud Platform Foundation Benchmark v2.0 reader (compliance v0.2 Task 4).

The v0.2 third framework in the CIS family. Reuses the framework-generic parse from
:mod:`compliance.tools.cis_aws_benchmark` over the bundled
``compliance.control_libraries.cis_gcp_v2.yaml`` — controls wire to D.5 multi-cloud-posture's
real ``MCSPM-GCP-*`` rule ids (honest wiring; the rest carry explicit empty mappings).
"""

from __future__ import annotations

import asyncio
from importlib import resources
from pathlib import Path

from compliance.tools.cis_aws_benchmark import CisControl, _read_sync


def default_cis_gcp_v2_path() -> Path:
    """Return the path to the bundled CIS GCP v2 YAML."""
    pkg = resources.files("compliance.control_libraries")
    return Path(str(pkg / "cis_gcp_v2.yaml"))


async def read_cis_gcp_benchmark(*, path: Path | None = None) -> tuple[CisControl, ...]:
    """Read the CIS GCP Benchmark v2.0 YAML and return the parsed controls. Uses the
    bundled library when ``path`` is ``None``. Pure I/O; malformed entries dropped."""
    target = path if path is not None else default_cis_gcp_v2_path()
    return await asyncio.to_thread(_read_sync, target)


__all__ = ["default_cis_gcp_v2_path", "read_cis_gcp_benchmark"]
