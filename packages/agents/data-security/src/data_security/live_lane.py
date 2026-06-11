"""NEXUS_LIVE_DATA_SECURITY gated live-eval lane (data-security v0.2 Task 19).

Consumes the hoisted charter Pattern D (`charter.live_lane`). Team decision (documented in
the PR): a **single** env gate covers all three cloud sources, with **per-source**
reachability probes (AWS S3 / Azure Blob / GCS) so an operator sees exactly which source is
reachable. A DISTINCT gate from every prior cycle. Probes are injectable so they're testable
without live clouds.
"""

from __future__ import annotations

from collections.abc import Callable

from charter.live_lane import live_skip_reason, nexus_live_enabled

DATA_SECURITY_LIVE_ENV = "NEXUS_LIVE_DATA_SECURITY"
DATA_SECURITY_LIVE_SETUP = (
    "set NEXUS_LIVE_DATA_SECURITY=1 and configure credentials for the cloud sources under "
    "test (AWS_PROFILE for S3, AZURE_* for Blob, GOOGLE_APPLICATION_CREDENTIALS for GCS). "
    "e.g.: NEXUS_LIVE_DATA_SECURITY=1 uv run pytest "
    "packages/agents/data-security/tests/integration/test_data_security_multi_cloud_e2e.py -v"
)

#: The three cloud sources the single lane covers.
CLOUD_SOURCES = ("aws_s3", "azure_blob", "gcs")


def nexus_live_data_security_enabled() -> bool:
    """True iff the live data-discovery lane is enabled (`NEXUS_LIVE_DATA_SECURITY=1`)."""
    return nexus_live_enabled(DATA_SECURITY_LIVE_ENV)


def source_reachable(
    available_sources: tuple[str, ...] = (),
    probe: Callable[[], tuple[bool, str]] | None = None,
) -> tuple[bool, str]:
    """Reachable iff at least one known cloud source is available. Pass the available source
    names, or an explicit ``probe``."""
    if probe is not None:
        return probe()
    present = [s for s in available_sources if s in CLOUD_SOURCES]
    if present:
        return True, ""
    return False, "no-cloud-source-reachable"


def data_security_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = lambda: (False, "no-cloud-source-reachable"),
) -> str | None:
    return live_skip_reason(
        DATA_SECURITY_LIVE_ENV, "cloud data sources", DATA_SECURITY_LIVE_SETUP, probe
    )
