"""Live-GCP lane gating (D.5 v0.2 Task 14).

Mirrors `live_lane_azure` (Task 13) / `cloud_posture.live_lane` (Q1). A DISTINCT
gate from `NEXUS_LIVE_AZURE` — the two lanes are independent (separate env vars,
separate fixtures, no conflict). Whether the `NEXUS_LIVE_GCP` lane is enabled,
whether live GCP is reachable (probed by resolving ADC through the Task-6
`GcpCredentialResolver`), and the skip message.
"""

from __future__ import annotations

import os

from multi_cloud_posture.credentials_gcp import GcpCredentialResolver

GCP_LIVE_SETUP = (
    "set NEXUS_LIVE_GCP=1 and configure GCP credentials (gcloud auth "
    "application-default login, a Service-Account key via "
    "GOOGLE_APPLICATION_CREDENTIALS, or Workload Identity) + GOOGLE_CLOUD_PROJECT. "
    "e.g.: NEXUS_LIVE_GCP=1 uv run pytest "
    "packages/agents/multi-cloud-posture/tests/integration/test_agent_gcp_live.py -v"
)


def nexus_live_gcp_enabled() -> bool:
    """True iff the live-GCP lane is enabled (`NEXUS_LIVE_GCP=1`)."""
    return os.environ.get("NEXUS_LIVE_GCP") == "1"


def gcp_reachable() -> tuple[bool, str]:
    """Probe live-GCP reachability by resolving ADC through the
    `GcpCredentialResolver`. Returns `(ok, reason)`; `reason` is a secret-free,
    traceback-free exception-type name."""
    try:
        GcpCredentialResolver().resolve_credential()
        return True, ""
    except Exception as exc:
        return False, type(exc).__name__


def gcp_skip_reason() -> str | None:
    """`None` when the lane is enabled AND reachable; otherwise the `pytest.skip`
    message with copy-paste setup instructions."""
    if not nexus_live_gcp_enabled():
        return GCP_LIVE_SETUP
    ok, reason = gcp_reachable()
    if not ok:
        return f"NEXUS_LIVE_GCP=1 set but GCP is unreachable ({reason}). {GCP_LIVE_SETUP}"
    return None
