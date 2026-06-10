"""Live-AWS lane gating (F.3 v0.2 Task 6).

A small in-package seam for the `NEXUS_LIVE_AWS` test lane: whether the lane is
enabled, whether live AWS is reachable (probed via STS `get_caller_identity`
through the Task-2 `CredentialResolver` — Task 3's mechanism), and the skip
message. The `aws_live_account` pytest fixture in
`tests/integration/conftest.py` consumes these; the helpers live here (not in
conftest) so they are importable + unit-testable under `--import-mode=importlib`.

Establishing the live-lane gating shape in-package (Q7) makes it a hoist
candidate for the third consumer (D.5 / D.2 v0.2).
"""

from __future__ import annotations

from charter.live_lane import live_skip_reason, nexus_live_enabled

from cloud_posture.credentials import CredentialResolver

AWS_LIVE_SETUP = (
    "set NEXUS_LIVE_AWS=1 and configure AWS credentials (AWS_PROFILE=<profile> "
    "or the boto3 default chain). The lane scans the current account via STS "
    "get_caller_identity. e.g.: AWS_PROFILE=dev NEXUS_LIVE_AWS=1 uv run pytest "
    "packages/agents/cloud-posture/tests/integration/test_agent_aws_live.py -v"
)


def nexus_live_aws_enabled() -> bool:
    """True iff the live-AWS lane is enabled (`NEXUS_LIVE_AWS=1`)."""
    return nexus_live_enabled("NEXUS_LIVE_AWS")


def aws_reachable() -> tuple[bool, str]:
    """Probe live-AWS reachability via STS `get_caller_identity` through the
    `CredentialResolver`. Returns `(ok, reason)`; `reason` is a secret-free,
    traceback-free exception-type name."""
    try:
        CredentialResolver().client("sts").get_caller_identity()
        return True, ""
    except Exception as exc:
        return False, type(exc).__name__


def aws_skip_reason() -> str | None:
    """`None` when the lane is enabled AND reachable; otherwise the
    `pytest.skip` message with copy-paste setup instructions."""
    return live_skip_reason("NEXUS_LIVE_AWS", "AWS", AWS_LIVE_SETUP, aws_reachable)
