"""NEXUS_LIVE_IDENTITY_AWS gated live-eval lane (D.2 v0.2 Task 16).

Mirrors the F.3 / D.1 live-lane gating, consuming the hoisted charter Pattern D
(`charter.live_lane`). Reports whether identity's live AWS-IAM lane is enabled,
whether live AWS is reachable (probed via STS `get_caller_identity` through the
Task-5 `CredentialResolver`), and the `pytest.skip` message with setup steps.

A DISTINCT gate from F.3's `NEXUS_LIVE_AWS` and D.1's `NEXUS_LIVE_REGISTRY_AWS` —
identity owns its own lane (WI-I1, per-cloud / per-agent separation). The live
end-to-end pipeline (Task 18, WI-I4) consumes this gate.
"""

from __future__ import annotations

from charter.live_lane import live_skip_reason, nexus_live_enabled

from identity.credentials import CredentialResolver

AWS_IDENTITY_LIVE_SETUP = (
    "set NEXUS_LIVE_IDENTITY_AWS=1 and configure AWS credentials (AWS_PROFILE=<profile> "
    "or the boto3 default chain) with IAM read access. The lane scans the current "
    "account's IAM, gated on STS get_caller_identity. e.g.: AWS_PROFILE=dev "
    "NEXUS_LIVE_IDENTITY_AWS=1 uv run pytest "
    "packages/agents/identity/tests/integration/test_agent_aws_live.py -v"
)


def nexus_live_identity_aws_enabled() -> bool:
    """True iff identity's live AWS-IAM lane is enabled (`NEXUS_LIVE_IDENTITY_AWS=1`)."""
    return nexus_live_enabled("NEXUS_LIVE_IDENTITY_AWS")


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
    """`None` when the lane is enabled AND reachable; otherwise the `pytest.skip`
    message with copy-paste setup instructions."""
    return live_skip_reason(
        "NEXUS_LIVE_IDENTITY_AWS", "AWS IAM", AWS_IDENTITY_LIVE_SETUP, aws_reachable
    )
