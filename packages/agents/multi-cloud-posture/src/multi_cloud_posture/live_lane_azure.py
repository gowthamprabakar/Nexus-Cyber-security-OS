"""Live-Azure lane gating (D.5 v0.2 Task 13).

Mirrors `cloud_posture.live_lane` (Q1; in-package so the helpers are importable +
unit-testable under `--import-mode=importlib`). Whether the `NEXUS_LIVE_AZURE`
lane is enabled, whether live Azure is reachable (probed by listing subscriptions
through the Task-2 `AzureCredentialResolver`), and the skip message. The
`azure_live_subscription` fixture in `tests/integration/conftest.py` consumes
these. Distinct from the future `NEXUS_LIVE_GCP` lane (Task 14).
"""

from __future__ import annotations

import os

from multi_cloud_posture.credentials_azure import AzureCredentialResolver

AZURE_LIVE_SETUP = (
    "set NEXUS_LIVE_AZURE=1 and configure Azure credentials (az login, a Service "
    "Principal via env, or Managed Identity) + AZURE_SUBSCRIPTION_ID. e.g.: "
    "NEXUS_LIVE_AZURE=1 uv run pytest "
    "packages/agents/multi-cloud-posture/tests/integration/test_agent_azure_live.py -v"
)


def nexus_live_azure_enabled() -> bool:
    """True iff the live-Azure lane is enabled (`NEXUS_LIVE_AZURE=1`)."""
    return os.environ.get("NEXUS_LIVE_AZURE") == "1"


def azure_reachable() -> tuple[bool, str]:
    """Probe live-Azure reachability by listing subscriptions through the
    `AzureCredentialResolver`. Returns `(ok, reason)`; `reason` is a secret-free,
    traceback-free exception-type name."""
    try:
        from azure.mgmt.subscription import SubscriptionClient

        client = AzureCredentialResolver().client(SubscriptionClient)
        next(iter(client.subscriptions.list()), None)
        return True, ""
    except Exception as exc:
        return False, type(exc).__name__


def azure_skip_reason() -> str | None:
    """`None` when the lane is enabled AND reachable; otherwise the `pytest.skip`
    message with copy-paste setup instructions."""
    if not nexus_live_azure_enabled():
        return AZURE_LIVE_SETUP
    ok, reason = azure_reachable()
    if not ok:
        return f"NEXUS_LIVE_AZURE=1 set but Azure is unreachable ({reason}). {AZURE_LIVE_SETUP}"
    return None
