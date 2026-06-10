"""NEXUS_LIVE_IDENTITY_AZURE gated live-eval lane (D.2 v0.2 Task 17).

Mirrors the Task-16 AWS lane, consuming the hoisted charter Pattern D
(`charter.live_lane`). Reports whether identity's live Azure-AD lane is enabled,
whether live Azure is reachable (probed by acquiring a Microsoft Graph token through
the Task-9 `AzureCredentialResolver`), and the `pytest.skip` message with setup steps.

A DISTINCT gate from D.5's `NEXUS_LIVE_AZURE` — identity owns its own Azure-AD lane
(WI-I1, per-cloud / per-agent separation). The live end-to-end pipeline (Task 18,
WI-I4) consumes this gate.
"""

from __future__ import annotations

from charter.live_lane import live_skip_reason, nexus_live_enabled

from identity.credentials_azure import AzureCredentialResolver
from identity.tools.azure_ad import GRAPH_SCOPE

AZURE_IDENTITY_LIVE_SETUP = (
    "set NEXUS_LIVE_IDENTITY_AZURE=1 and configure Azure credentials "
    "(DefaultAzureCredential: env Service Principal / Managed Identity / az login) with "
    "Microsoft Graph Directory.Read.All. e.g.: NEXUS_LIVE_IDENTITY_AZURE=1 uv run pytest "
    "packages/agents/identity/tests/integration/test_agent_azure_live.py -v"
)


def nexus_live_identity_azure_enabled() -> bool:
    """True iff identity's live Azure-AD lane is enabled (`NEXUS_LIVE_IDENTITY_AZURE=1`)."""
    return nexus_live_enabled("NEXUS_LIVE_IDENTITY_AZURE")


def azure_reachable() -> tuple[bool, str]:
    """Probe live-Azure reachability by acquiring a Microsoft Graph token through the
    `AzureCredentialResolver`. Returns `(ok, reason)`; `reason` is a secret-free,
    traceback-free exception-type name."""
    try:
        AzureCredentialResolver().resolve_credential().get_token(GRAPH_SCOPE)
        return True, ""
    except Exception as exc:
        return False, type(exc).__name__


def azure_skip_reason() -> str | None:
    """`None` when the lane is enabled AND reachable; otherwise the `pytest.skip`
    message with copy-paste setup instructions."""
    return live_skip_reason(
        "NEXUS_LIVE_IDENTITY_AZURE", "Azure AD", AZURE_IDENTITY_LIVE_SETUP, azure_reachable
    )
