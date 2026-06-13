"""Tool-proxy invariant for execute mode (remediation v0.2 Task 17, WI-A14 / audit #316 C-1).

A.1 is the only state-mutating agent, and the audit #316 C-1 finding made it a hard rule:
**EXECUTE-mode mutation MUST go through ``ctx.call_tool``** (the charter tool proxy), never a
direct SDK/kubectl invocation — the proxy is where authorization, budget, and the audit chain are
enforced. ``assert_tool_proxy_for_execute`` codifies that at the invariant level: an execute-mode
call that bypasses the proxy raises. (The runtime guard is ADR-016 ``DirectInvocationBlocked``;
this is the code-level mirror.)
"""

from __future__ import annotations

from remediation.schemas import RemediationMode


class ToolProxyBypassError(RuntimeError):
    """Raised when an execute-mode mutation bypasses the charter tool proxy (WI-A14)."""


def assert_tool_proxy_for_execute(*, mode: RemediationMode, via_tool_proxy: bool) -> None:
    """Hard guard — execute-mode mutation must route through ``ctx.call_tool`` (WI-A14).

    recommend / dry-run modes do not mutate the cluster, so they are not fenced here; only the
    execute tier requires the proxy.
    """
    if mode == RemediationMode.EXECUTE and not via_tool_proxy:
        raise ToolProxyBypassError(
            "execute-mode mutation must route through the charter tool proxy; a direct invocation "
            "bypasses authorization + audit (WI-A14 / audit #316 C-1 / ADR-016)."
        )
