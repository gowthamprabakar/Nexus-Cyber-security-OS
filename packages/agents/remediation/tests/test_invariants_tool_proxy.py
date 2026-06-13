"""remediation v0.2 Task 17 — assert_tool_proxy_for_execute tests (WI-A14)."""

from __future__ import annotations

import pytest
from remediation.invariants.tool_proxy import (
    ToolProxyBypassError,
    assert_tool_proxy_for_execute,
)
from remediation.schemas import RemediationMode


def test_execute_via_proxy_ok() -> None:
    assert_tool_proxy_for_execute(mode=RemediationMode.EXECUTE, via_tool_proxy=True)


def test_execute_direct_raises() -> None:
    with pytest.raises(ToolProxyBypassError, match="charter tool proxy"):
        assert_tool_proxy_for_execute(mode=RemediationMode.EXECUTE, via_tool_proxy=False)


def test_recommend_not_fenced() -> None:
    assert_tool_proxy_for_execute(mode=RemediationMode.RECOMMEND, via_tool_proxy=False)


def test_dry_run_not_fenced() -> None:
    assert_tool_proxy_for_execute(mode=RemediationMode.DRY_RUN, via_tool_proxy=False)
