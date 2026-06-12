"""supervisor v0.2 — bootstrap smoke tests (Milestone 1, Task 1).

The version-extension eligibility guards (ADR-010): the v0.2 bump must not perturb the v0.1
contracts — and, critically, must not erode the **dispatcher-class deviation profile**
(WI-O11): supervisor has **no Charter wrap, no ToolRegistry, no OCSF emission**. These guards
fail loudly if a later task accidentally adds any of them, and re-assert the
``_FORBIDDEN_SUBSCRIPTIONS`` fence (WI-O10) + the 4 existing F.6 audit-vocabulary entries
(byte-identical, WI-O5) at bootstrap before any live-dispatch surface is added.
"""

from __future__ import annotations

from pathlib import Path

import supervisor
from shared.fabric.client import _FORBIDDEN_SUBSCRIPTIONS

_SRC = Path(supervisor.__file__).resolve().parent


def _all_source() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in _SRC.rglob("*.py"))


def test_version_bumped_to_v0_2() -> None:
    assert supervisor.__version__ == "0.2.0"


def test_core_modules_still_import() -> None:
    import supervisor.agent
    import supervisor.audit_emit
    import supervisor.dispatch
    import supervisor.escalation
    import supervisor.scheduled_queue  # noqa: F401


def test_deviation_no_ocsf_emission() -> None:
    """WI-O11: supervisor emits F.6 audit vocabulary, NOT OCSF — no OCSF surface at all."""
    src = _all_source()
    assert "class_uid" not in src
    assert "def to_ocsf" not in src
    assert "OCSF_CLASS_UID" not in src


def test_deviation_no_charter_wrap() -> None:
    """WI-O11: supervisor CONSTRUCTS contracts, it does not run inside `with Charter(...)`."""
    assert "with Charter(" not in _all_source()


def test_deviation_no_own_tool_registry() -> None:
    """WI-O11: supervisor has no ToolRegistry of its own (routing is declarative)."""
    src = _all_source()
    assert "ToolRegistry(" not in src


def test_forbidden_subscriptions_fence_preserved() -> None:
    """WI-O10: supervisor must never subscribe to claims.> — the fence is intact."""
    assert _FORBIDDEN_SUBSCRIPTIONS["supervisor"] == frozenset({"claims.>"})


def test_existing_audit_vocabulary_present() -> None:
    """WI-O5: the 4 existing F.6 audit-vocabulary entries are unchanged."""
    from supervisor.audit_emit import (
        ACTION_DELEGATION_COMPLETED,
        ACTION_DELEGATION_DISPATCHED,
        ACTION_ESCALATION_RAISED,
        ACTION_HEARTBEAT_STARTED,
    )

    assert ACTION_HEARTBEAT_STARTED == "supervisor.heartbeat.started"
    assert ACTION_DELEGATION_DISPATCHED == "supervisor.delegation.dispatched"
    assert ACTION_DELEGATION_COMPLETED == "supervisor.delegation.completed"
    assert ACTION_ESCALATION_RAISED == "supervisor.escalation.raised"
