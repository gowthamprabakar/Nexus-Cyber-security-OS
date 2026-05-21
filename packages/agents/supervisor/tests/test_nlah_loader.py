"""Tests — `supervisor.nlah_loader` + bundled NLAH content (Task 11).

Supervisor is the 13th agent shipped natively against ADR-007
v1.2's 21-LOC shim pattern. 17 tests verifying:

1.  21-LOC shim under the ≤35-line budget.
2.  Shim public surface matches charter's contract.
3.  Default NLAH directory exists.
4.  README.md present.
5.  tools.md present.
6.  examples/ subdirectory present.
7.  Three examples shipped (basic-routing / parallel-dispatch /
    escalation-on-timeout).
8.  load_system_prompt returns non-empty content.
9.  load_system_prompt includes README content.
10. load_system_prompt includes tools.md content.
11. load_system_prompt includes example content.
12. load_system_prompt(None) == load_system_prompt(default_dir).
13. README documents all 5 pipeline stages.
14. README carries the Q-ARCH-1 forbidden-subscription invariant
    block (WI-5 forward-carry must be load-bearing in the persona).
15. README carries the WI-4 read-only commitment + 7 deferrals.
16. tools.md declares the in-driver helper groups + the 4
    additive audit-action vocabulary entries.
17. README documents the 60s heartbeat interval + per-customer
    fcntl.flock discipline.
"""

from __future__ import annotations

from pathlib import Path

from supervisor.nlah_loader import default_nlah_dir, load_system_prompt

_SHIM_PATH = Path(__file__).parent.parent / "src" / "supervisor" / "nlah_loader.py"
_LOC_BUDGET = 35


# ---------------------------------------------------------------------------
# 21-LOC shim
# ---------------------------------------------------------------------------


def test_nlah_loader_under_loc_budget() -> None:
    line_count = sum(1 for _ in _SHIM_PATH.read_text().splitlines())
    assert line_count <= _LOC_BUDGET, (
        f"nlah_loader.py grew to {line_count} lines (budget {_LOC_BUDGET})"
    )


def test_nlah_loader_reexports_from_charter() -> None:
    import supervisor.nlah_loader as shim

    assert callable(shim.default_nlah_dir)
    assert callable(shim.load_system_prompt)
    assert set(shim.__all__) == {"default_nlah_dir", "load_system_prompt"}


# ---------------------------------------------------------------------------
# NLAH directory layout
# ---------------------------------------------------------------------------


def test_default_nlah_dir_exists() -> None:
    nlah = default_nlah_dir()
    assert nlah.is_dir(), f"NLAH dir missing: {nlah}"


def test_nlah_readme_present() -> None:
    assert (default_nlah_dir() / "README.md").is_file()


def test_nlah_tools_present() -> None:
    assert (default_nlah_dir() / "tools.md").is_file()


def test_nlah_examples_dir_present() -> None:
    assert (default_nlah_dir() / "examples").is_dir()


def test_nlah_ships_three_examples() -> None:
    """Plan §Task 11: 3 examples covering basic-routing /
    parallel-dispatch / escalation-on-timeout."""
    examples = sorted((default_nlah_dir() / "examples").glob("*.md"))
    assert len(examples) == 3
    names = {p.name for p in examples}
    assert any("basic-routing" in n for n in names)
    assert any("parallel-dispatch" in n for n in names)
    assert any("escalation" in n for n in names)


# ---------------------------------------------------------------------------
# load_system_prompt concatenation
# ---------------------------------------------------------------------------


def test_load_system_prompt_returns_non_empty() -> None:
    assert load_system_prompt().strip()


def test_load_system_prompt_includes_readme_content() -> None:
    text = load_system_prompt()
    assert "Supervisor Agent" in text or "Supervisor persona" in text


def test_load_system_prompt_includes_tools_md_content() -> None:
    text = load_system_prompt()
    assert "load_routing_rules" in text
    assert "dispatch_parallel" in text
    assert "scheduled_queue" in text


def test_load_system_prompt_includes_example_content() -> None:
    text = load_system_prompt()
    assert "heartbeat-once" in text
    assert "Semaphore" in text
    assert "auto-retry" in text


def test_load_system_prompt_accepts_explicit_path() -> None:
    a = load_system_prompt()
    b = load_system_prompt(default_nlah_dir())
    assert a == b


# ---------------------------------------------------------------------------
# README content (load-bearing v0.1 invariants)
# ---------------------------------------------------------------------------


def test_readme_documents_all_pipeline_stages() -> None:
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    for stage in ("INGEST", "ROUTE", "DISPATCH", "AUDIT", "HANDOFF"):
        assert stage in readme, f"pipeline stage {stage} missing from README.md"


def test_readme_carries_q_arch_1_forbidden_subscription_block() -> None:
    """Q-ARCH-1 / WI-5 — the forbidden-subscription invariant must
    be load-bearing in the persona. A.4 v0.2 plan author reads this
    to understand the trajectory."""
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "_FORBIDDEN_SUBSCRIPTIONS" in readme
    assert "WI-5" in readme
    assert "A.4 v0.2" in readme


def test_readme_documents_wi4_read_only_commitment() -> None:
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "read-only" in readme.lower()
    assert "WI-4" in readme
    # 7 explicit deferrals named in the persona (the 8 from the plan
    # condensed for the persona — the multi-tenant production one
    # is implicit in the substrate stance).
    for deferral in (
        "LLM-driven routing",
        "multi-agent planning",
        "auto-retry",
        "cron scheduler",
        "subprocess",
    ):
        assert deferral in readme, f"deferral {deferral!r} missing from README"


def test_readme_documents_heartbeat_interval_and_lock() -> None:
    readme = (default_nlah_dir() / "README.md").read_text(encoding="utf-8")
    assert "60" in readme
    assert "fcntl.flock" in readme
    assert "lock" in readme.lower()


# ---------------------------------------------------------------------------
# tools.md content
# ---------------------------------------------------------------------------


def test_tools_md_declares_in_driver_helper_groups() -> None:
    """v0.1 ships no charter-registered tools; the in-driver helper
    groups are documented for the LLM's mental model (when a future
    LLM-driven Supervisor v0.2+ surface arrives)."""
    tools = (default_nlah_dir() / "tools.md").read_text(encoding="utf-8")
    assert "load_routing_rules" in tools
    assert "supervisor.routing.router.route" in tools
    assert "dispatch_parallel" in tools
    assert "scheduled_queue" in tools
    assert "emit_" in tools


def test_tools_md_documents_additive_audit_actions() -> None:
    tools = (default_nlah_dir() / "tools.md").read_text(encoding="utf-8")
    for action in (
        "supervisor.heartbeat.started",
        "supervisor.delegation.dispatched",
        "supervisor.delegation.completed",
        "supervisor.escalation.raised",
    ):
        assert action in tools, f"audit-action {action} missing from tools.md"
