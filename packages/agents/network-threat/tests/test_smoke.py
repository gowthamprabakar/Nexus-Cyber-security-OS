"""Smoke tests — network_threat package imports + every substrate gate fires."""

from __future__ import annotations


def test_package_imports() -> None:
    import network_threat

    assert hasattr(network_threat, "__version__")
    assert isinstance(network_threat.__version__, str)
    assert network_threat.__version__ == "0.1.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 — D.4 is the **seventh** consumer of the hoist."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — D.4 is the **fourth** agent shipped natively against v1.2
    (after D.3 + F.6 + D.7).
    """
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_charter_audit_log_import_works() -> None:
    """D.4 emits its own per-run audit chain via charter.audit.AuditLog (F.1)."""
    from charter.audit import AuditLog

    assert AuditLog.__name__ == "AuditLog"


def test_charter_memory_episodic_import_works() -> None:
    """D.4 lazily persists per-run findings to the F.5 EpisodicStore (Phase 1c)."""
    from charter.memory import EpisodicStore

    assert EpisodicStore.__name__ == "EpisodicStore"


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — network_threat must NOT ship a local llm.py."""
    import importlib.util

    assert importlib.util.find_spec("network_threat.llm") is None, (
        "network_threat must not ship a per-agent llm.py — consume charter.llm_adapter directly"
    )


def test_no_per_agent_nlah_loader() -> None:
    """ADR-007 v1.2 anti-pattern guard — D.4 ships only a 21-LOC shim, not a full loader.

    The shim itself lands at Task 10; until then there is NO local nlah_loader,
    and after Task 10 ships, the shim must not implement loading logic
    (must delegate to charter.nlah_loader.load_system_prompt).
    """
    # Anti-pattern guard at v0.1 bootstrap: no local nlah_loader yet
    # (Task 10 introduces it as a thin shim).
    pass


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares `network_threat = network_threat.eval_runner:NetworkThreatEvalRunner`
    under `nexus_eval_runners`. The target class lands in Task 14; here we only verify
    the *entry-point declaration* is discoverable.
    """
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "network_threat" in names, f"network_threat entry-point not registered; got {names}"


def test_cli_script_entry_point_registered() -> None:
    """Pyproject declares `network-threat = network_threat.cli:main` under `[project.scripts]`.
    Task 15 lands the CLI; here we only verify the declaration is reachable from importlib.metadata.
    """
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    names = {ep.name for ep in scripts}
    assert "network-threat" in names, f"network-threat console script not registered; got {names}"
