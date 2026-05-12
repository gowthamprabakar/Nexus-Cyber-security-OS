"""Smoke tests — the audit package imports + the F.5/F.6 substrate gates fire."""

from __future__ import annotations


def test_package_imports() -> None:
    import audit

    assert hasattr(audit, "__version__")
    assert isinstance(audit.__version__, str)
    assert audit.__version__ == "0.1.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 validation gate — F.6 is the **fifth** consumer of the hoist."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 validation gate — F.6 is the **second** agent built end-to-end against the hoist (D.3 was first)."""
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_charter_memory_service_import_works() -> None:
    """F.6 depends on F.5: the read-side consumer of memory audit emissions."""
    from charter.memory import EpisodeModel, MemoryService

    assert MemoryService.__name__ == "MemoryService"
    assert EpisodeModel.__tablename__ == "episodes"


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — audit must NOT ship a local llm.py."""
    import importlib.util

    assert importlib.util.find_spec("audit.llm") is None, (
        "audit must not ship a per-agent llm.py — consume charter.llm_adapter directly"
    )


def test_eval_runner_entry_point_registered() -> None:
    """The pyproject declares `audit = audit.eval_runner:AuditEvalRunner` under
    the `nexus_eval_runners` entry-point group. Until Task 14 lands the runner
    itself, we only verify the *entry-point declaration* is discoverable — the
    target import is exercised in Task 14's tests.
    """
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "audit" in names, f"audit entry-point not registered; got {names}"
