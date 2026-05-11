"""Smoke tests — the package imports + both ADR-007 hoists are consumed."""

from __future__ import annotations


def test_package_imports() -> None:
    import runtime_threat

    assert hasattr(runtime_threat, "__version__")
    assert isinstance(runtime_threat.__version__, str)
    assert runtime_threat.__version__ == "0.1.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 validation gate — D.3 is the **third** consumer of the hoist."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 validation gate — D.3 is the **first** agent built end-to-end against the hoist.

    Any new agent inheriting from D.3 (D.4+) should also pass this gate via
    its own smoke test. If the import fails it means the charter side of
    the canon is broken — fix charter, not the agent.
    """
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — runtime_threat must NOT ship a local llm.py."""
    import importlib.util

    assert importlib.util.find_spec("runtime_threat.llm") is None, (
        "runtime_threat must not ship a per-agent llm.py — consume charter.llm_adapter directly"
    )
