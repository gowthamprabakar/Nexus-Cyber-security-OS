"""Smoke test — the package imports and exposes a version."""

from __future__ import annotations


def test_package_imports() -> None:
    import identity

    assert hasattr(identity, "__version__")
    assert isinstance(identity.__version__, str)
    assert identity.__version__ == "0.1.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 validation gate — D.2 imports the adapter directly.

    The four symbols the agent driver (Task 11) needs all resolve from
    `charter.llm_adapter` without a per-agent re-export. Twice-validates
    the v1.1 hoist (D.1 was the first consumer).
    """
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — identity must NOT ship a local llm.py.

    A new agent inheriting from the reference template would only ship a
    local `llm.py` if it failed to consume the hoisted adapter. This test
    is the explicit guard so the regression cannot land silently.
    """
    import importlib.util

    assert importlib.util.find_spec("identity.llm") is None, (
        "identity must not ship a per-agent llm.py — consume charter.llm_adapter directly"
    )
