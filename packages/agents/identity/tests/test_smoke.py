"""Smoke test — the package imports and exposes a version."""

from __future__ import annotations


def test_package_imports() -> None:
    import identity

    assert hasattr(identity, "__version__")
    assert isinstance(identity.__version__, str)
    assert identity.__version__ == "0.1.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 validation gate — D.2 imports the adapter directly."""
    from charter.llm_adapter import LLMConfig, config_from_env, make_provider  # noqa: F401
