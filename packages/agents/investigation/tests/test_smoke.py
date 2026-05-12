"""Smoke tests — the investigation package imports + every substrate gate fires."""

from __future__ import annotations


def test_package_imports() -> None:
    import investigation

    assert hasattr(investigation, "__version__")
    assert isinstance(investigation.__version__, str)
    assert investigation.__version__ == "0.1.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 — D.7 is the **sixth** consumer of the hoist."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — D.7 is the **third** agent shipped natively against v1.2
    (after D.3 + F.6).
    """
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_charter_memory_semantic_import_works() -> None:
    """D.7 reads the F.5 SemanticStore for entity-relationship traversal."""
    from charter.memory import MAX_TRAVERSAL_DEPTH, SemanticStore

    assert SemanticStore.__name__ == "SemanticStore"
    assert MAX_TRAVERSAL_DEPTH == 3


def test_charter_memory_procedural_import_works() -> None:
    """D.7 writes hypotheses into the F.5 ProceduralStore for cross-incident pattern detection."""
    from charter.memory import ProceduralStore

    assert ProceduralStore.__name__ == "ProceduralStore"


def test_f6_audit_store_import_works() -> None:
    """D.7 queries the F.6 AuditStore for cross-agent action history."""
    from audit.store import AuditStore

    assert AuditStore.__name__ == "AuditStore"


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — investigation must NOT ship a local llm.py."""
    import importlib.util

    assert importlib.util.find_spec("investigation.llm") is None, (
        "investigation must not ship a per-agent llm.py — consume charter.llm_adapter directly"
    )


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares `investigation = investigation.eval_runner:InvestigationEvalRunner`
    under `nexus_eval_runners`. The target class lands in Task 14; here we only verify
    the *entry-point declaration* is discoverable.
    """
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "investigation" in names, f"investigation entry-point not registered; got {names}"
