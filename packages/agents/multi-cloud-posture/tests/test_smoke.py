"""Smoke tests — multi_cloud_posture package imports + every substrate gate fires."""

from __future__ import annotations


def test_package_imports() -> None:
    import multi_cloud_posture

    assert hasattr(multi_cloud_posture, "__version__")
    assert isinstance(multi_cloud_posture.__version__, str)
    assert multi_cloud_posture.__version__ == "0.1.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 — D.5 is the **eighth** consumer of the hoist."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — D.5 is the **fifth** agent shipped natively against v1.2
    (after D.3 + F.6 + D.7 + D.4).
    """
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_charter_audit_log_import_works() -> None:
    """D.5 emits its own per-run audit chain via charter.audit.AuditLog (F.1)."""
    from charter.audit import AuditLog

    assert AuditLog.__name__ == "AuditLog"


def test_charter_memory_episodic_import_works() -> None:
    """D.5 lazily persists per-run findings to the F.5 EpisodicStore (Phase 1c)."""
    from charter.memory import EpisodicStore

    assert EpisodicStore.__name__ == "EpisodicStore"


def test_cloud_posture_schema_reexport_available() -> None:
    """D.5 re-exports F.3's `class_uid 2003 Compliance Finding` (Q1 resolution).

    The schema-as-typing-layer pattern is unchanged; D.5 adds a
    `CloudProvider` enum discriminator on top.
    """
    from cloud_posture.schemas import (
        OCSF_CLASS_UID,
        AffectedResource,
        CloudPostureFinding,
        Severity,
        build_finding,
    )

    assert OCSF_CLASS_UID == 2003
    assert CloudPostureFinding.__name__ == "CloudPostureFinding"
    assert AffectedResource.__name__ == "AffectedResource"
    assert build_finding.__name__ == "build_finding"
    assert Severity.CRITICAL.value == "critical"


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — multi_cloud_posture must NOT ship a local llm.py."""
    import importlib.util

    assert importlib.util.find_spec("multi_cloud_posture.llm") is None, (
        "multi_cloud_posture must not ship a per-agent llm.py — consume charter.llm_adapter"
    )


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares `multi_cloud_posture = ...eval_runner:MultiCloudPostureEvalRunner`
    under `nexus_eval_runners`. Class lands in Task 13.
    """
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "multi_cloud_posture" in names, (
        f"multi_cloud_posture entry-point not registered; got {names}"
    )


def test_cli_script_entry_point_registered() -> None:
    """Pyproject declares `multi-cloud-posture = multi_cloud_posture.cli:main`
    under `[project.scripts]`. Class lands in Task 14.
    """
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    names = {ep.name for ep in scripts}
    assert "multi-cloud-posture" in names, (
        f"multi-cloud-posture console script not registered; got {names}"
    )
