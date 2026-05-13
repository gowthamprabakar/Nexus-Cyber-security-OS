"""Smoke tests — k8s_posture package imports + every substrate gate fires."""

from __future__ import annotations


def test_package_imports() -> None:
    import k8s_posture

    assert hasattr(k8s_posture, "__version__")
    assert isinstance(k8s_posture.__version__, str)
    assert k8s_posture.__version__ == "0.1.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 — D.6 is the **ninth** consumer of the hoist."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — D.6 is the **sixth** agent shipped natively against v1.2
    (after D.3 + F.6 + D.7 + D.4 + D.5).
    """
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_charter_audit_log_import_works() -> None:
    """D.6 emits its own per-run audit chain via charter.audit.AuditLog (F.1)."""
    from charter.audit import AuditLog

    assert AuditLog.__name__ == "AuditLog"


def test_charter_memory_episodic_import_works() -> None:
    """D.6 lazily persists per-run findings to the F.5 EpisodicStore (Phase 1c)."""
    from charter.memory import EpisodicStore

    assert EpisodicStore.__name__ == "EpisodicStore"


def test_cloud_posture_schema_reexport_available() -> None:
    """D.6 re-exports F.3's `class_uid 2003 Compliance Finding` per D.5's pattern (Q1).

    The schema-as-typing-layer pattern is unchanged; D.6 adds a `K8sFindingType`
    enum discriminator (lands in Task 2).
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
    """ADR-007 v1.1 anti-pattern guard — k8s_posture must NOT ship a local llm.py."""
    import importlib.util

    assert importlib.util.find_spec("k8s_posture.llm") is None, (
        "k8s_posture must not ship a per-agent llm.py — consume charter.llm_adapter"
    )


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares `k8s_posture = ...eval_runner:K8sPostureEvalRunner`
    under `nexus_eval_runners`. Class lands in Task 14.
    """
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "k8s_posture" in names, f"k8s_posture entry-point not registered; got {names}"


def test_cli_script_entry_point_registered() -> None:
    """Pyproject declares `k8s-posture = k8s_posture.cli:main` under `[project.scripts]`.
    Class lands in Task 15.
    """
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    names = {ep.name for ep in scripts}
    assert "k8s-posture" in names, f"k8s-posture console script not registered; got {names}"
