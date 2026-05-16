"""Smoke tests — `remediation` package imports + every substrate gate fires."""

from __future__ import annotations


def test_package_imports() -> None:
    import remediation

    assert hasattr(remediation, "__version__")
    assert isinstance(remediation.__version__, str)
    assert remediation.__version__ == "0.1.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 — A.1 is the **tenth** consumer of the hoist."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — A.1 will be the **seventh** agent shipped natively against v1.2
    (after D.3 / F.6 / D.7 / D.4 / D.5 / D.6). NLAH loader lands in Task 10.
    """
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_charter_audit_log_import_works() -> None:
    """A.1 emits a hash-chained audit chain per run via F.6 AuditLog.

    The audit chain is **load-bearing** for A.1 — every action enumeration /
    artifact generation / dry-run / execute / validate / rollback emits an
    audit entry. The chain is the single source of truth for "what did the
    agent do, when, with what authorization."
    """
    from charter.audit import AuditLog

    assert AuditLog.__name__ == "AuditLog"


def test_charter_memory_episodic_import_works() -> None:
    """A.1 persists per-run outcomes to the F.5 EpisodicStore (Phase 1c)."""
    from charter.memory import EpisodicStore

    assert EpisodicStore.__name__ == "EpisodicStore"


def test_cloud_posture_schema_reexport_available() -> None:
    """A.1 reads OCSF 2003 Compliance Findings from detect agents (F.3 / D.5 / D.6).

    The schema is the input contract; A.1 produces OCSF 2007 Remediation Activity
    on the output side. Both classes are part of OCSF v1.3.
    """
    from cloud_posture.schemas import (
        OCSF_CLASS_UID,
        AffectedResource,
        CloudPostureFinding,
        Severity,
        build_finding,
    )

    assert OCSF_CLASS_UID == 2003  # input class
    assert CloudPostureFinding.__name__ == "CloudPostureFinding"
    assert AffectedResource.__name__ == "AffectedResource"
    assert build_finding.__name__ == "build_finding"
    assert Severity.CRITICAL.value == "critical"


def test_k8s_posture_manifest_finding_available() -> None:
    """A.1 v0.1 consumes D.6's `ManifestFinding` shape via the findings_reader (Task 6)."""
    from k8s_posture.tools.manifests import ManifestFinding

    assert ManifestFinding.__name__ == "ManifestFinding"


def test_kubernetes_sdk_installed() -> None:
    """A.1 executes patches via the kubernetes SDK (Task 5)."""
    import kubernetes

    assert hasattr(kubernetes, "__version__")
    major = int(kubernetes.__version__.split(".")[0])
    assert major >= 31, f"kubernetes SDK >=31.0.0 required; got {kubernetes.__version__}"


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — `remediation` must NOT ship a local llm.py."""
    import importlib.util

    assert importlib.util.find_spec("remediation.llm") is None, (
        "remediation must not ship a per-agent llm.py — consume charter.llm_adapter"
    )


def test_no_local_audit_or_finding_schema() -> None:
    """ADR-007 anti-pattern guard — `remediation` must NOT reinvent F.6 audit or
    the cloud_posture finding schema. F.6 + F.3 hoists are load-bearing."""
    import importlib.util

    # If a remediation/audit.py exists, it must be a wiring shim — but at the
    # smoke-test layer we just confirm no local schemas/audit_log.py exists.
    assert importlib.util.find_spec("remediation.audit_log") is None
    assert importlib.util.find_spec("remediation.findings_schema") is None


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares `remediation = ...eval_runner:RemediationEvalRunner`
    under `nexus_eval_runners`. Class lands in Task 14.
    """
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "remediation" in names, f"remediation entry-point not registered; got {names}"


def test_cli_script_entry_point_registered() -> None:
    """Pyproject declares `remediation = remediation.cli:main` under `[project.scripts]`.
    Class lands in Task 15.
    """
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    names = {ep.name for ep in scripts}
    assert "remediation" in names, f"remediation console script not registered; got {names}"
