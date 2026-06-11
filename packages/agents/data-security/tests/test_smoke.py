"""Smoke tests — data_security package imports + every substrate gate fires.

Task 1 (Bootstrap). 9 tests:

1. Package version (__version__ wired).
2. ADR-007 v1.1 — charter.llm_adapter reachable.
3. ADR-007 v1.2 — charter.nlah_loader reachable.
4. F.1 — charter.audit.AuditLog reachable.
5. F.3 schema re-export — cloud_posture.schemas reachable (Q1 substrate).
6. Anti-pattern guard #1 — no per-agent llm.py (ADR-007 v1.1).
7. Anti-pattern guard #2 — no premature charter.data_classification
   substrate (classifier stays agent-local per ADR-007 3rd-consumer
   hoist rule; plan Q3).
8. Entry-point check #1 — `data_security` eval-runner registered
   (class lands in Task 14).
9. Entry-point check #2 — `data-security` CLI script registered
   (main lands in Task 15).
"""

from __future__ import annotations


def test_package_imports() -> None:
    import data_security

    assert hasattr(data_security, "__version__")
    assert isinstance(data_security.__version__, str)
    assert data_security.__version__ == "0.2.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 — D.5 is the **eleventh** consumer of the hoist."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — D.5 is the **seventh** agent shipped natively against v1.2
    (after D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture).
    """
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_charter_audit_log_import_works() -> None:
    """D.5 emits its own per-run audit chain via charter.audit.AuditLog (F.1).

    Audit chain: 8 events per run (agent_started → ingest_completed →
    classify_completed → detect_completed → correlate_completed →
    scored → summary_written → findings_published).
    """
    from charter.audit import AuditLog

    assert AuditLog.__name__ == "AuditLog"


def test_cloud_posture_schema_reexport_available() -> None:
    """D.5 re-exports F.3's `class_uid 2003 Compliance Finding` (Q1 resolution).

    Third re-exporter after multi-cloud-posture + k8s-posture. The
    schema-as-typing-layer pattern is unchanged; D.5 adds a
    `DataSecurityFindingType` enum + `ClassifierLabel` enum on top
    (lands in Task 2).
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
    """ADR-007 v1.1 anti-pattern guard — data_security must NOT ship a local llm.py."""
    import importlib.util

    assert importlib.util.find_spec("data_security.llm") is None, (
        "data_security must not ship a per-agent llm.py — consume charter.llm_adapter"
    )


def test_no_premature_charter_data_classification_substrate() -> None:
    """ADR-007 3rd-consumer hoist anti-pattern guard — D.5 v0.1 keeps the PII /
    sensitive-data classifier agent-local under ``data_security.classifiers``
    (lands in Task 3).

    Per plan Q3 + sketch §1: promotion to ``charter.data_classification`` only
    when D.6 Compliance or D.12 Curiosity end up needing the same classifier
    (the 3rd-consumer hoist rule). If this substrate appears at Bootstrap
    time, something has gone wrong — premature hoist breaks the YAGNI gate.
    """
    import importlib.util

    assert importlib.util.find_spec("charter.data_classification") is None, (
        "charter.data_classification substrate exists — premature hoist? "
        "D.5 v0.1 keeps classifier agent-local per ADR-007 3rd-consumer rule. "
        "Review against plan Q3."
    )


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares ``data_security = ...eval_runner:DataSecurityEvalRunner``
    under ``nexus_eval_runners``. Class lands in Task 14.
    """
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "data_security" in names, f"data_security entry-point not registered; got {names}"


def test_cli_script_entry_point_registered() -> None:
    """Pyproject declares ``data-security = data_security.cli:main`` under
    ``[project.scripts]``. ``main`` lands in Task 15.
    """
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    names = {ep.name for ep in scripts}
    assert "data-security" in names, f"data-security console script not registered; got {names}"
