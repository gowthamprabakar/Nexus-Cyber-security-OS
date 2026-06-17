"""Smoke tests — compliance package imports + substrate gates fire.

Task 1 (Bootstrap). 9 tests:

1. Package version (__version__ wired).
2. ADR-007 v1.1 — charter.llm_adapter reachable.
3. ADR-007 v1.2 — charter.nlah_loader reachable.
4. F.3 schema re-export — cloud_posture.schemas reachable (Q1
   substrate; D.9 is the 3rd re-exporter of class_uid 2003 after
   D.5 + D.8 patterns).
5. D.5 finding-shape reference — data_security.schemas reachable
   (D.9 reads D.5 findings.json sibling workspaces per Q3).
6. Anti-pattern guard #1 — no per-agent llm.py (ADR-007 v1.1).
7. Anti-pattern guard #2 — no premature charter.compliance_framework
   substrate (framework loader stays agent-local per ADR-007 3rd-
   consumer hoist rule; plan Q2).
8. Entry-point check #1 — ``compliance`` eval-runner registered
   (class lands in Task 13).
9. Entry-point check #2 — ``compliance`` CLI script registered
   (main lands in Task 14).
"""

from __future__ import annotations


def test_package_imports() -> None:
    import compliance

    assert hasattr(compliance, "__version__")
    assert isinstance(compliance.__version__, str)
    assert compliance.__version__ == "0.2.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 — D.9 is the **thirteenth** consumer of the hoist."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — D.9 is the **ninth** agent shipped natively against v1.2
    (after D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5 /
    D.8).
    """
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_cloud_posture_schema_reexport_available() -> None:
    """D.9 re-exports F.3's ``class_uid 2003 Compliance Finding`` (Q1).

    3rd re-exporter of F.3's 2003 schema after multi-cloud-posture +
    k8s-posture + D.5; 5th producer overall. Compliance Finding shape
    carries `finding_info.types[0]` as the control discriminator
    (`compliance_cis_aws_v3_*`), and the same severity/affected-
    resource model that F.3 + D.5 already use.
    """
    from cloud_posture.schemas import OCSF_CLASS_UID

    assert OCSF_CLASS_UID == 2003


def test_data_security_schema_import_works() -> None:
    """D.9 reads D.5 Data Security findings via sibling-workspace
    `findings.json` (Q3). The schema module must import cleanly so
    Task 7's correlator can validate the minimal D.5 fields D.9
    cares about.
    """
    from data_security.schemas import OCSF_CLASS_UID  # noqa: F401


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — compliance must NOT ship a local llm.py."""
    import importlib.util

    assert importlib.util.find_spec("compliance.llm") is None, (
        "compliance must not ship a per-agent llm.py — consume charter.llm_adapter"
    )


def test_no_premature_charter_compliance_substrate() -> None:
    """ADR-007 3rd-consumer hoist anti-pattern guard — D.9 v0.1 keeps the
    framework loader + control library + correlators agent-local under
    ``compliance/`` (lands in Tasks 3-9).

    Per plan Q2 + sketch §2: framework loader is agent-local v0.1.
    Promotion to ``charter.compliance_framework`` (or similar substrate)
    requires the 3rd-consumer rule — D.9 is the 1st consumer; revisit
    if D.13 Synthesis or A.4 Meta-Harness end up needing the same
    framework-control pattern. If this substrate appears at Bootstrap
    time, something has gone wrong — premature hoist breaks the YAGNI
    gate.
    """
    import importlib.util

    assert importlib.util.find_spec("charter.compliance_framework") is None, (
        "charter.compliance_framework substrate exists — premature hoist? "
        "D.9 v0.1 keeps framework loader agent-local per ADR-007 3rd-consumer rule. "
        "Review against plan Q2."
    )


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares ``compliance = compliance.eval_runner:ComplianceEvalRunner``
    under ``nexus_eval_runners``. Class lands in Task 13.
    """
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "compliance" in names, f"compliance entry-point not registered; got {names}"


def test_cli_script_entry_point_registered() -> None:
    """Pyproject declares ``compliance = compliance.cli:main`` under
    ``[project.scripts]``. ``main`` lands in Task 14.
    """
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    names = {ep.name for ep in scripts}
    assert "compliance" in names, f"compliance console script not registered; got {names}"
