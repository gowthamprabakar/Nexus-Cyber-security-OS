"""Smoke tests — synthesis package imports + substrate gates fire.

Task 1 (Bootstrap). 9 tests:

1. Package version (__version__ wired).
2. ADR-007 v1.1 — charter.llm_adapter reachable (D.13 is the
   first agent to actually call the LLM in its hot path).
3. ADR-007 v1.2 — charter.nlah_loader reachable.
4. D.7 Investigation finding-shape reference — investigation
   package import works (D.13 reads investigation conclusions
   per Q2).
5. D.6 Compliance finding-shape reference — compliance package
   import works (D.13 reads compliance posture per Q2).
6. F.3 Cloud Posture finding-shape reference — cloud_posture
   package import works (D.13 reads F.3 findings as the technical-
   details fallback per Q2).
7. Anti-pattern guard #1 — no per-agent llm.py (ADR-007 v1.1).
8. Entry-point check #1 — ``synthesis`` eval-runner registered
   (class lands in Task 11).
9. Entry-point check #2 — ``synthesis`` CLI script registered
   (main lands in Task 12).
"""

from __future__ import annotations


def test_package_imports() -> None:
    import synthesis

    assert hasattr(synthesis, "__version__")
    assert isinstance(synthesis.__version__, str)
    assert synthesis.__version__ == "0.2.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 — D.13 is the **fourteenth** consumer of the hoist
    and the **first agent that actually calls the LLM in its hot path**.
    """
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — D.13 is the **tenth** agent shipped natively against v1.2
    (after D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5 /
    D.8 / D.6).
    """
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_investigation_schema_import_works() -> None:
    """D.13 reads D.7 Investigation conclusions via sibling-workspace
    `findings.json` (Q2). The schema module must import cleanly so
    Task 3's reader can validate the minimal D.7 fields D.13 cares
    about.
    """
    import investigation  # noqa: F401


def test_compliance_schema_import_works() -> None:
    """D.13 reads D.6 Compliance posture via sibling-workspace
    `findings.json` (Q2).
    """
    from compliance.schemas import OCSF_CLASS_UID  # noqa: F401


def test_cloud_posture_schema_import_works() -> None:
    """D.13 reads F.3 Cloud Posture findings as the technical-details
    fallback when D.7 isn't pinned (Q2).
    """
    from cloud_posture.schemas import OCSF_CLASS_UID  # noqa: F401


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — synthesis must NOT ship a local llm.py.

    **Especially important for D.13**, since this is the first agent to
    actually call the LLM. The pull to create a local `llm.py` "for
    convenience" is strong; ADR-007 v1.1 says: always go through
    ``charter.llm_adapter``.
    """
    import importlib.util

    assert importlib.util.find_spec("synthesis.llm") is None, (
        "synthesis must not ship a per-agent llm.py — consume charter.llm_adapter"
    )


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares ``synthesis = synthesis.eval_runner:SynthesisEvalRunner``
    under ``nexus_eval_runners``. Class lands in Task 11.
    """
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "synthesis" in names, f"synthesis entry-point not registered; got {names}"


def test_cli_script_entry_point_registered() -> None:
    """Pyproject declares ``synthesis = synthesis.cli:main`` under
    ``[project.scripts]``. ``main`` lands in Task 12.
    """
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    names = {ep.name for ep in scripts}
    assert "synthesis" in names, f"synthesis console script not registered; got {names}"
