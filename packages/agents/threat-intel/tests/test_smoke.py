"""Smoke tests — threat_intel package imports + every substrate gate fires.

Task 1 (Bootstrap). 9 tests:

1. Package version (__version__ wired).
2. ADR-007 v1.1 — charter.llm_adapter reachable.
3. ADR-007 v1.2 — charter.nlah_loader reachable.
4. F.1 — charter.audit.AuditLog reachable.
5. D.4 schema re-export — network_threat.schemas reachable (Q1
   substrate; D.8 is the 2nd re-exporter of class_uid 2004).
6. Anti-pattern guard #1 — no per-agent llm.py (ADR-007 v1.1).
7. Anti-pattern guard #2 — no premature charter.threat_intel_feed
   substrate (feed clients stay agent-local per ADR-007 3rd-
   consumer hoist rule; plan Q3).
8. Entry-point check #1 — ``threat_intel`` eval-runner registered
   (class lands in Task 14).
9. Entry-point check #2 — ``threat-intel`` CLI script registered
   (main lands in Task 15).
"""

from __future__ import annotations


def test_package_imports() -> None:
    import threat_intel

    assert hasattr(threat_intel, "__version__")
    assert isinstance(threat_intel.__version__, str)
    assert threat_intel.__version__ == "0.1.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 — D.8 is the **twelfth** consumer of the hoist."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — D.8 is the **eighth** agent shipped natively against v1.2
    (after D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5).
    """
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_charter_audit_log_import_works() -> None:
    """D.8 emits its own per-run audit chain via charter.audit.AuditLog (F.1).

    Audit chain: 8 events per run (agent_started → ingest_completed →
    enrich_completed → correlate_completed → scored → summary_written →
    semantic_store_written → findings_published).
    """
    from charter.audit import AuditLog

    assert AuditLog.__name__ == "AuditLog"


def test_network_threat_schema_reexport_available() -> None:
    """D.8 re-exports D.4's ``class_uid 2004 Detection Finding`` (Q1 resolution).

    2nd re-exporter of D.4's 2004 schema (D.4 itself is the 1st). The
    schema-as-typing-layer pattern is unchanged; D.8 adds
    ``ThreatIntelFindingType`` enum + ``IocType`` enum on top (lands in
    Task 2). Threat-intel correlations are detection-shaped, not
    compliance-shaped — same class as D.4 keeps wire shape unified for
    D.7 Investigation + Meta-Harness consumers.
    """
    from network_threat.schemas import OCSF_CLASS_UID

    assert OCSF_CLASS_UID == 2004


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — threat_intel must NOT ship a local llm.py."""
    import importlib.util

    assert importlib.util.find_spec("threat_intel.llm") is None, (
        "threat_intel must not ship a per-agent llm.py — consume charter.llm_adapter"
    )


def test_no_premature_charter_threat_intel_substrate() -> None:
    """ADR-007 3rd-consumer hoist anti-pattern guard — D.8 v0.1 keeps the
    feed clients + IOC index + correlators agent-local under
    ``threat_intel/`` (lands in Tasks 3-9).

    Per plan Q3 + sketch §3: feed clients are agent-local v0.1.
    Promotion to ``charter.threat_intel_feed`` (or similar substrate)
    requires the 3rd-consumer rule — D.8 is the 1st consumer; revisit
    if D.12 Curiosity or D.13 Synthesis end up needing the same
    feed-client pattern. If this substrate appears at Bootstrap time,
    something has gone wrong — premature hoist breaks the YAGNI gate.
    """
    import importlib.util

    assert importlib.util.find_spec("charter.threat_intel_feed") is None, (
        "charter.threat_intel_feed substrate exists — premature hoist? "
        "D.8 v0.1 keeps feed clients agent-local per ADR-007 3rd-consumer rule. "
        "Review against plan Q3."
    )


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares ``threat_intel = ...eval_runner:ThreatIntelEvalRunner``
    under ``nexus_eval_runners``. Class lands in Task 14.
    """
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "threat_intel" in names, f"threat_intel entry-point not registered; got {names}"


def test_cli_script_entry_point_registered() -> None:
    """Pyproject declares ``threat-intel = threat_intel.cli:main`` under
    ``[project.scripts]``. ``main`` lands in Task 15.
    """
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    names = {ep.name for ep in scripts}
    assert "threat-intel" in names, f"threat-intel console script not registered; got {names}"
